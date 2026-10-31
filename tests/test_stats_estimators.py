from __future__ import annotations

import numpy as np
import pytest

from limen.stats.active import difference_estimate, inclusion_probs, poisson_sample, uncertainty
from limen.stats.fnr import fnr_upper_from_count
from limen.stats.stratified import StratumCounts, korn_graubard_total_upper, union_total_upper


def test_fnr_transform() -> None:
    assert fnr_upper_from_count(10, 90) == pytest.approx(0.1)
    assert fnr_upper_from_count(0, 0) == 0.0
    assert fnr_upper_from_count(5, 0) == 1.0


def test_union_bound_is_conservative_vs_single_stratum() -> None:
    strata = [StratumCounts("a", 1000, 100, 0), StratumCounts("b", 1000, 100, 0)]
    u = union_total_upper(strata, 0.95)
    assert u > 0
    # пустая страта без выборки — худший случай: вся страта
    assert union_total_upper([StratumCounts("c", 50, 0, 0)], 0.95) == 50


def test_korn_graubard_handles_zero_findings() -> None:
    strata = [StratumCounts("a", 5000, 150, 0), StratumCounts("b", 3000, 150, 0)]
    u = korn_graubard_total_upper(strata, 0.95)
    assert 0 < u < 8000


def test_inclusion_probs_respect_budget_and_bounds() -> None:
    rng = np.random.default_rng(1)
    u = uncertainty(rng.beta(0.5, 8, size=5000))
    pi = inclusion_probs(u, budget=300, floor=0.2)
    assert pi.sum() == pytest.approx(300, rel=0.02)
    assert pi.min() >= 0.2 * 300 / 5000 - 1e-12
    assert pi.max() <= 1.0


def test_difference_estimator_is_unbiased() -> None:
    rng = np.random.default_rng(2)
    n_pop = 4000
    p = rng.beta(0.3, 20, size=n_pop)
    y = (rng.random(n_pop) < p).astype(float)
    pred = np.clip(p + rng.normal(0, 0.01, n_pop), 0, 1)  # неидеальная модель
    pi = inclusion_probs(uncertainty(pred), budget=300, floor=0.2)
    totals = []
    for _ in range(400):
        sel = poisson_sample(pi, rng)
        totals.append(difference_estimate(pred, pi, sel, y[sel]).total)
    assert np.mean(totals) == pytest.approx(y.sum(), rel=0.08)


def test_difference_estimate_checks_lengths() -> None:
    with pytest.raises(ValueError):
        difference_estimate(np.zeros(3), np.ones(3), np.array([True, False, True]), np.array([1.0]))


@pytest.mark.slow
@pytest.mark.xfail(
    strict=True,
    reason="Известная проблема: нормальная граница схемы active при редких атаках накрывает истину реже "
    "заявленных 95% (docs/methodology.md). Когда граница станет корректной, тест начнёт проходить — "
    "тогда снять xfail.",
)
def test_active_bound_coverage_with_rare_attacks() -> None:
    rng = np.random.default_rng(0)
    n_pop, budget = 5000, 300
    p = np.clip(rng.beta(0.6, 30, n_pop) * 0.005 / (0.6 / 30.6), 0, 1)  # в среднем 0,5% атак
    y = (rng.random(n_pop) < p).astype(float)
    f = np.clip(p + rng.normal(0, 0.005, n_pop), 0, 1)  # хорошо откалиброванная модель
    pi = inclusion_probs(uncertainty(f), budget, 0.2)
    covered = []
    for _ in range(1000):
        sel = poisson_sample(pi, rng)
        covered.append(y.sum() <= difference_estimate(f, pi, sel, y[sel], 0.95).upper)
    assert np.mean(covered) >= 0.93

from __future__ import annotations

import math
from itertools import pairwise

import numpy as np
import pytest

from limen.stats.binomial import cp_lower, cp_upper, hypergeom_upper_count, n_required, zero_failure_n


def test_zero_failure_sample_sizes_match_hand_calculation() -> None:
    # ln(0.05)/ln(0.99) = 298.07 → 299; для 2% → 149; для 5% → 59
    assert zero_failure_n(0.01, 0.95) == 299
    assert zero_failure_n(0.02, 0.95) == 149
    assert zero_failure_n(0.05, 0.95) == 59


def test_cp_upper_zero_findings() -> None:
    assert cp_upper(0, 299, 0.95) <= 0.01 < cp_upper(0, 298, 0.95)
    assert math.isclose(cp_upper(0, 299, 0.95), 1 - 0.05 ** (1 / 299), rel_tol=1e-9)


def test_cp_upper_known_values() -> None:
    assert cp_upper(8, 450, 0.95) == pytest.approx(0.03185, abs=1e-4)
    assert cp_upper(1, 300, 0.95) == pytest.approx(0.01571, abs=1e-4)


def test_cp_edges_and_monotonicity() -> None:
    assert cp_upper(0, 0) == 1.0
    assert cp_upper(10, 10) == 1.0
    assert cp_lower(0, 50) == 0.0
    ups = [cp_upper(k, 200) for k in range(0, 10)]
    assert all(a < b for a, b in pairwise(ups))
    assert cp_lower(3, 100) < 3 / 100 < cp_upper(3, 100)


def test_cp_rejects_bad_input() -> None:
    with pytest.raises(ValueError):
        cp_upper(5, 3)
    with pytest.raises(ValueError):
        cp_upper(1, 10, confidence=1.0)


def test_hypergeometric_is_tighter_than_binomial() -> None:
    n_pop, n, k = 2000, 600, 2
    hyper = hypergeom_upper_count(k, n, n_pop, 0.95)
    binom = cp_upper(k, n, 0.95) * n_pop
    assert k <= hyper <= math.ceil(binom)


def test_n_required_with_findings() -> None:
    n = n_required(0.02, 0.95, k=2)
    assert cp_upper(2, n, 0.95) <= 0.02 < cp_upper(2, n - 1, 0.95)


@pytest.mark.slow
def test_cp_upper_coverage_by_simulation() -> None:
    rng = np.random.default_rng(0)
    p_true, n, reps = 0.02, 200, 4000
    k = rng.binomial(n, p_true, size=reps)
    violations = np.mean([p_true > cp_upper(int(x), n, 0.95) for x in k])
    assert violations <= 0.05 + 0.01  # не больше номинальных 5% (с запасом на шум симуляции)

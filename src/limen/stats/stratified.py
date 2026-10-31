"""Верхняя граница числа атак при стратифицированной выборке (страты — обычно правила корреляции).

* ``union`` — корректно на конечной выборке: δ делится между стратами (неравенство Буля),
  граница = Σ N_h · CP_upper(k_h, n_h; 1 − δ_h). Консервативна при большом числе страт.
* ``korn_graubard`` — приближённая граница: Клоппер–Пирсон по эффективному размеру выборки
  (Korn, Graubard, 1998). Её фактическое покрытие проверяется в эксперименте H1.
"""

from __future__ import annotations

from dataclasses import dataclass

from limen.stats.binomial import cp_upper, hypergeom_upper_count
from limen.stats.special import betaincinv


@dataclass(frozen=True)
class StratumCounts:
    name: str
    population: int  # N_h — автозакрытых алертов в страте
    sampled: int  # n_h — перепроверено
    attacks: int  # k_h — найдено атак


def union_total_upper(
    strata: list[StratumCounts], confidence: float = 0.95, method: str = "binomial"
) -> float:
    """Корректная на конечной выборке граница суммарного числа атак A_C."""
    active = [s for s in strata if s.population > 0]
    if not active:
        return 0.0
    delta_h = (1.0 - confidence) / len(active)
    conf_h = 1.0 - delta_h
    total = 0.0
    for s in active:
        if s.sampled == 0:
            total += s.population  # нет данных — худший случай
        elif method == "hypergeometric":
            total += hypergeom_upper_count(s.attacks, s.sampled, s.population, conf_h)
        else:
            total += s.population * cp_upper(s.attacks, s.sampled, conf_h)
    return total


def korn_graubard_total_upper(strata: list[StratumCounts], confidence: float = 0.95) -> float:
    """Приближённая граница A_C через эффективный размер выборки."""
    active = [s for s in strata if s.population > 0]
    if not active:
        return 0.0
    big_n = sum(s.population for s in active)
    unsampled = sum(s.population for s in active if s.sampled == 0)  # худший случай для страт без выборки
    sampled = [s for s in active if s.sampled > 0]
    n_total = sum(s.sampled for s in sampled)
    if n_total == 0:
        return float(big_n)
    n_cov = sum(s.population for s in sampled)
    p_hat = 0.0
    var = 0.0
    for s in sampled:
        w = s.population / n_cov
        p_h = s.attacks / s.sampled
        p_hat += w * p_h
        if s.sampled > 1:
            fpc = 1.0 - s.sampled / s.population
            var += w * w * fpc * p_h * (1.0 - p_h) / (s.sampled - 1)
    n_eff = n_total if var <= 0 or p_hat in (0.0, 1.0) else min(n_total, p_hat * (1.0 - p_hat) / var)
    k_eff = n_eff * p_hat
    upper = 1.0 if k_eff >= n_eff else betaincinv(k_eff + 1.0, n_eff - k_eff, confidence)
    return n_cov * upper + unsampled

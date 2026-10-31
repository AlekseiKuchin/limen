"""Оценка с использованием прогнозов модели: active statistical inference и prediction-powered inference.

Модель даёт для каждого автозакрытого алерта вероятность атаки f_i. Алерт попадает в выборку с вероятностью
π_i (выборка Пуассона), которая растёт с неопределённостью модели (Zrnic, Candès, ICML 2024).
Оценка числа атак (разностная оценка с весами 1/π_i):

    Â = Σ_i λ f_i + Σ_{i ∈ S} (y_i − λ f_i) / π_i

Она несмещённая при любой модели f; модель влияет только на дисперсию. При равных π_i это
prediction-powered inference (Angelopoulos и др., 2023). Граница строится через нормальное
приближение, поэтому гарантия асимптотическая: при редких атаках её покрытие нужно проверять (гипотеза H1).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import numpy.typing as npt

from limen.stats.special import norm_ppf

FloatArray = npt.NDArray[np.float64]
BoolArray = npt.NDArray[np.bool_]


def uncertainty(scores: FloatArray) -> FloatArray:
    """Неопределённость бинарного прогноза: sqrt(p(1 − p))."""
    p = np.clip(scores, 1e-6, 1.0 - 1e-6)
    return np.sqrt(p * (1.0 - p))


def inclusion_probs(
    weights: FloatArray, budget: float, floor: float = 0.2, max_iter: int = 100
) -> FloatArray:
    """Вероятности отбора π_i ∝ weights с суммой ``budget`` и ограничениями [π_min, 1].

    ``floor`` — минимальная вероятность как доля равномерной (budget / N): защищает от огромных весов 1/π.
    """
    n = len(weights)
    if n == 0:
        return np.zeros(0)
    budget = min(float(budget), float(n))
    pi_min = min(1.0, floor * budget / n)
    w = np.maximum(np.asarray(weights, dtype=float), 0.0)
    if w.sum() == 0:
        w = np.ones(n)
    pi = np.full(n, budget / n)
    fixed = np.zeros(n, dtype=bool)
    for _ in range(max_iter):
        free = ~fixed
        remaining = budget - pi[fixed].sum()
        if free.sum() == 0:
            break
        wf = w[free]
        pi[free] = remaining * wf / wf.sum() if wf.sum() > 0 else remaining / free.sum()
        over = (pi > 1.0) & free
        under = (pi < pi_min) & free
        if not over.any() and not under.any():
            break
        pi[over] = 1.0
        pi[under] = pi_min
        fixed |= over | under
    return np.asarray(np.clip(pi, pi_min, 1.0), dtype=np.float64)


def poisson_sample(pi: FloatArray, rng: np.random.Generator) -> BoolArray:
    """Независимый отбор каждого алерта с вероятностью π_i."""
    return rng.random(len(pi)) < pi


@dataclass(frozen=True)
class DifferenceEstimate:
    total: float  # оценка числа атак среди автозакрытых
    se: float
    upper: float  # верхняя граница (1 − δ)
    n_labeled: int


def difference_estimate(
    predictions: FloatArray,
    pi: FloatArray,
    selected: BoolArray,
    y_selected: FloatArray,
    confidence: float = 0.95,
    lam: float = 1.0,
) -> DifferenceEstimate:
    """Разностная оценка числа атак и её односторонняя верхняя граница.

    :param predictions: f_i для всех автозакрытых алертов
    :param pi: вероятности отбора π_i для всех алертов
    :param selected: маска попавших в выборку
    :param y_selected: метки (0/1) для попавших в выборку, в том же порядке
    :param lam: коэффициент доверия к модели (λ = 0 — чистая оценка Хорвица–Томпсона)
    """
    f = np.asarray(predictions, dtype=float)
    pi = np.asarray(pi, dtype=float)
    sel = np.asarray(selected, dtype=bool)
    y = np.asarray(y_selected, dtype=float)
    if sel.sum() != len(y):
        raise ValueError("Число меток не совпадает с числом отобранных алертов")
    resid = y - lam * f[sel]
    pis = pi[sel]
    total = float(lam * f.sum() + np.sum(resid / pis))
    var = float(np.sum((1.0 - pis) / pis**2 * resid**2))
    se = var**0.5
    z = norm_ppf(confidence)
    upper = min(float(len(f)), max(total + z * se, float(y.sum())))
    return DifferenceEstimate(total=total, se=se, upper=upper, n_labeled=int(sel.sum()))

"""Точные границы для доли по случайной выборке.

* Клоппер–Пирсон (Clopper, Pearson, 1934): покрытие не ниже заявленного на любой конечной выборке.
  Для выборки без возвращения из конечной совокупности биномиальная граница консервативна.
* Гипергеометрическая граница для числа атак в конечной совокупности — точнее,
  когда выборка составляет заметную долю автозакрытых алертов.

Вычисления — на стандартной библиотеке (``limen.stats.special``), без SciPy.
"""

from __future__ import annotations

import math

from limen.stats.special import betaincinv, binom_cdf, hypergeom_cdf


def _check(k: int, n: int, confidence: float) -> None:
    if n < 0 or k < 0 or k > n:
        raise ValueError(f"Некорректные k={k}, n={n}")
    if not 0.0 < confidence < 1.0:
        raise ValueError(f"Уверенность должна быть в (0, 1), получено {confidence}")


def cp_upper(k: int, n: int, confidence: float = 0.95) -> float:
    """Односторонняя верхняя граница Клоппера–Пирсона для доли при k успехах из n."""
    _check(k, n, confidence)
    if n in (0, k):
        return 1.0
    if k == 0:
        return 1.0 - float((1.0 - confidence) ** (1.0 / n))
    return betaincinv(k + 1, n - k, confidence)


def cp_lower(k: int, n: int, confidence: float = 0.95) -> float:
    """Односторонняя нижняя граница Клоппера–Пирсона."""
    _check(k, n, confidence)
    if k == 0:
        return 0.0
    if k == n:
        return float((1.0 - confidence) ** (1.0 / n))
    return betaincinv(k, n - k + 1, 1.0 - confidence)


def hypergeom_upper_count(k: int, n: int, population: int, confidence: float = 0.95) -> int:
    """Верхняя граница числа атак M в совокупности размера N по k атакам в выборке n без возвращения.

    Наибольшее M, при котором P(X ≤ k | N, M, n) ≥ δ. Вероятность монотонно убывает по M — бинарный поиск.
    """
    _check(k, n, confidence)
    if n > population:
        raise ValueError("Выборка больше совокупности")
    delta = 1.0 - confidence
    lo, hi = k, population - (n - k)  # допустимые значения M
    if lo >= hi:
        return hi
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if hypergeom_cdf(k, population, mid, n) >= delta:
            lo = mid
        else:
            hi = mid - 1
    return int(lo)


def zero_failure_n(p_max: float, confidence: float = 0.95) -> int:
    """Сколько алертов нужно перепроверить без единой находки, чтобы граница доли была ≤ p_max.

    Пример: p_max = 1%, уверенность 95% → 299 алертов.
    """
    if not 0.0 < p_max < 1.0:
        raise ValueError("p_max должна быть в (0, 1)")
    return math.ceil(math.log(1.0 - confidence) / math.log(1.0 - p_max))


def n_required(p_max: float, confidence: float = 0.95, k: int = 0, n_max: int = 10_000_000) -> int:
    """Минимальный размер выборки, при котором k найденных атак ещё дают верхнюю границу ≤ p_max.

    Граница Клоппера–Пирсона не выше p_max ровно тогда, когда P(X ≤ k | n, p_max) ≤ δ, — поэтому
    в бинарном поиске считается функция распределения, а не обратная функция.
    """
    if k == 0:
        return zero_failure_n(p_max, confidence)
    delta = 1.0 - confidence
    lo, hi = k + 1, n_max
    if binom_cdf(k, hi, p_max) > delta:
        raise ValueError("Недостижимо в пределах n_max")
    while lo < hi:
        mid = (lo + hi) // 2
        if binom_cdf(k, mid, p_max) <= delta:
            hi = mid
        else:
            lo = mid + 1
    return lo

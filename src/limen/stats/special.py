"""Специальные функции на стандартной библиотеке Python — без SciPy в ядре.

Ядро ставится в контур заказчика и собирается из исходников. SciPy для этого требует Fortran,
BLAS и долгой сборки, а ядру нужны только:

* регуляризованная неполная бета-функция I_x(a, b) и обратная к ней — границы Клоппера–Пирсона;
* функция распределения биномиального и гипергеометрического законов;
* квантиль нормального распределения — из ``statistics.NormalDist``.

Неполная бета-функция считается непрерывной дробью (модифицированный метод Лентца), обратная —
методом Ньютона с защитой бисекцией. Совпадение со SciPy проверяется в tests/test_special.py.
"""

from __future__ import annotations

import math
from statistics import NormalDist

_EPS = 1e-15
_TINY = 1e-300
_MAX_ITER = 10_000


def _betacf(a: float, b: float, x: float) -> float:
    """Непрерывная дробь для неполной бета-функции (Press и др., Numerical Recipes, § 6.4)."""
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > _TINY else _TINY)
    h = d
    for m in range(1, _MAX_ITER + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > _TINY else _TINY)
        c = 1.0 + aa / c
        c = c if abs(c) > _TINY else _TINY
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > _TINY else _TINY)
        c = 1.0 + aa / c
        c = c if abs(c) > _TINY else _TINY
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPS:
            return h
    raise ArithmeticError("Непрерывная дробь неполной бета-функции не сошлась")


def _log_beta(a: float, b: float) -> float:
    return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)


def betainc(a: float, b: float, x: float) -> float:
    """Регуляризованная неполная бета-функция I_x(a, b) при a, b > 0 и 0 ≤ x ≤ 1."""
    if a <= 0.0 or b <= 0.0:
        raise ValueError(f"Параметры бета-функции должны быть положительными: a={a}, b={b}")
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    front = math.exp(a * math.log(x) + b * math.log1p(-x) - _log_beta(a, b))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def betaincinv(a: float, b: float, y: float) -> float:
    """Обратная функция: такое x, что I_x(a, b) = y. Ньютон с защитой бисекцией."""
    if not 0.0 <= y <= 1.0:
        raise ValueError(f"Вероятность должна быть в [0, 1], получено {y}")
    if y == 0.0:
        return 0.0
    if y == 1.0:
        return 1.0
    lo, hi = 0.0, 1.0
    x = a / (a + b)
    log_b = _log_beta(a, b)
    for _ in range(200):
        f = betainc(a, b, x) - y
        if f == 0.0:
            return x
        if f < 0.0:
            lo = x
        else:
            hi = x
        log_pdf = (a - 1.0) * math.log(x) + (b - 1.0) * math.log1p(-x) - log_b
        pdf = math.exp(log_pdf) if log_pdf < 700.0 else math.inf
        x_new = x - f / pdf if pdf > 0.0 and math.isfinite(pdf) else (lo + hi) / 2.0
        if not lo < x_new < hi:
            x_new = (lo + hi) / 2.0
        if abs(x_new - x) <= 1e-15 * max(x, 1e-300) or hi - lo <= 1e-16 * max(hi, 1e-300):
            return x_new
        x = x_new
    return x


def binom_cdf(k: int, n: int, p: float) -> float:
    """P(X ≤ k) для X ~ Bin(n, p)."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    return betainc(n - k, k + 1, 1.0 - p)


def binom_sf(k: int, n: int, p: float) -> float:
    """P(X ≥ k) для X ~ Bin(n, p)."""
    return 1.0 - binom_cdf(k - 1, n, p)


def _log_comb(n: int, k: int) -> float:
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def hypergeom_cdf(k: int, population: int, successes: int, draws: int) -> float:
    """P(X ≤ k) для гипергеометрической X: совокупность population, «успехов» successes, выборка draws."""
    if not 0 <= successes <= population or not 0 <= draws <= population:
        raise ValueError("Некорректные параметры гипергеометрического распределения")
    lo = max(0, draws - (population - successes))
    hi = min(draws, successes)
    if k < lo:
        return 0.0
    if k >= hi:
        return 1.0
    log_total = _log_comb(population, draws)
    terms = [
        math.exp(_log_comb(successes, i) + _log_comb(population - successes, draws - i) - log_total)
        for i in range(lo, k + 1)
    ]
    return min(1.0, math.fsum(terms))


def norm_ppf(q: float) -> float:
    """Квантиль стандартного нормального распределения."""
    return NormalDist().inv_cdf(q)

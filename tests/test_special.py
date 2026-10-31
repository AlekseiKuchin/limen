"""Специальные функции ядра: известные значения и сверка со SciPy (если он установлен)."""

from __future__ import annotations

import math
from fractions import Fraction

import pytest

from limen.stats.special import betainc, betaincinv, binom_cdf, hypergeom_cdf, norm_ppf


def test_betainc_closed_forms() -> None:
    for b in (1.0, 3.0, 299.0):
        for x in (1e-4, 0.01, 0.3, 0.9):
            assert betainc(1.0, b, x) == pytest.approx(1 - (1 - x) ** b, rel=1e-12)
            assert betainc(b, 1.0, x) == pytest.approx(x**b, rel=1e-10, abs=1e-300)


def test_betaincinv_inverts_betainc() -> None:
    for a, b in ((1, 299), (3, 447), (9, 442), (2.5, 7.5), (30, 3000)):
        for y in (0.001, 0.05, 0.5, 0.95, 0.999):
            assert betainc(a, b, betaincinv(a, b, y)) == pytest.approx(y, rel=1e-10)


def _exact_binom_cdf(k: int, n: int, p: Fraction) -> float:
    return float(sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k + 1)))


def test_binom_cdf_matches_exact_rational_arithmetic() -> None:
    for n, k, p in ((20, 3, Fraction(1, 10)), (60, 0, Fraction(1, 50)), (100, 7, Fraction(3, 100))):
        assert binom_cdf(k, n, float(p)) == pytest.approx(_exact_binom_cdf(k, n, p), rel=1e-11)


def test_hypergeom_cdf_matches_exact_enumeration() -> None:
    def exact(k: int, total: int, good: int, draws: int) -> float:
        num = sum(math.comb(good, i) * math.comb(total - good, draws - i) for i in range(k + 1))
        return float(Fraction(num, math.comb(total, draws)))

    for case in ((0, 200, 5, 30), (2, 500, 40, 60), (3, 1000, 121, 300), (1, 50, 49, 10)):
        assert hypergeom_cdf(*case) == pytest.approx(exact(*case), rel=1e-11, abs=1e-15)


def test_norm_ppf_known_values() -> None:
    assert norm_ppf(0.975) == pytest.approx(1.959963984540054, rel=1e-12)
    assert norm_ppf(0.95) == pytest.approx(1.6448536269514722, rel=1e-12)


def test_against_scipy_on_a_grid() -> None:
    sp = pytest.importorskip("scipy.special")
    st = pytest.importorskip("scipy.stats")
    for a in (1.0, 2.0, 9.0, 101.0, 2.7):
        for b in (1.0, 17.0, 450.0, 12000.0):
            for q in (0.01, 0.05, 0.5, 0.95, 0.99):
                assert betaincinv(a, b, q) == pytest.approx(float(sp.betaincinv(a, b, q)), rel=1e-9)
    for total, draws in ((12400, 300), (2000, 600)):
        for good in (0, 5, 121):
            for k in (0, 1, 3):
                ref = float(st.hypergeom.cdf(k, total, good, draws))
                assert hypergeom_cdf(k, total, good, draws) == pytest.approx(ref, rel=1e-9, abs=1e-300)

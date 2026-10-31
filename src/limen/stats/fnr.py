"""Переход от границы доли атак среди автозакрытых (FOR) к границе доли пропущенных атак (FNR)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


def fnr_upper_from_count(attacks_closed_upper: float, attacks_open: int) -> float:
    """Верхняя граница FNR = U / (U + A_O).

    FNR = A_C / (A_C + A_O) монотонно растёт по A_C, поэтому верхняя граница для A_C
    с уверенностью 1 − δ даёт верхнюю границу FNR с той же уверенностью.
    """
    if attacks_closed_upper < 0 or attacks_open < 0:
        raise ValueError("Отрицательные значения")
    total = attacks_closed_upper + attacks_open
    return 0.0 if total == 0 else attacks_closed_upper / total


@dataclass(frozen=True)
class AuditEstimate:
    """Итог аудита одной совокупности автозакрытых алертов (всего потока или одного правила)."""

    scope: str  # "all" или идентификатор правила
    scheme: str
    method: str
    confidence: float
    n_closed: int  # N_C
    n_sampled: int  # n
    attacks_in_sample: int  # k (с учётом политики «не знаю»)
    attacks_open: int  # A_O
    for_point: float
    for_upper: float
    attacks_closed_upper: float
    fnr_upper: float
    finite_sample_valid: bool  # True — гарантия на конечной выборке, False — асимптотическая

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

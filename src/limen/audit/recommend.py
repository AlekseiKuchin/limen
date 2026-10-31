"""Рекомендации по правилам: где автоматизацию можно расширять, а где она теряет атаки."""

from __future__ import annotations

from enum import StrEnum

import pandas as pd

from limen.stats.binomial import cp_lower, cp_upper, n_required, zero_failure_n


class Decision(StrEnum):
    SAFE = "safe"
    LEAKS = "leaks"
    UNCERTAIN = "uncertain"
    INSUFFICIENT = "insufficient"


DECISION_RU: dict[Decision, str] = {
    Decision.SAFE: "можно автоматизировать",
    Decision.LEAKS: "теряет атаки — исправить правило или автоматизацию",
    Decision.UNCERTAIN: "неясно — нужна дополнительная выборка",
    Decision.INSUFFICIENT: "мало данных для вывода",
}


def decide(n: int, k: int, target: float, confidence: float) -> tuple[Decision, int]:
    """Решение по одному правилу и сколько ещё алертов перепроверить, чтобы прийти к выводу.

    * SAFE — верхняя граница доли атак ≤ target;
    * LEAKS — даже нижняя граница > target: атаки теряются с уверенностью;
    * INSUFFICIENT — атак не найдено, но выборка мала для вывода;
    * UNCERTAIN — атаки найдены, но вывод пока не однозначен.
    """
    if n == 0:
        return Decision.INSUFFICIENT, zero_failure_n(target, confidence)
    if cp_upper(k, n, confidence) <= target:
        return Decision.SAFE, 0
    if cp_lower(k, n, confidence) > target:
        return Decision.LEAKS, 0
    try:
        extra = max(0, n_required(target, confidence, k) - n)
    except ValueError:
        extra = -1  # недостижимо в разумном объёме
    return (Decision.INSUFFICIENT if k == 0 else Decision.UNCERTAIN), extra


def decide_from_upper(n: int, k: int, upper: float, target: float) -> tuple[Decision, int]:
    """Решение, когда отбор внутри правила не простой случайный (active, правило в нескольких стратах).

    Сырые k/n здесь смещены, поэтому опираемся только на корректную верхнюю границу. Вывод «теряет атаки»
    не делается (нет нижней границы), добор не рассчитывается (−1).
    """
    if n == 0:
        return Decision.INSUFFICIENT, -1
    if upper <= target:
        return Decision.SAFE, 0
    return (Decision.INSUFFICIENT if k == 0 else Decision.UNCERTAIN), -1


def recommend(per_rule: pd.DataFrame, target: float) -> pd.DataFrame:
    """Добавить решение, его русскую формулировку и требуемый добор выборки."""
    out = per_rule.copy()
    srs = out["srs_within_rule"] if "srs_within_rule" in out else pd.Series(True, index=out.index)
    decisions = [
        decide(int(r.n_sampled), int(r.attacks_in_sample), target, float(r.confidence))
        if is_srs
        else decide_from_upper(int(r.n_sampled), int(r.attacks_in_sample), float(r.for_upper), target)
        for r, is_srs in zip(out.itertuples(index=False), srs.astype(bool), strict=True)
    ]
    out["decision"] = [d.value for d, _ in decisions]
    out["decision_ru"] = [DECISION_RU[d] for d, _ in decisions]
    out["extra_sample_needed"] = [e for _, e in decisions]
    return out

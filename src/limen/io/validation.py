"""Проверки выгрузки до начала аудита (шаг 3 протокола пилота)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from limen.schema import (
    ALERT_ID,
    CLOSED_AT,
    CLOSING_SOURCE,
    REQUIRED_COLUMNS,
    RULE_ID,
    VERDICT,
    ClosingSource,
    Verdict,
)


class AuditBlockedError(RuntimeError):
    """Аудит по этой выгрузке провести нельзя (например, автозакрытие неотличимо от ручного)."""


def verdicts(df: pd.DataFrame) -> pd.Series[Any]:
    """Колонка вердиктов; если её нет в выгрузке, все вердикты считаются неизвестными."""
    if VERDICT in df.columns:
        return df[VERDICT].fillna(Verdict.UNKNOWN.value).astype(str)
    return pd.Series(Verdict.UNKNOWN.value, index=df.index, dtype=object)


@dataclass
class ValidationReport:
    n_rows: int
    n_duplicates: int
    counts_by_source: dict[str, int]
    n_rules: int
    attacks_found_by_analysts: int
    period: tuple[str, str] | None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def raise_if_blocked(self) -> None:
        if self.errors:
            raise AuditBlockedError("; ".join(self.errors))


def validate(df: pd.DataFrame, audited_sources: tuple[ClosingSource, ...]) -> ValidationReport:
    """Проверить, что по выгрузке можно провести аудит."""
    errors: list[str] = []
    warnings: list[str] = []

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        errors.append(f"Нет обязательных полей: {missing}")
        return ValidationReport(len(df), 0, {}, 0, 0, None, errors, warnings)

    counts = df[CLOSING_SOURCE].value_counts().to_dict()
    counts = {str(k): int(v) for k, v in counts.items()}
    n_dup = int(df[ALERT_ID].duplicated().sum())
    if n_dup:
        warnings.append(f"Повторяющихся alert_id: {n_dup} — при подготовке оставляется последняя запись")

    unknown = counts.get(ClosingSource.UNKNOWN.value, 0)
    if unknown == len(df):
        errors.append(
            "Источник закрытия неизвестен у всех алертов: нельзя отличить автозакрытие от ручного. "
            "Нужен признак (сервисная учётная запись SOAR, плейбук, модуль ИИ)."
        )
    elif unknown:
        warnings.append(
            f"Источник закрытия неизвестен у {unknown} алертов ({unknown / len(df):.1%}) — они не аудируются"
        )

    n_audited = sum(counts.get(s.value, 0) for s in audited_sources)
    if n_audited == 0 and not errors:
        errors.append("Нет алертов, закрытых автоматически или подавлением: проверять нечего")

    analyst_mask = df[CLOSING_SOURCE] == ClosingSource.ANALYST.value
    verdict = verdicts(df)
    attacks_open = int((analyst_mask & (verdict == Verdict.ATTACK.value)).sum())
    if analyst_mask.any() and (verdict[analyst_mask] == Verdict.UNKNOWN.value).all():
        warnings.append(
            "У алертов, закрытых аналитиками, нет вердиктов: граница доли пропущенных атак (FNR) не считается"
        )
    elif attacks_open == 0:
        warnings.append(
            "Аналитики не нашли ни одной атаки за период: граница FNR будет неинформативной (близкой к 1)"
        )

    period = None
    if CLOSED_AT in df.columns and df[CLOSED_AT].notna().any():
        period = (str(df[CLOSED_AT].min()), str(df[CLOSED_AT].max()))

    return ValidationReport(
        n_rows=len(df),
        n_duplicates=n_dup,
        counts_by_source=counts,
        n_rules=int(df[RULE_ID].nunique()),
        attacks_found_by_analysts=attacks_open,
        period=period,
        errors=errors,
        warnings=warnings,
    )

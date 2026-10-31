"""Каноническая схема закрытого алерта.

Любая выгрузка (KUMA, MaxPatrol SIEM, R-Vision, CSV) приводится к этим полям через маппинг
из ``configs/mappings``. Дальше весь конвейер работает только с каноническими именами.
"""

from __future__ import annotations

from enum import StrEnum


class ClosingSource(StrEnum):
    """Кто закрыл алерт."""

    AUTO = "auto"  # ИИ вендора, плейбук SOAR, «автоаналитик»
    SUPPRESSION = "suppression"  # правило подавления или исключение
    ANALYST = "analyst"  # аналитик вручную
    UNKNOWN = "unknown"  # источник закрытия неизвестен


class Verdict(StrEnum):
    """Вердикт по алерту: у аналитика при ручном закрытии или при перепроверке в аудите."""

    ATTACK = "attack"
    BENIGN = "benign"
    UNKNOWN = "unknown"


# Канонические поля
ALERT_ID = "alert_id"
RULE_ID = "rule_id"
RULE_NAME = "rule_name"
CLOSED_AT = "closed_at"
CLOSING_SOURCE = "closing_source"
CLOSING_REASON = "closing_reason"
VERDICT = "verdict"
SCORE = "score"  # оценка вероятности атаки (0..1) от вендора или своей модели
TENANT = "tenant"  # клиент MSSP

REQUIRED_COLUMNS: tuple[str, ...] = (ALERT_ID, RULE_ID, CLOSING_SOURCE)
OPTIONAL_COLUMNS: tuple[str, ...] = (RULE_NAME, CLOSED_AT, CLOSING_REASON, VERDICT, SCORE, TENANT)
CANONICAL_COLUMNS: tuple[str, ...] = REQUIRED_COLUMNS + OPTIONAL_COLUMNS

# Служебные поля плана выборки
INCLUSION_PROB = "inclusion_prob"
SELECTED = "selected"
STRATUM = "stratum"
LABEL = "label"
Y = "y"  # 1 — атака, 0 — не атака, NaN — нет метки

AUTOMATED_SOURCES: frozenset[ClosingSource] = frozenset({ClosingSource.AUTO, ClosingSource.SUPPRESSION})

"""Метки перепроверки: шаблон для аналитиков, чтение и привязка к плану выборки."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from limen.sampling.plans import SamplingPlan
from limen.schema import ALERT_ID, LABEL, SELECTED, Verdict, Y

TECHNIQUE = "attack_technique"  # техника MITRE ATT&CK для найденной атаки, например T1078 или T1059.001
LABEL_COLUMNS = [ALERT_ID, LABEL, "analyst", "seconds_spent", "comment", "labeled_at", TECHNIQUE]
TECHNIQUE_PATTERN = r"^T\d{4}(\.\d{3})?$"
CONTEXT_COLUMNS = ["rule_id", "rule_name", "closed_at", "closing_source", "closing_reason", "score", "tenant"]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def excel_safe(value: object) -> object:
    """Защита от CSV-инъекции: шаблон открывают в Excel, а текст полей алерта может задать атакующий.

    Строка, которая начинается с символа формулы, получает префикс-апостроф и остаётся текстом.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def write_label_template(plan: SamplingPlan, alerts: pd.DataFrame, path: str | Path) -> Path:
    """Шаблон разметки: отобранные алерты с контекстом и пустыми полями для аналитика.

    Подходит и для интерфейса «Лимен», и для разметки в Excel или задачах SOAR заказчика.
    """
    ids = plan.selected_ids()
    ctx_cols = [c for c in CONTEXT_COLUMNS if c in alerts.columns]
    ctx = alerts.loc[alerts[ALERT_ID].astype(str).isin(ids), [ALERT_ID, *ctx_cols]].copy()
    ctx[ALERT_ID] = ctx[ALERT_ID].astype(str)
    for col in ctx_cols:
        if pd.api.types.is_object_dtype(ctx[col]) or pd.api.types.is_string_dtype(ctx[col]):
            ctx[col] = ctx[col].map(excel_safe)
    tpl = pd.DataFrame({ALERT_ID: ids}).merge(ctx, on=ALERT_ID, how="left")
    for col in LABEL_COLUMNS[1:]:
        tpl[col] = ""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tpl.to_csv(p, index=False)
    return p


def read_labels(path: str | Path) -> pd.DataFrame:
    """Прочитать метки; при повторной разметке одного алерта берётся последняя запись."""
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    if ALERT_ID not in df or LABEL not in df:
        raise KeyError(f"В файле меток нужны колонки {ALERT_ID} и {LABEL}")
    df = df.loc[df[LABEL].str.strip() != ""].copy()
    df[LABEL] = df[LABEL].str.strip().str.lower()
    allowed = {v.value for v in Verdict}
    bad = sorted(set(df[LABEL]) - allowed)
    if bad:
        raise ValueError(f"Недопустимые метки: {bad}; допустимы {sorted(allowed)}")
    if "seconds_spent" in df:
        df["seconds_spent"] = pd.to_numeric(df["seconds_spent"], errors="coerce")
    if TECHNIQUE in df:
        df[TECHNIQUE] = df[TECHNIQUE].str.strip().str.upper()
        given = df.loc[df[TECHNIQUE] != "", TECHNIQUE]
        bad_tech = sorted(set(given[~given.str.match(TECHNIQUE_PATTERN)]))
        if bad_tech:
            raise ValueError(f"Неверный формат техники ATT&CK: {bad_tech}; ожидается T1234 или T1234.001")
    return df.drop_duplicates(subset=[ALERT_ID], keep="last").reset_index(drop=True)


def technique_counts(labels: pd.DataFrame) -> dict[str, int]:
    """Сколько найденных атак отнесено к каждой технике ATT&CK (только метки «атака»)."""
    if TECHNIQUE not in labels:
        return {}
    attacks = labels.loc[(labels[LABEL] == Verdict.ATTACK.value) & (labels[TECHNIQUE] != "")]
    counts = attacks[TECHNIQUE].value_counts()
    return {str(k): int(v) for k, v in counts.sort_index().items()}


def attach_labels(
    plan: SamplingPlan, labels: pd.DataFrame, unknown_policy: str = "as_attack"
) -> pd.DataFrame:
    """Добавить к плану колонку y: 1 — атака, 0 — нет, NaN — не размечено или исключено.

    Политика ``as_attack`` (по умолчанию, консервативно): метка «не знаю» и неразмеченные отобранные
    алерты при расчёте считаются атаками — граница остаётся корректной, но становится шире.
    Политика ``exclude``: такие алерты исключаются из выборки; если пропуски связаны с содержанием
    алерта, оценка может сместиться — это фиксируется в отчёте.
    """
    frame = plan.frame.copy()
    lab = labels.set_index(ALERT_ID)[LABEL]
    mapped = frame[ALERT_ID].astype(str).map(lab)
    y = pd.Series(np.nan, index=frame.index, dtype=float)
    y[mapped == Verdict.ATTACK.value] = 1.0
    y[mapped == Verdict.BENIGN.value] = 0.0
    if unknown_policy == "as_attack":
        y[mapped == Verdict.UNKNOWN.value] = 1.0
    frame[Y] = y
    frame["labeled"] = mapped.notna()
    frame["missing_label"] = frame[SELECTED] & ~frame["labeled"]
    return frame

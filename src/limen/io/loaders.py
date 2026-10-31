"""Чтение выгрузки закрытых алертов и приведение к канонической схеме."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd

from limen.config import FieldMapping, ValueMap
from limen.schema import (
    ALERT_ID,
    CLOSED_AT,
    CLOSING_SOURCE,
    RULE_ID,
    SCORE,
    VERDICT,
    ClosingSource,
    Verdict,
)


def read_table(path: str | Path, mapping: FieldMapping) -> pd.DataFrame:
    """Прочитать файл выгрузки в «сыром» виде (до маппинга)."""
    p = Path(path)
    fmt = mapping.format
    if fmt == "csv":
        return pd.read_csv(
            p, sep=mapping.csv.sep, encoding=mapping.csv.encoding, dtype=str, keep_default_na=False
        )
    if fmt == "jsonl":
        return pd.read_json(p, lines=True, dtype=False)
    # json: массив записей или объект с массивом под ключом records_path
    with p.open(encoding="utf-8") as fh:
        payload: Any = json.load(fh)
    if mapping.json_options.records_path:
        payload = payload[mapping.json_options.records_path]
    if not isinstance(payload, list):
        raise ValueError("Ожидался JSON-массив алертов; укажите json.records_path в маппинге")
    return pd.json_normalize(payload)


def _map_values(series: pd.Series[Any], vmap: ValueMap) -> pd.Series[Any]:
    """Сопоставить значения без учёта регистра и пробелов по краям."""
    lookup = {k.strip().lower(): v for k, v in vmap.values.items()}
    normalized = series.astype(str).str.strip().str.lower()
    return normalized.map(lookup).fillna(vmap.default)


def apply_mapping(raw: pd.DataFrame, mapping: FieldMapping) -> pd.DataFrame:
    """Переименовать колонки, вывести источник закрытия и вердикт, привести типы.

    Колонки сущностей (``mapping.entities``) сохраняются под исходными именами —
    их обезличивает ``limen.privacy`` до любых дальнейших шагов.
    """
    missing = [src for src in mapping.columns.values() if src not in raw.columns]
    if missing:
        raise KeyError(f"В выгрузке нет колонок из маппинга: {missing}")
    if mapping.closing_source.field not in raw.columns:
        raise KeyError(
            f"В выгрузке нет поля источника закрытия «{mapping.closing_source.field}». "
            "Без него нельзя отличить автозакрытие от ручного — аудит невозможен."
        )

    out = pd.DataFrame(index=raw.index)
    for canonical, source in mapping.columns.items():
        out[canonical] = raw[source]

    out[CLOSING_SOURCE] = _map_values(raw[mapping.closing_source.field], mapping.closing_source)
    if mapping.verdict is not None and mapping.verdict.field in raw.columns:
        out[VERDICT] = _map_values(raw[mapping.verdict.field], mapping.verdict)
    else:
        out[VERDICT] = Verdict.UNKNOWN.value

    for col in mapping.entities:
        if col in raw.columns:
            out[col] = raw[col].astype(str)

    out[ALERT_ID] = out[ALERT_ID].astype(str)
    out[RULE_ID] = out[RULE_ID].astype(str).replace({"": "__no_rule__"})
    if CLOSED_AT in out:
        out[CLOSED_AT] = pd.to_datetime(out[CLOSED_AT], errors="coerce", utc=True)
    if SCORE in out:
        out[SCORE] = pd.to_numeric(out[SCORE], errors="coerce").clip(0.0, 1.0)

    out.attrs["entity_columns"] = dict(mapping.entities)
    return out.reset_index(drop=True)


def load_export(path: str | Path, mapping: FieldMapping) -> pd.DataFrame:
    """Прочитать выгрузку и привести к канонической схеме."""
    return apply_mapping(read_table(path, mapping), mapping)


def automated_subset(df: pd.DataFrame, sources: tuple[ClosingSource, ...]) -> pd.DataFrame:
    """Алерты, закрытые без аналитика (объект аудита)."""
    mask = df[CLOSING_SOURCE].isin([s.value for s in sources])
    return df.loc[mask].reset_index(drop=True)

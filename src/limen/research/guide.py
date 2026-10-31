"""Загрузка Microsoft GUIDE и агрегация до инцидентов.

GUIDE (Freitas и др., arXiv:2407.09017): около 13 млн улик, 1,6 млн алертов, 1 млн инцидентов
из 6,1 тыс. организаций; метки триажа (TP/BP/FP) поставили аналитики клиентов.
Метка задана на уровне инцидента, поэтому единица наблюдения — инцидент.

Против утечки: в признаки не попадают поля, которые появляются после решения аналитика
(например, выполненные действия по реагированию). Список признаков — NUMERIC и CATEGORICAL ниже.
"""

from __future__ import annotations

import json
from typing import Any

import pandas as pd

from limen.research.config import DataCfg

KEYS = ["org", "incident"]
NUMERIC = [
    "n_evidence",
    "n_alerts",
    "n_detectors",
    "n_categories",
    "n_entity_types",
    "n_mitre",
    "duration_h",
    "hour",
]
CATEGORICAL = ["top_detector", "top_category"]


def load_guide(cfg: DataCfg) -> pd.DataFrame:
    """Прочитать нужные колонки CSV GUIDE и переименовать в короткие имена из конфигурации."""
    cols = cfg.columns
    df = pd.read_csv(cfg.path, usecols=list(cols.values()), nrows=cfg.nrows, low_memory=False)
    return df.rename(columns={v: k for k, v in cols.items()})


def _group_mode(df: pd.DataFrame, col: str) -> pd.Series[Any]:
    """Наиболее частое значение колонки в каждом инциденте (быстрее, чем groupby().agg(mode))."""
    counts = df.groupby([*KEYS, col], observed=True).size().reset_index(name="_n")
    counts = counts.sort_values([*KEYS, "_n"], ascending=[True, True, False]).drop_duplicates(KEYS)
    return counts.set_index(KEYS)[col]


def to_incidents(df: pd.DataFrame, attack_grade: str = "TruePositive") -> pd.DataFrame:
    """Агрегировать улики до инцидентов; y = 1 для истинных атак (TruePositive)."""
    df = df.dropna(subset=["grade"]).copy()
    df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    g = df.groupby(KEYS, sort=False, observed=True)
    inc = g.agg(
        n_evidence=("alert", "size"),
        n_alerts=("alert", "nunique"),
        n_detectors=("detector", "nunique"),
        n_categories=("category", "nunique"),
        n_entity_types=("entity_type", "nunique"),
        n_mitre=("mitre", "count"),
        t_first=("ts", "min"),
        t_last=("ts", "max"),
        grade=("grade", "first"),
    )
    inc["top_detector"] = _group_mode(df, "detector").astype(str)
    inc["top_category"] = _group_mode(df, "category").astype(str)
    inc["duration_h"] = (inc["t_last"] - inc["t_first"]).dt.total_seconds() / 3600.0
    inc["hour"] = inc["t_first"].dt.hour
    inc["y"] = (inc["grade"] == attack_grade).astype(int)
    inc = inc.reset_index()
    inc["alert_id"] = inc["org"].astype(str) + ":" + inc["incident"].astype(str)
    return inc.drop(columns=["t_first", "t_last"])


def _cache_meta(cfg: DataCfg) -> dict[str, Any]:
    return {
        "source": str(cfg.path),
        "nrows": cfg.nrows,
        "attack_grade": cfg.attack_grade,
        "columns": dict(cfg.columns),
    }


def load_incidents(cfg: DataCfg, *, rebuild: bool = False) -> pd.DataFrame:
    """Инциденты из кэша (CSV, сжатый gzip) или построенные заново из исходного CSV.

    Рядом с кэшем лежит описание источника (*.meta.json). Если параметры загрузки изменились
    (другой файл, другое nrows), кэш пересобирается — отладочный прогон не подменит данные полного.
    """
    meta_path = cfg.processed_path.with_suffix(".meta.json")
    meta = _cache_meta(cfg)
    cached = cfg.processed_path.exists() and meta_path.exists() and not rebuild
    if cached and json.loads(meta_path.read_text(encoding="utf-8")) == meta:
        return pd.read_csv(
            cfg.processed_path, dtype={"top_detector": str, "top_category": str, "alert_id": str}
        )
    inc = to_incidents(load_guide(cfg), cfg.attack_grade)
    cfg.processed_path.parent.mkdir(parents=True, exist_ok=True)
    inc.to_csv(cfg.processed_path, index=False)
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return inc

"""Сквозной конвейер аудита: подготовка выгрузки → план → оценка по меткам → результат."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from limen import __version__
from limen.audit.estimate import attacks_open_counts, estimate_overall, estimate_per_rule
from limen.audit.labels import attach_labels, technique_counts
from limen.audit.recommend import recommend
from limen.config import AuditConfig, FieldMapping
from limen.integrity import sha256_json
from limen.io.loaders import automated_subset, load_export
from limen.io.validation import ValidationReport, validate
from limen.privacy.pseudonymize import alert_id_lookup, pseudonymize_frame
from limen.sampling.plans import SamplingPlan, make_plan
from limen.schema import (
    ALERT_ID,
    CLOSED_AT,
    CLOSING_REASON,
    CLOSING_SOURCE,
    RULE_ID,
    SCORE,
    SELECTED,
    VERDICT,
)
from limen.stats.fnr import AuditEstimate

# Основной режим поставки: только эти поля уходят за контур заказчика.
MINIMAL_COLUMNS: tuple[str, ...] = (
    ALERT_ID,
    RULE_ID,
    CLOSING_SOURCE,
    CLOSED_AT,
    CLOSING_REASON,
    VERDICT,
    SCORE,
)


def prepare(
    export_path: str | Path,
    mapping: FieldMapping,
    key: bytes,
    cfg: AuditConfig,
    *,
    keep_mapping: bool = False,
) -> tuple[pd.DataFrame, ValidationReport, pd.DataFrame | None]:
    """Прочитать выгрузку, проверить и обезличить. Исходные чувствительные колонки удаляются."""
    alerts = load_export(export_path, mapping)
    alerts = alerts.drop_duplicates(subset=[ALERT_ID], keep="last").reset_index(drop=True)
    report = validate(alerts, cfg.audited_sources)
    alerts, table = pseudonymize_frame(alerts, mapping.entities, key, keep_mapping=keep_mapping)
    return alerts, report, table


def minimal_export(
    alerts: pd.DataFrame, key: bytes | None, *, hash_ids: bool = True, with_reason: bool = True
) -> pd.DataFrame:
    """Минимальная таблица для передачи за контур (основной режим поставки).

    Остаются: псевдоним alert_id, правило, источник и время закрытия, причина закрытия (если её
    значения — справочник, а не свободный текст), вердикт аналитика attack/benign/unknown
    (нужен для числа найденных атак A_O) и оценка модели. Учётки, хосты, адреса и названия правил не уходят.
    """
    cols = [c for c in MINIMAL_COLUMNS if c in alerts.columns and (with_reason or c != CLOSING_REASON)]
    out = alerts[cols].copy()
    out.attrs = {}
    if hash_ids:
        if key is None:
            raise ValueError("Для замены alert_id псевдонимами нужен ключ обезличивания")
        lookup = alert_id_lookup(out[ALERT_ID].astype(str), key)
        out[ALERT_ID] = out[ALERT_ID].astype(str).map(lookup)
    return out


def config_sha256(cfg: AuditConfig) -> str:
    """Хеш параметров аудита: фиксируется в протоколе пилота и в плане выборки."""
    return sha256_json(cfg.model_dump(mode="json"))


def build_plan(alerts: pd.DataFrame, cfg: AuditConfig, alerts_sha256: str | None = None) -> SamplingPlan:
    """План выборки по автозакрытым алертам. В метаданные плана записываются хеши входов."""
    closed = automated_subset(alerts, cfg.audited_sources)
    s = cfg.sampling
    plan = make_plan(closed, s.scheme, s.budget, s.seed, s.stratum_column, s.min_per_stratum, s.active_floor)
    plan.meta["config_sha256"] = config_sha256(cfg)
    if alerts_sha256:
        plan.meta["alerts_sha256"] = alerts_sha256
    return plan


@dataclass
class AuditResult:
    overall: AuditEstimate
    per_rule: pd.DataFrame
    config: dict[str, Any]
    labeling: dict[str, Any]
    validation: dict[str, Any] = field(default_factory=dict)
    inputs: dict[str, Any] = field(default_factory=dict)  # SHA-256 входов: таблица, план, метки, конфигурация
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))
    version: str = __version__

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "config": self.config,
            "validation": self.validation,
            "inputs": self.inputs,
            "labeling": self.labeling,
            "overall": self.overall.to_dict(),
            "per_rule": json.loads(self.per_rule.to_json(orient="records", force_ascii=False)),
        }

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | Path) -> AuditResult:
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            overall=AuditEstimate(**d["overall"]),
            per_rule=pd.DataFrame(d["per_rule"]),
            config=d["config"],
            labeling=d["labeling"],
            validation=d.get("validation", {}),
            inputs=d.get("inputs", {}),
            created_at=d["created_at"],
            version=d["version"],
        )


def evaluate(
    alerts: pd.DataFrame,
    plan: SamplingPlan,
    labels: pd.DataFrame,
    cfg: AuditConfig,
    validation: ValidationReport | None = None,
    inputs: dict[str, Any] | None = None,
) -> AuditResult:
    """Посчитать границы по плану и меткам аналитиков."""
    closed = automated_subset(alerts, cfg.audited_sources)
    a_open, a_open_by_rule = attacks_open_counts(alerts)
    labeled = attach_labels(plan, labels, cfg.estimation.unknown_label_policy)

    overall = estimate_overall(plan, labeled, a_open, cfg)
    per_rule = recommend(estimate_per_rule(closed, plan, labeled, a_open_by_rule, cfg), cfg.target_for)

    sel = labeled.loc[labeled[SELECTED]]
    seconds = pd.to_numeric(labels["seconds_spent"], errors="coerce") if "seconds_spent" in labels else None
    labeling = {
        "n_selected": len(sel),
        "n_labeled": int(sel["labeled"].sum()),
        "n_missing": int(sel["missing_label"].sum()),
        "median_seconds_per_alert": (
            float(seconds.median()) if seconds is not None and seconds.notna().any() else None
        ),
        "attack_techniques": technique_counts(labels),
    }
    vdict = (
        {
            "n_rows": validation.n_rows,
            "counts_by_source": validation.counts_by_source,
            "period": validation.period,
            "warnings": validation.warnings,
        }
        if validation
        else {}
    )
    return AuditResult(overall, per_rule, cfg.model_dump(mode="json"), labeling, vdict, dict(inputs or {}))

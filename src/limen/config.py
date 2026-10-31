"""Конфигурация аудита и маппинга выгрузок (YAML → pydantic)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, TypeVar

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from limen.schema import ClosingSource, Verdict

ModelT = TypeVar("ModelT", bound=BaseModel)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# ----------------------------------------------------------------------------- маппинг выгрузки
class CsvOptions(_Strict):
    sep: str = ","
    encoding: str = "utf-8"


class JsonOptions(_Strict):
    records_path: str | None = None  # ключ, под которым лежит массив алертов


class ValueMap(_Strict):
    """Отображение значений колонки выгрузки в каноническое значение."""

    field: str
    values: dict[str, str] = Field(default_factory=dict)
    default: str = "unknown"


class FieldMapping(_Strict):
    """Как привести выгрузку конкретной SIEM/SOAR к канонической схеме."""

    format: Literal["csv", "json", "jsonl"] = "csv"
    csv: CsvOptions = CsvOptions()
    json_options: JsonOptions = Field(default=JsonOptions(), alias="json")
    columns: dict[str, str]  # каноническое поле → колонка в выгрузке
    closing_source: ValueMap
    verdict: ValueMap | None = None
    entities: dict[str, str] = Field(default_factory=dict)  # колонка → префикс идентификатора

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    @field_validator("closing_source")
    @classmethod
    def _check_sources(cls, v: ValueMap) -> ValueMap:
        allowed = {s.value for s in ClosingSource}
        bad = {x for x in [*v.values.values(), v.default] if x not in allowed}
        if bad:
            raise ValueError(f"Недопустимые источники закрытия: {sorted(bad)}; допустимы {sorted(allowed)}")
        return v

    @field_validator("verdict")
    @classmethod
    def _check_verdicts(cls, v: ValueMap | None) -> ValueMap | None:
        if v is None:
            return v
        allowed = {s.value for s in Verdict}
        bad = {x for x in [*v.values.values(), v.default] if x not in allowed}
        if bad:
            raise ValueError(f"Недопустимые вердикты: {sorted(bad)}; допустимы {sorted(allowed)}")
        return v


# ----------------------------------------------------------------------------- параметры аудита
class SamplingConfig(_Strict):
    scheme: Literal["uniform", "stratified", "active"] = "uniform"
    budget: int = Field(default=300, gt=0)
    seed: int = 20261027
    stratum_column: str = "rule_id"
    min_per_stratum: int = Field(default=5, ge=0)
    active_floor: float = Field(default=0.2, gt=0, le=1)


class EstimationConfig(_Strict):
    bound_method: Literal["binomial", "hypergeometric"] = "binomial"
    stratified_method: Literal["union", "korn_graubard"] = "union"
    simultaneous_rules: bool = False
    unknown_label_policy: Literal["as_attack", "exclude"] = "as_attack"


class AuditConfig(_Strict):
    confidence: float = Field(default=0.95, gt=0.5, lt=1)
    target_for: float = Field(default=0.01, gt=0, lt=1)
    audited_sources: tuple[ClosingSource, ...] = (ClosingSource.AUTO, ClosingSource.SUPPRESSION)
    sampling: SamplingConfig = SamplingConfig()
    estimation: EstimationConfig = EstimationConfig()

    @property
    def delta(self) -> float:
        """Допустимая вероятность ошибки границы: δ = 1 − уверенность."""
        return 1.0 - self.confidence


# ----------------------------------------------------------------------------- загрузка
def load_yaml(path: str | Path, model: type[ModelT]) -> ModelT:
    """Прочитать YAML и проверить его моделью pydantic."""
    with Path(path).open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return model.model_validate(raw)


def load_audit_config(path: str | Path | None) -> AuditConfig:
    return AuditConfig() if path is None else load_yaml(path, AuditConfig)


def load_mapping(path: str | Path) -> FieldMapping:
    return load_yaml(path, FieldMapping)

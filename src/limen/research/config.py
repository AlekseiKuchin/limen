"""Конфигурация эксперимента H1/H2 (configs/experiments/*.yaml)."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DataCfg(_M):
    path: Path
    nrows: int | None = None
    attack_grade: str = "TruePositive"
    columns: dict[str, str]
    processed_path: Path = Path("data/processed/guide_incidents.csv.gz")


class SplitCfg(_M):
    n_reps: int = Field(default=200, gt=0)
    train_frac: float = Field(default=0.5, gt=0, lt=1)
    seed: int = 20261027


class AutocloserCfg(_M):
    iterations: int = 300
    depth: int = 6
    learning_rate: float = 0.1
    max_train_rows: int = 300_000
    thread_count: int = -1


class AuditSimCfg(_M):
    close_shares: list[float] = [0.30, 0.68]
    budgets: list[int] = [100, 300, 1000]
    schemes: list[str] = ["uniform", "stratified", "active", "naive_top"]
    confidence: float = 0.95
    stratum_column: str = "top_detector"
    min_per_stratum: int = 2
    active_floor: float = 0.2


class HypothesesCfg(_M):
    h1_tolerance: float = 0.10
    h2_budget: int = 300
    h2_reduction: float = 0.20
    h2_baseline: str = "uniform"
    h2_candidate: str = "active"
    alpha: float = 0.05  # уровень значимости тестов


class OutputCfg(_M):
    dir: Path = Path("reports/experiments")


class TrackingCfg(_M):
    experiment: str = "limen-guide-audit"


class ExperimentConfig(_M):
    data: DataCfg
    split: SplitCfg = SplitCfg()
    autocloser: AutocloserCfg = AutocloserCfg()
    audit: AuditSimCfg = AuditSimCfg()
    hypotheses: HypothesesCfg = HypothesesCfg()
    output: OutputCfg = OutputCfg()
    tracking: TrackingCfg = TrackingCfg()

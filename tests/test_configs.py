"""Все YAML из configs/ проходят проверку схемой: опечатка в конфиге ловится до пилота или эксперимента."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from limen.config import load_audit_config, load_mapping, load_yaml
from limen.research.config import DataCfg, ExperimentConfig
from limen.research.guide import load_incidents

ROOT = Path(__file__).resolve().parents[1]
MAPPINGS = sorted((ROOT / "configs" / "mappings").glob("*.yaml"))
EXPERIMENTS = sorted((ROOT / "configs" / "experiments").glob("*.yaml"))


@pytest.mark.parametrize("path", MAPPINGS, ids=lambda p: p.name)
def test_mappings_are_valid(path: Path) -> None:
    m = load_mapping(path)
    assert {"alert_id", "rule_id"} <= set(m.columns)


def test_audit_example_is_valid() -> None:
    cfg = load_audit_config(ROOT / "configs" / "audit.example.yaml")
    assert 0.5 < cfg.confidence < 1
    assert cfg.sampling.budget > 0


@pytest.mark.parametrize("path", EXPERIMENTS, ids=lambda p: p.name)
def test_experiment_configs_are_valid(path: Path) -> None:
    cfg = load_yaml(path, ExperimentConfig)
    assert cfg.audit.schemes and cfg.audit.budgets


def test_smoke_and_full_runs_do_not_share_outputs() -> None:
    smoke = load_yaml(ROOT / "configs" / "experiments" / "guide_smoke.yaml", ExperimentConfig)
    full = load_yaml(ROOT / "configs" / "experiments" / "guide_audit.yaml", ExperimentConfig)
    assert smoke.data.processed_path != full.data.processed_path
    assert smoke.output.dir != full.output.dir


def test_incident_cache_rebuilds_when_source_changes(tmp_path: Path) -> None:
    columns = load_yaml(ROOT / "configs" / "experiments" / "guide_smoke.yaml", ExperimentConfig).data.columns
    raw = {
        "org": [1, 1, 2],
        "incident": [10, 11, 20],
        "alert": [100, 101, 200],
        "detector": [5, 6, 5],
        "category": ["InitialAccess", "Exfiltration", "InitialAccess"],
        "grade": ["TruePositive", "FalsePositive", "BenignPositive"],
        "timestamp": ["2024-06-01T00:00:00Z"] * 3,
        "mitre": ["T1078", "", "T1566"],
        "entity_type": ["User", "Ip", "User"],
    }
    csv = tmp_path / "guide.csv"
    pd.DataFrame({columns[k]: v for k, v in raw.items()}).to_csv(csv, index=False)
    cache = tmp_path / "inc.csv.gz"
    full = load_incidents(DataCfg(path=csv, columns=columns, processed_path=cache))
    again = load_incidents(DataCfg(path=csv, columns=columns, processed_path=cache))
    part = load_incidents(DataCfg(path=csv, columns=columns, processed_path=cache, nrows=1))
    assert len(full) == len(again) == 3
    assert len(part) == 1  # другое nrows — кэш пересобран, а не прочитан


def test_package_version_matches_pyproject() -> None:
    import tomllib

    import limen

    with (ROOT / "pyproject.toml").open("rb") as fh:
        assert tomllib.load(fh)["project"]["version"] == limen.__version__

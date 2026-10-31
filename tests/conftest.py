from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from limen.config import AuditConfig, load_mapping
from limen.privacy.pseudonymize import generate_key
from limen.synthetic import SyntheticSpec, make_synthetic_export

ROOT = Path(__file__).resolve().parents[1]
GENERIC_MAPPING = ROOT / "configs" / "mappings" / "generic_csv.yaml"


@pytest.fixture(scope="session")
def synthetic() -> tuple[pd.DataFrame, pd.DataFrame]:
    return make_synthetic_export(SyntheticSpec(n_alerts=6000, n_rules=25, seed=11))


@pytest.fixture()
def export_csv(tmp_path: Path, synthetic: tuple[pd.DataFrame, pd.DataFrame]) -> Path:
    export, _ = synthetic
    p = tmp_path / "export.csv"
    export.to_csv(p, index=False)
    return p


@pytest.fixture()
def truth(synthetic: tuple[pd.DataFrame, pd.DataFrame]) -> pd.Series:
    _, t = synthetic
    return t.set_index("alert_id")["is_attack"]


@pytest.fixture()
def key_file(tmp_path: Path) -> Path:
    return generate_key(tmp_path / "pseudo.key")


@pytest.fixture()
def mapping():  # type: ignore[no-untyped-def]
    return load_mapping(GENERIC_MAPPING)


@pytest.fixture()
def cfg() -> AuditConfig:
    return AuditConfig()

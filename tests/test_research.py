"""Исследовательский контур: симуляция без CatBoost (подменённая модель) и проверка гипотез."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from limen.research.config import AuditSimCfg, DataCfg, ExperimentConfig, HypothesesCfg, SplitCfg
from limen.research.guide import to_incidents
from limen.research.hypotheses import bias_table, h1_table, h2_test
from limen.research.simulate import roc_auc, run_simulation


def _fake_incidents(n: int = 6000, n_orgs: int = 60, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    org = rng.integers(0, n_orgs, n)
    detector = rng.choice([f"d{i}" for i in range(12)], n)
    base = rng.beta(0.6, 6, n)
    y = (rng.random(n) < base).astype(int)
    return pd.DataFrame(
        {
            "org": org,
            "incident": np.arange(n),
            "alert_id": [f"{o}:{i}" for o, i in zip(org, range(n), strict=True)],
            "top_detector": detector,
            "y": y,
            "p_true": base,
        }
    )


def _oracle_scores(train: pd.DataFrame, audit: pd.DataFrame, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return np.clip(audit["p_true"].to_numpy() + rng.normal(0, 0.05, len(audit)), 0, 1)


def test_simulation_and_hypotheses() -> None:
    cfg = ExperimentConfig(
        data=DataCfg(path="unused.csv", columns={}),
        split=SplitCfg(n_reps=6, train_frac=0.5, seed=3),
        audit=AuditSimCfg(
            close_shares=[0.3], budgets=[150], schemes=["uniform", "stratified", "active", "naive_top"]
        ),
        hypotheses=HypothesesCfg(h2_budget=150),
    )
    res = run_simulation(_fake_incidents(), cfg, score_fn=_oracle_scores)
    assert len(res) == 6 * 4
    assert res["fnr_upper"].between(0, 1).all()
    assert res["model_auc"].between(0.5, 1).all()  # «оракульная» модель лучше случайной
    h1 = h1_table(res, cfg.hypotheses)
    assert set(h1["scheme"]) == {"uniform", "stratified", "active", "naive_top"}
    h2 = h2_test(res, cfg.hypotheses)
    assert h2 and 0 < h2[0]["pairs"] <= 6
    bias = bias_table(res, cfg.hypotheses)
    assert set(bias["scheme"]) == set(h1["scheme"])
    assert bias["median_bias"].notna().all()


def test_to_incidents_aggregates_evidence() -> None:
    ev = pd.DataFrame(
        {
            "org": [1, 1, 1, 2],
            "incident": [10, 10, 11, 20],
            "alert": [100, 101, 102, 200],
            "detector": ["d1", "d1", "d2", "d3"],
            "category": ["c", "c", "c", "x"],
            "grade": ["TruePositive", "TruePositive", "FalsePositive", None],
            "timestamp": [
                "2024-06-01T00:00:00Z",
                "2024-06-01T02:00:00Z",
                "2024-06-02T00:00:00Z",
                "2024-06-03T00:00:00Z",
            ],
            "mitre": ["T1", None, None, None],
            "entity_type": ["Ip", "User", "Ip", "Ip"],
        }
    )
    inc = to_incidents(ev)
    assert len(inc) == 2  # инцидент без метки отброшен
    row = inc.set_index("alert_id").loc["1:10"]
    assert row["y"] == 1 and row["n_alerts"] == 2 and row["top_detector"] == "d1"
    assert row["duration_h"] == pytest.approx(2.0)


@pytest.mark.research
def test_catboost_autocloser_smoke() -> None:
    pytest.importorskip("catboost")
    from limen.research.autocloser import close_lowest, predict_attack_proba, train_autocloser
    from limen.research.config import AutocloserCfg
    from limen.research.guide import CATEGORICAL, NUMERIC

    rng = np.random.default_rng(0)
    n = 800
    df = pd.DataFrame({c: rng.random(n) for c in NUMERIC})
    for c in CATEGORICAL:
        df[c] = rng.choice(["a", "b", "c"], n)
    df["y"] = (df["n_evidence"] > 0.7).astype(int)
    model = train_autocloser(df, AutocloserCfg(iterations=30, depth=3), seed=1)
    p = predict_attack_proba(model, df)
    assert p.shape == (n,)
    assert close_lowest(p, 0.3).sum() == round(0.3 * n)


def test_roc_auc_matches_definition() -> None:
    y = np.array([0, 0, 1, 1])
    assert roc_auc(np.array([0.1, 0.2, 0.8, 0.9]), y) == 1.0
    assert roc_auc(np.array([0.9, 0.8, 0.2, 0.1]), y) == 0.0
    assert roc_auc(np.array([0.5, 0.5, 0.5, 0.5]), y) == 0.5
    assert np.isnan(roc_auc(np.array([0.1, 0.2]), np.array([1, 1])))

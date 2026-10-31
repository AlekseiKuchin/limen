from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from limen.sampling.plans import OTHER_STRATUM, SamplingPlan, allocate_stratified, make_plan
from limen.schema import ALERT_ID, RULE_ID, SCORE, SELECTED, STRATUM


@pytest.fixture()
def closed() -> pd.DataFrame:
    rng = np.random.default_rng(3)
    n = 3000
    return pd.DataFrame(
        {
            ALERT_ID: [f"a{i}" for i in range(n)],
            RULE_ID: rng.choice(
                [f"r{j}" for j in range(30)], n, p=np.r_[np.full(10, 0.07), np.full(20, 0.015)]
            ),
            SCORE: rng.beta(0.5, 10, n),
        }
    )


def test_uniform_exact_size_and_reproducible(closed: pd.DataFrame) -> None:
    a = make_plan(closed, "uniform", 300, seed=42)
    b = make_plan(closed, "uniform", 300, seed=42)
    assert a.n_selected == 300
    assert a.selected_ids() == b.selected_ids()
    assert make_plan(closed, "uniform", 300, seed=43).selected_ids() != a.selected_ids()


def test_stratified_respects_budget_and_minimum(closed: pd.DataFrame) -> None:
    plan = make_plan(closed, "stratified", 120, seed=1, min_per_stratum=5)
    per_stratum = plan.frame.groupby(STRATUM)[SELECTED].sum()
    assert plan.n_selected == 120
    assert (per_stratum >= 5).all()
    assert OTHER_STRATUM in set(plan.frame[STRATUM])  # мелкие правила слиты


def test_allocation_proportional() -> None:
    sizes = pd.Series({"a": 900, "b": 90, "c": 10})
    alloc = allocate_stratified(sizes, 100, min_per_stratum=2)
    assert alloc.sum() == 100
    assert alloc["a"] > alloc["b"] > 0
    assert alloc["c"] >= 2


def test_active_requires_score(closed: pd.DataFrame) -> None:
    with pytest.raises(ValueError):
        make_plan(closed.drop(columns=[SCORE]), "active", 100, seed=1)
    plan = make_plan(closed, "active", 300, seed=1)
    assert abs(plan.n_selected - 300) < 80  # выборка Пуассона: размер случайный


def test_plan_roundtrip_csv(tmp_path: Path, closed: pd.DataFrame) -> None:
    plan = make_plan(closed, "stratified", 100, seed=5)
    p = tmp_path / "plan.csv"
    plan.to_csv(p)
    back = SamplingPlan.from_csv(p)
    assert back.scheme == "stratified" and back.seed == 5 and back.budget == 100
    assert back.selected_ids() == plan.selected_ids()

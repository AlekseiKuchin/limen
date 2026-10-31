"""Планы выборки.

Каждый план фиксирует схему, зерно генератора и вероятность отбора каждого алерта — план воспроизводим
и проверяем: заказчик может пересчитать его сам. Гарантии границ держатся на случайности отбора,
а не на предположениях о модели или о распределении данных.

* ``uniform`` — простая случайная выборка без возвращения (корректно на конечной выборке);
* ``stratified`` — выборка по стратам (правилам) с минимумом на страту;
* ``active`` — выборка Пуассона с π_i ∝ неопределённости модели (нужна колонка score);
* ``naive_top`` — «перепроверить самое подозрительное» без весов: только для исследования (H1, схема «г»).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from limen.schema import ALERT_ID, INCLUSION_PROB, RULE_ID, SCORE, SELECTED, STRATUM
from limen.stats.active import inclusion_probs, poisson_sample, uncertainty

OTHER_STRATUM = "__other__"


@dataclass
class SamplingPlan:
    scheme: str
    seed: int
    budget: int
    frame: pd.DataFrame  # alert_id, stratum, inclusion_prob, selected (+ score для active)
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def n_selected(self) -> int:
        return int(self.frame[SELECTED].sum())

    def selected_ids(self) -> list[str]:
        return [str(x) for x in self.frame.loc[self.frame[SELECTED], ALERT_ID]]

    def to_csv(self, path: str | Path) -> None:
        df = self.frame.copy()
        df.attrs = {}
        for k, v in {"scheme": self.scheme, "seed": self.seed, "budget": self.budget, **self.meta}.items():
            df[f"__meta_{k}"] = v
        df.to_csv(path, index=False)

    @classmethod
    def from_csv(cls, path: str | Path) -> SamplingPlan:
        header = pd.read_csv(path, nrows=0).columns
        meta_cols = [c for c in header if c.startswith("__meta_")]
        df = pd.read_csv(path, dtype={ALERT_ID: str, STRATUM: str, **dict.fromkeys(meta_cols, str)})
        meta = {c.removeprefix("__meta_"): df[c].iloc[0] for c in meta_cols} if len(df) else {}
        df = df.drop(columns=meta_cols)
        df[SELECTED] = df[SELECTED].astype(bool)
        scheme = str(meta.pop("scheme", "uniform"))
        seed = int(meta.pop("seed", 0))
        budget = int(meta.pop("budget", int(df[SELECTED].sum())))
        return cls(scheme=scheme, seed=seed, budget=budget, frame=df, meta=meta)


def _base_frame(closed: pd.DataFrame, stratum_col: str) -> pd.DataFrame:
    frame = pd.DataFrame({ALERT_ID: closed[ALERT_ID].astype(str).to_numpy()})
    frame[STRATUM] = closed[stratum_col].astype(str).to_numpy() if stratum_col in closed else "all"
    return frame


def plan_uniform(closed: pd.DataFrame, budget: int, seed: int, stratum_col: str = RULE_ID) -> SamplingPlan:
    rng = np.random.default_rng(seed)
    frame = _base_frame(closed, stratum_col)
    n_pop = len(frame)
    n = min(budget, n_pop)
    chosen = rng.choice(n_pop, size=n, replace=False) if n else np.array([], dtype=int)
    frame[SELECTED] = False
    frame.loc[chosen, SELECTED] = True
    frame[INCLUSION_PROB] = n / n_pop if n_pop else 0.0
    return SamplingPlan("uniform", seed, budget, frame)


def _merge_small_strata(sizes: pd.Series[Any], budget: int, min_per_stratum: int) -> dict[str, str]:
    """Слить самые мелкие страты в «прочие», пока минимум на страту помещается в бюджет."""
    rename: dict[str, str] = {}
    if min_per_stratum <= 0:
        return rename
    order = sizes.sort_values(ascending=True)
    kept = len(order)
    for name in order.index:
        n_strata = kept + (1 if rename else 0)  # слитые правила образуют ещё одну страту «прочие»
        if n_strata * min_per_stratum <= budget:
            break
        rename[str(name)] = OTHER_STRATUM
        kept -= 1
    return rename


def allocate_stratified(
    sizes: pd.Series[Any], budget: int, min_per_stratum: int = 0, prior_rates: pd.Series[Any] | None = None
) -> pd.Series[Any]:
    """Распределить бюджет по стратам: пропорционально N_h (или по Нейману, если даны оценки доли атак),
    с минимумом на страту и округлением методом наибольших остатков."""
    sizes = sizes.astype(int)
    budget = min(budget, int(sizes.sum()))
    if prior_rates is not None:
        p = prior_rates.reindex(sizes.index).fillna(prior_rates.mean()).clip(1e-4, 1 - 1e-4)
        weights = sizes * np.sqrt(p * (1 - p))
    else:
        weights = sizes.astype(float)
    base = np.minimum(sizes, min_per_stratum).astype(int)
    rest = budget - int(base.sum())
    if rest < 0:
        raise ValueError("Минимум на страту не помещается в бюджет — увеличьте бюджет или слейте страты")
    room = (sizes - base).astype(float)
    alloc = base.astype(float)
    while rest > 0 and room.sum() > 0:
        w = weights.where(room > 0, 0.0)
        if w.sum() == 0:
            w = room
        share = w / w.sum() * rest
        add = np.minimum(np.floor(share), room)
        if add.sum() == 0:  # распределяем остаток по наибольшим дробным частям
            frac = (share - np.floor(share)).where(room > 0, -1.0)
            top = frac.sort_values(ascending=False).index[: int(rest)]
            add = pd.Series(0.0, index=sizes.index)
            add.loc[top] = 1.0
            add = np.minimum(add, room)
        alloc += add
        room -= add
        rest -= int(add.sum())
    return alloc.astype(int)


def plan_stratified(
    closed: pd.DataFrame,
    budget: int,
    seed: int,
    stratum_col: str = RULE_ID,
    min_per_stratum: int = 5,
    prior_rates: pd.Series[Any] | None = None,
) -> SamplingPlan:
    rng = np.random.default_rng(seed)
    frame = _base_frame(closed, stratum_col)
    sizes = frame[STRATUM].value_counts()
    rename = _merge_small_strata(sizes, budget, min_per_stratum)
    if rename:
        frame[STRATUM] = frame[STRATUM].replace(rename)
        sizes = frame[STRATUM].value_counts()
    alloc = allocate_stratified(sizes, budget, min_per_stratum, prior_rates)
    frame[SELECTED] = False
    frame[INCLUSION_PROB] = 0.0
    for name, n_h in alloc.items():
        idx = np.flatnonzero((frame[STRATUM] == name).to_numpy())
        if len(idx) == 0:
            continue
        if n_h > 0:
            chosen = rng.choice(idx, size=int(n_h), replace=False)
            frame.loc[chosen, SELECTED] = True
        frame.loc[idx, INCLUSION_PROB] = n_h / len(idx)
    meta = {"merged_strata": len(rename)}
    return SamplingPlan("stratified", seed, budget, frame, meta)


def plan_active(
    closed: pd.DataFrame, budget: int, seed: int, stratum_col: str = RULE_ID, floor: float = 0.2
) -> SamplingPlan:
    if SCORE not in closed or closed[SCORE].isna().all():
        raise ValueError("Для схемы active нужна колонка score (оценка вероятности атаки от модели)")
    rng = np.random.default_rng(seed)
    frame = _base_frame(closed, stratum_col)
    scores = closed[SCORE].fillna(closed[SCORE].median()).to_numpy(dtype=float)
    pi = inclusion_probs(uncertainty(scores), budget, floor)
    frame[SCORE] = scores
    frame[INCLUSION_PROB] = pi
    frame[SELECTED] = poisson_sample(pi, rng)
    return SamplingPlan("active", seed, budget, frame, {"floor": floor})


def plan_naive_top(closed: pd.DataFrame, budget: int, seed: int, stratum_col: str = RULE_ID) -> SamplingPlan:
    """Только для исследования: самые «подозрительные» по score, без вероятностного дизайна."""
    if SCORE not in closed:
        raise ValueError("Для схемы naive_top нужна колонка score")
    frame = _base_frame(closed, stratum_col)
    frame[SCORE] = closed[SCORE].to_numpy(dtype=float)
    top = np.argsort(-frame[SCORE].to_numpy())[: min(budget, len(frame))]
    frame[SELECTED] = False
    frame.loc[top, SELECTED] = True
    frame[INCLUSION_PROB] = np.nan
    return SamplingPlan("naive_top", seed, budget, frame)


PlanFn = Callable[..., SamplingPlan]
SCHEMES: dict[str, PlanFn] = {
    "uniform": plan_uniform,
    "stratified": plan_stratified,
    "active": plan_active,
    "naive_top": plan_naive_top,
}


def make_plan(
    closed: pd.DataFrame,
    scheme: str,
    budget: int,
    seed: int,
    stratum_col: str = RULE_ID,
    min_per_stratum: int = 5,
    active_floor: float = 0.2,
) -> SamplingPlan:
    if scheme == "uniform":
        return plan_uniform(closed, budget, seed, stratum_col)
    if scheme == "stratified":
        return plan_stratified(closed, budget, seed, stratum_col, min_per_stratum)
    if scheme == "active":
        return plan_active(closed, budget, seed, stratum_col, active_floor)
    if scheme == "naive_top":
        return plan_naive_top(closed, budget, seed, stratum_col)
    raise ValueError(f"Неизвестная схема выборки: {scheme}")

"""Симуляция аудита на GUIDE: проверка корректности (H1) и экономии разметки (H2).

В каждом разбиении организаций: модель учится на обучающих организациях, на организациях аудита
закрывает долю инцидентов с наименьшей оценкой атаки, затем каждая схема аудита перепроверяет
выборку из закрытых. Истинные метки известны, поэтому видно, накрыла ли граница истинную FNR.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import numpy as np
import pandas as pd
from scipy import stats

from limen.audit.estimate import estimate_overall
from limen.audit.labels import attach_labels
from limen.config import AuditConfig
from limen.research.autocloser import close_lowest, predict_attack_proba, train_autocloser
from limen.research.config import ExperimentConfig
from limen.research.splits import org_splits
from limen.sampling.plans import make_plan
from limen.schema import ALERT_ID, LABEL, RULE_ID, SCORE

ScoreFn = Callable[[pd.DataFrame, pd.DataFrame, int], np.ndarray]


def _catboost_scores(cfg: ExperimentConfig) -> ScoreFn:
    def fn(train: pd.DataFrame, audit: pd.DataFrame, seed: int) -> np.ndarray:
        model = train_autocloser(train, cfg.autocloser, seed)
        return predict_attack_proba(model, audit)

    return fn


def _seed(*parts: int) -> int:
    return int(np.random.SeedSequence(list(parts)).generate_state(1)[0])


def roc_auc(scores: np.ndarray, y: np.ndarray) -> float:
    """ROC AUC через ранги (статистика Манна–Уитни); NaN, если в данных один класс."""
    pos = np.asarray(y) == 1
    n1, n0 = int(pos.sum()), int((~pos).sum())
    if n1 == 0 or n0 == 0:
        return float("nan")
    ranks = stats.rankdata(scores)
    return float((ranks[pos].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))


def audit_one_split(
    rep: int, audit: pd.DataFrame, scores: np.ndarray, cfg: ExperimentConfig
) -> list[dict[str, Any]]:
    """Все схемы, бюджеты и доли автозакрытия на одном разбиении."""
    a = cfg.audit
    est_cfg = AuditConfig(confidence=a.confidence)
    y_all = audit["y"].to_numpy()
    auc = roc_auc(scores, y_all)  # качество модели-«автозакрывателя» на организациях аудита
    rows: list[dict[str, Any]] = []
    for s_idx, share in enumerate(a.close_shares):
        closed_mask = close_lowest(scores, share)
        a_c, a_o = int(y_all[closed_mask].sum()), int(y_all[~closed_mask].sum())
        n_closed = int(closed_mask.sum())
        true_fnr = a_c / (a_c + a_o) if a_c + a_o else 0.0
        closed = pd.DataFrame(
            {
                ALERT_ID: audit.loc[closed_mask, "alert_id"].astype(str).to_numpy(),
                RULE_ID: audit.loc[closed_mask, a.stratum_column].astype(str).to_numpy(),
                SCORE: scores[closed_mask],
            }
        )
        truth = pd.Series(y_all[closed_mask], index=closed[ALERT_ID])
        for budget in a.budgets:
            for sc_idx, scheme in enumerate(a.schemes):
                plan = make_plan(
                    closed,
                    scheme,
                    budget,
                    _seed(cfg.split.seed, rep, s_idx, budget, sc_idx),
                    RULE_ID,
                    a.min_per_stratum,
                    a.active_floor,
                )
                ids = plan.selected_ids()
                labels = pd.DataFrame(
                    {ALERT_ID: ids, LABEL: np.where(truth.loc[ids].to_numpy() == 1, "attack", "benign")}
                )
                est = estimate_overall(plan, attach_labels(plan, labels), a_o, est_cfg)
                rows.append(
                    {
                        "rep": rep,
                        "close_share": share,
                        "budget": budget,
                        "scheme": scheme,
                        "n_closed": n_closed,
                        "model_auc": auc,
                        "n_labeled": est.n_sampled,
                        "attacks_closed_true": a_c,
                        "attacks_open": a_o,
                        "true_for": a_c / n_closed if n_closed else 0.0,
                        "true_fnr": true_fnr,
                        "for_point": est.for_point,
                        "for_upper": est.for_upper,
                        "fnr_upper": est.fnr_upper,
                        "violated": bool(true_fnr > est.fnr_upper + 1e-12),
                        "finite_sample_valid": est.finite_sample_valid,
                    }
                )
    return rows


def run_simulation(
    incidents: pd.DataFrame, cfg: ExperimentConfig, score_fn: ScoreFn | None = None
) -> pd.DataFrame:
    """Прогнать все разбиения. ``score_fn`` можно подменить (например, в тестах — без CatBoost)."""
    score_fn = score_fn or _catboost_scores(cfg)
    rows: list[dict[str, Any]] = []
    for rep, train_orgs, audit_orgs in org_splits(
        incidents["org"].to_numpy(), cfg.split.train_frac, cfg.split.n_reps, cfg.split.seed
    ):
        train = incidents.loc[incidents["org"].isin(train_orgs)]
        audit = incidents.loc[incidents["org"].isin(audit_orgs)].reset_index(drop=True)
        scores = score_fn(train, audit, _seed(cfg.split.seed, rep))
        rows.extend(audit_one_split(rep, audit, scores, cfg))
    return pd.DataFrame(rows)

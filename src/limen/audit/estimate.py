"""Оценка доли атак среди автозакрытых и доли пропущенных атак — по всему потоку и по правилам."""

from __future__ import annotations

from typing import Any

import pandas as pd

from limen.config import AuditConfig
from limen.io.validation import verdicts
from limen.sampling.plans import SamplingPlan
from limen.schema import (
    ALERT_ID,
    CLOSING_SOURCE,
    INCLUSION_PROB,
    RULE_ID,
    SCORE,
    SELECTED,
    STRATUM,
    ClosingSource,
    Verdict,
    Y,
)
from limen.stats.active import difference_estimate
from limen.stats.binomial import cp_lower, cp_upper, hypergeom_upper_count
from limen.stats.fnr import AuditEstimate, fnr_upper_from_count
from limen.stats.stratified import StratumCounts, korn_graubard_total_upper, union_total_upper


def _effective_sample(frame: pd.DataFrame, policy: str) -> pd.DataFrame:
    """Отобранные алерты с итоговой меткой: «не знаю» и неразмеченные — атака (as_attack) или исключение."""
    sel = frame.loc[frame[SELECTED]].copy()
    if policy == "as_attack":
        sel[Y] = sel[Y].fillna(1.0)
        return sel
    return sel.loc[sel[Y].notna()]


def estimate_overall(
    plan: SamplingPlan, labeled: pd.DataFrame, attacks_open: int, cfg: AuditConfig
) -> AuditEstimate:
    """Граница для всего множества автозакрытых алертов по схеме плана."""
    conf = cfg.confidence
    policy = cfg.estimation.unknown_label_policy
    n_closed = len(labeled)
    sample = _effective_sample(labeled, policy)
    n, k = len(sample), int(sample[Y].sum())
    scheme = plan.scheme

    if scheme == "uniform":
        if cfg.estimation.bound_method == "hypergeometric" and n_closed:
            upper_count = float(hypergeom_upper_count(k, n, n_closed, conf))
            method = "hypergeometric"
        else:
            upper_count = cp_upper(k, n, conf) * n_closed
            method = "clopper_pearson"
        point = k / n if n else float("nan")
        valid = True
    elif scheme == "stratified":
        strata = _strata_counts(labeled, sample)
        if cfg.estimation.stratified_method == "korn_graubard":
            upper_count = korn_graubard_total_upper(strata, conf)
            method, valid = "korn_graubard", False
        else:
            upper_count = union_total_upper(strata, conf, cfg.estimation.bound_method)
            method, valid = "union_bound", True
        est = sum(s.population * s.attacks / s.sampled for s in strata if s.sampled)
        point = est / n_closed if n_closed else float("nan")
    elif scheme == "active":
        selected = (
            labeled[SELECTED].to_numpy(dtype=bool) & labeled[ALERT_ID].isin(sample[ALERT_ID]).to_numpy()
        )
        y_sel = sample.set_index(ALERT_ID).loc[labeled.loc[selected, ALERT_ID], Y].to_numpy(dtype=float)
        de = difference_estimate(
            labeled[SCORE].to_numpy(dtype=float),
            labeled[INCLUSION_PROB].to_numpy(dtype=float),
            selected,
            y_sel,
            conf,
        )
        upper_count, point = de.upper, de.total / n_closed if n_closed else float("nan")
        method, valid = "active_inference_normal", False
    elif scheme == "naive_top":  # только для исследования: смещённая оценка
        upper_count = cp_upper(k, n, conf) * n_closed
        point = k / n if n else float("nan")
        method, valid = "naive_unweighted", False
    else:
        raise ValueError(f"Неизвестная схема: {scheme}")

    upper_count = min(float(n_closed), upper_count)
    return AuditEstimate(
        scope="all",
        scheme=scheme,
        method=method,
        confidence=conf,
        n_closed=n_closed,
        n_sampled=n,
        attacks_in_sample=k,
        attacks_open=attacks_open,
        for_point=point,
        for_upper=upper_count / n_closed if n_closed else 0.0,
        attacks_closed_upper=upper_count,
        fnr_upper=fnr_upper_from_count(upper_count, attacks_open),
        finite_sample_valid=valid,
    )


def _strata_counts(labeled: pd.DataFrame, sample: pd.DataFrame) -> list[StratumCounts]:
    pop = labeled.groupby(STRATUM).size()
    smp = sample.groupby(STRATUM)[Y].agg(["size", "sum"])
    out = []
    for name, n_pop in pop.items():
        n_h = int(smp.loc[name, "size"]) if name in smp.index else 0
        k_h = int(smp.loc[name, "sum"]) if name in smp.index else 0
        out.append(StratumCounts(str(name), int(n_pop), n_h, k_h))
    return out


def estimate_per_rule(
    closed: pd.DataFrame,
    plan: SamplingPlan,
    labeled: pd.DataFrame,
    attacks_open_by_rule: pd.Series[Any],
    cfg: AuditConfig,
) -> pd.DataFrame:
    """Границы по каждому правилу.

    * uniform, а также stratified со стратами-правилами: внутри правила при фиксированном n_h выборка
      простая случайная, граница Клоппера–Пирсона корректна (``srs_within_rule = True``);
    * stratified, если правило попало в несколько страт: граница через неравенство Буля по ячейкам
      «правило × страта» — корректна, но без нижней границы;
    * active: разностная оценка, гарантия приближённая.

    При ``simultaneous_rules`` уверенность поправляется по Бонферрони на число правил.
    """
    policy = cfg.estimation.unknown_label_policy
    frame = labeled.merge(closed[[ALERT_ID, RULE_ID]].astype({ALERT_ID: str}), on=ALERT_ID, how="left")
    rules = frame[RULE_ID].fillna("__no_rule__")
    n_rules = int(rules.nunique())
    conf = 1.0 - cfg.delta / n_rules if cfg.estimation.simultaneous_rules and n_rules else cfg.confidence

    rows = []
    for rule, part in frame.groupby(rules):
        n_pop = len(part)
        sample = _effective_sample(part, policy)
        n_h, k_h = len(sample), int(sample[Y].sum())
        if plan.scheme == "active" and n_h:
            sel = part[SELECTED].to_numpy(dtype=bool) & part[ALERT_ID].isin(sample[ALERT_ID]).to_numpy()
            y_sel = sample.set_index(ALERT_ID).loc[part.loc[sel, ALERT_ID], Y].to_numpy(dtype=float)
            de = difference_estimate(
                part[SCORE].to_numpy(dtype=float),
                part[INCLUSION_PROB].to_numpy(dtype=float),
                sel,
                y_sel,
                conf,
            )
            upper_count, point, lower = min(float(n_pop), de.upper), de.total / n_pop, float("nan")
            srs = False
        elif plan.scheme == "stratified" and part[STRATUM].nunique() > 1:
            cells = _strata_counts(part, sample)
            upper_count = union_total_upper(cells, conf, cfg.estimation.bound_method)
            point = sum(c.population * c.attacks / c.sampled for c in cells if c.sampled) / n_pop
            lower, srs = float("nan"), False
        else:
            upper_count = cp_upper(k_h, n_h, conf) * n_pop
            point = k_h / n_h if n_h else float("nan")
            lower = cp_lower(k_h, n_h, conf) if n_h else 0.0
            srs = plan.scheme != "active"
        a_open = int(attacks_open_by_rule.get(rule, 0))
        rows.append(
            {
                RULE_ID: rule,
                "n_closed": n_pop,
                "n_sampled": n_h,
                "attacks_in_sample": k_h,
                "for_point": point,
                "for_lower": lower,
                "for_upper": upper_count / n_pop if n_pop else 0.0,
                "attacks_closed_upper": upper_count,
                "attacks_open": a_open,
                "fnr_upper": fnr_upper_from_count(upper_count, a_open),
                "confidence": conf,
                "srs_within_rule": srs,
            }
        )
    out = pd.DataFrame(rows)
    return out.sort_values("n_closed", ascending=False).reset_index(drop=True) if len(out) else out


def attacks_open_counts(alerts: pd.DataFrame) -> tuple[int, pd.Series[Any]]:
    """A_O: атаки, найденные аналитиками (всего и по правилам)."""
    mask = (alerts[CLOSING_SOURCE] == ClosingSource.ANALYST.value) & (
        verdicts(alerts) == Verdict.ATTACK.value
    )
    by_rule = alerts.loc[mask].groupby(RULE_ID).size()
    return int(mask.sum()), by_rule.astype(int)

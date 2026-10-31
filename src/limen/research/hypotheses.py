"""Проверка гипотез по результатам симуляции.

H1 (корректность): для схем uniform, stratified, active доля разбиений, где истинная FNR выше 95%-й
верхней границы, меньше допуска (0,10). H0: доля нарушений ≥ допуска. Точный односторонний
биномиальный тест. Для naive_top проверяется обратное: нарушений больше допуска.

H2 (экономия разметки): при бюджете 300 медианная верхняя граница FNR у active хотя бы на 20% ниже,
чем у uniform. Парный критерий Уилкоксона для d = (1 − 0,20)·U_uniform − U_active > 0.

Смещение точечной оценки (дополнительно): для каждой схемы разность «оценка доли атак среди
автозакрытых − истинная доля» по разбиениям, двусторонний критерий Уилкоксона. У несмещённых схем
смещения быть не должно; у naive_top направление заранее не фиксируется.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from scipy import stats

from limen.research.config import HypothesesCfg

BIASED_SCHEMES = {"naive_top"}


def h1_table(results: pd.DataFrame, cfg: HypothesesCfg) -> pd.DataFrame:
    rows = []
    for (scheme, budget, share), g in results.groupby(["scheme", "budget", "close_share"]):
        reps, viol = len(g), int(g["violated"].sum())
        alternative = "greater" if scheme in BIASED_SCHEMES else "less"
        p = float(stats.binomtest(viol, reps, cfg.h1_tolerance, alternative=alternative).pvalue)
        if scheme in BIASED_SCHEMES:
            verdict = "смещение подтверждено" if p < cfg.alpha else "смещение не доказано"
        else:
            verdict = "H1 подтверждена" if p < cfg.alpha else "H1 не подтверждена"
        rows.append(
            {
                "scheme": scheme,
                "budget": budget,
                "close_share": share,
                "reps": reps,
                "violations": viol,
                "violation_rate": viol / reps if reps else np.nan,
                "p_value": p,
                "verdict": verdict,
                "median_fnr_upper": float(g["fnr_upper"].median()),
                "median_true_fnr": float(g["true_fnr"].median()),
            }
        )
    return pd.DataFrame(rows).sort_values(["close_share", "budget", "scheme"]).reset_index(drop=True)


def h2_test(results: pd.DataFrame, cfg: HypothesesCfg) -> list[dict[str, Any]]:
    out = []
    sub = results.loc[results["budget"] == cfg.h2_budget]
    for share, g in sub.groupby("close_share"):
        wide = g.pivot_table(index="rep", columns="scheme", values="fnr_upper", aggfunc="first")
        if cfg.h2_baseline not in wide or cfg.h2_candidate not in wide:
            continue
        base, cand = wide[cfg.h2_baseline], wide[cfg.h2_candidate]
        d = (1.0 - cfg.h2_reduction) * base - cand
        d = d.dropna()
        if len(d) < 2 or np.allclose(d, 0):
            p = float("nan")
        else:
            p = float(stats.wilcoxon(d, alternative="greater", zero_method="wilcox").pvalue)
        ratio = (cand / base.replace(0, np.nan)).median()
        out.append(
            {
                "close_share": share,
                "budget": cfg.h2_budget,
                "baseline": cfg.h2_baseline,
                "candidate": cfg.h2_candidate,
                "pairs": len(d),
                "median_ratio": float(ratio),
                "median_reduction": float(1.0 - ratio),
                "p_value": p,
                "verdict": "H2 подтверждена" if p < cfg.alpha else "H2 не подтверждена",
            }
        )
    return out


def bias_table(results: pd.DataFrame, cfg: HypothesesCfg) -> pd.DataFrame:
    """Смещение точечной оценки доли атак среди автозакрытых по каждой схеме, бюджету и доле автозакрытия."""
    rows = []
    for (scheme, budget, share), g in results.groupby(["scheme", "budget", "close_share"]):
        diff = (g["for_point"] - g["true_for"]).dropna()
        if len(diff) < 2 or np.allclose(diff, 0):
            p = float("nan")
        else:
            p = float(stats.wilcoxon(diff, alternative="two-sided", zero_method="wilcox").pvalue)
        median = float(diff.median()) if len(diff) else float("nan")
        if not p < cfg.alpha:
            verdict = "смещение не обнаружено"
        else:
            verdict = "смещение вверх" if median > 0 else "смещение вниз"
        rows.append(
            {
                "scheme": scheme,
                "budget": budget,
                "close_share": share,
                "reps": len(diff),
                "median_bias": median,
                "median_true_for": float(g["true_for"].median()),
                "p_value": p,
                "verdict": verdict,
            }
        )
    return pd.DataFrame(rows).sort_values(["close_share", "budget", "scheme"]).reset_index(drop=True)

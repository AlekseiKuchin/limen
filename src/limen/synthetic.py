"""Синтетическая выгрузка закрытых алертов — ТОЛЬКО для демо и тестов.

Данные полностью выдуманы генератором и не описывают ни одного реального SOC.
Формат совпадает с ``configs/mappings/generic_csv.yaml``. Истинные метки атак
сохраняются отдельно (truth), чтобы проверить, что границы аудита накрывают истинное значение.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class SyntheticSpec:
    n_alerts: int = 20_000
    n_rules: int = 40
    n_tenants: int = 5
    automated_rule_share: float = 0.6  # доля правил, где включено автозакрытие или подавление
    leaky_rules: int = 3  # правила, где автоматизация заметно теряет атаки
    seed: int = 7


def make_synthetic_export(spec: SyntheticSpec | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Вернуть (выгрузка в формате generic_csv, истинные метки alert_id → is_attack)."""
    s = spec or SyntheticSpec()
    rng = np.random.default_rng(s.seed)

    rules = pd.DataFrame({"rule_id": [f"R{i:03d}" for i in range(s.n_rules)]})
    rules["rule_name"] = [f"Синтетическое правило {i}" for i in range(s.n_rules)]
    rules["weight"] = rng.dirichlet(np.full(s.n_rules, 0.7))
    rules["attack_rate"] = np.clip(rng.lognormal(mean=np.log(0.01), sigma=0.9, size=s.n_rules), 0.0005, 0.2)
    rules["automated"] = rng.random(s.n_rules) < s.automated_rule_share
    leaky = rng.choice(
        np.flatnonzero(rules["automated"]),
        size=min(s.leaky_rules, int(rules["automated"].sum())),
        replace=False,
    )
    rules.loc[leaky, "attack_rate"] = rng.uniform(0.03, 0.08, size=len(leaky))
    rules["suppression"] = rules["automated"] & (rng.random(s.n_rules) < 0.3)

    idx = rng.choice(s.n_rules, size=s.n_alerts, p=rules["weight"].to_numpy())
    r = rules.iloc[idx].reset_index(drop=True)
    is_attack = rng.random(s.n_alerts) < r["attack_rate"].to_numpy()

    # оценка вендора: шумная, но связана с атакой
    logit = (
        np.log(r["attack_rate"] / (1 - r["attack_rate"])).to_numpy()
        + 2.5 * is_attack
        + rng.normal(0, 1.0, s.n_alerts)
    )
    score = 1.0 / (1.0 + np.exp(-logit))

    # автозакрытие: в автоматизированных правилах закрывается то, что модель считает неопасным
    auto = r["automated"].to_numpy() & (score < np.quantile(score, 0.85))
    closed_by = np.where(
        auto,
        np.where(
            r["suppression"].to_numpy(), "suppression", rng.choice(["ml_autoclose", "playbook"], s.n_alerts)
        ),
        "analyst",
    )
    resolution = np.where(
        closed_by == "analyst",
        np.where(is_attack, "true_positive", rng.choice(["false_positive", "benign_positive"], s.n_alerts)),
        "",
    )
    start = pd.Timestamp("2026-09-01", tz="UTC")
    closed_at = start + pd.to_timedelta(rng.integers(0, 30 * 24 * 3600, s.n_alerts), unit="s")

    export = pd.DataFrame(
        {
            "id": [f"A{i:07d}" for i in range(s.n_alerts)],
            "rule_id": r["rule_id"],
            "rule_name": r["rule_name"],
            "closed_at": closed_at.astype(str),
            "closing_reason": np.where(closed_by == "analyst", "manual", "auto"),
            "closed_by": closed_by,
            "resolution": resolution,
            "vendor_score": np.round(score, 4),
            "tenant": rng.choice([f"tenant{t}" for t in range(1, s.n_tenants + 1)], s.n_alerts),
            "user": [f"user{u}" for u in rng.integers(1, 2000, s.n_alerts)],
            "host": [f"ws-{h:04d}" for h in rng.integers(1, 800, s.n_alerts)],
            "src_ip": [f"10.{a}.{b}.{c}" for a, b, c in rng.integers(0, 255, (s.n_alerts, 3))],
        }
    )
    truth = pd.DataFrame({"alert_id": export["id"], "is_attack": is_attack.astype(int)})
    return export, truth

"""Только для демо на синтетике: заполнить шаблон разметки истинными метками вместо аналитика."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--template", type=Path, required=True)
    ap.add_argument("--truth", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    tpl = pd.read_csv(args.template, dtype=str, keep_default_na=False)
    truth = pd.read_csv(args.truth, dtype={"alert_id": str}).set_index("alert_id")["is_attack"]
    rng = np.random.default_rng(args.seed)
    tpl["label"] = np.where(tpl["alert_id"].map(truth).fillna(0).astype(int) == 1, "attack", "benign")
    tpl["analyst"] = "demo"
    tpl["seconds_spent"] = rng.integers(120, 900, len(tpl))  # имитация 2–15 минут на алерт
    args.out.parent.mkdir(parents=True, exist_ok=True)
    tpl.to_csv(args.out, index=False)
    print(f"Демо-метки: {args.out} ({len(tpl)} алертов)")


if __name__ == "__main__":
    main()

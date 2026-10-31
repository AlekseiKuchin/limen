"""Сгенерировать синтетическую выгрузку для демо.

python scripts/make_synthetic_export.py --out data/demo/export.csv --truth-out data/demo/truth.csv
"""

from __future__ import annotations

import argparse
from pathlib import Path

from limen.synthetic import SyntheticSpec, make_synthetic_export


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--truth-out", type=Path, required=True, help="Истинные метки (только для синтетики)")
    ap.add_argument("--n-alerts", type=int, default=20_000)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    export, truth = make_synthetic_export(SyntheticSpec(n_alerts=args.n_alerts, seed=args.seed))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    export.to_csv(args.out, index=False)
    truth.to_csv(args.truth_out, index=False)
    print(f"Синтетическая выгрузка: {args.out} ({len(export)} алертов); истинные метки: {args.truth_out}")


if __name__ == "__main__":
    main()

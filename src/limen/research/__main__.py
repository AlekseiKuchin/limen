"""Исследовательский CLI.

python -m limen.research prepare --config configs/experiments/guide_audit.yaml  # GUIDE → инциденты
python -m limen.research run --config configs/experiments/guide_smoke.yaml       # симуляция + гипотезы
python -m limen.research analyze --config ... --results reports/.../results.csv.gz
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pandas as pd

from limen.config import load_yaml
from limen.research.config import ExperimentConfig
from limen.research.guide import load_incidents
from limen.research.hypotheses import bias_table, h1_table, h2_test
from limen.research.simulate import run_simulation
from limen.research.tracking import Tracker


def _analyze(
    results: pd.DataFrame, cfg: ExperimentConfig, out_dir: Path
) -> tuple[pd.DataFrame, list[dict[str, Any]]]:
    h1 = h1_table(results, cfg.hypotheses)
    h2 = h2_test(results, cfg.hypotheses)
    h1.to_csv(out_dir / "h1_validity.csv", index=False)
    bias_table(results, cfg.hypotheses).to_csv(out_dir / "bias.csv", index=False)
    (out_dir / "h2_efficiency.json").write_text(
        json.dumps(h2, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return h1, h2


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="python -m limen.research",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("prepare", "run", "analyze"):
        p = sub.add_parser(name)
        p.add_argument("--config", type=Path, required=True)
        if name == "prepare":
            p.add_argument("--rebuild", action="store_true")
        if name == "analyze":
            p.add_argument("--results", type=Path, required=True)
    args = ap.parse_args()

    cfg = load_yaml(args.config, ExperimentConfig)
    out_dir = cfg.output.dir
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.cmd == "prepare":
        inc = load_incidents(cfg.data, rebuild=args.rebuild)
        print(f"Инцидентов: {len(inc)}, организаций: {inc['org'].nunique()}, доля TP: {inc['y'].mean():.3f}")
        return
    if args.cmd == "analyze":
        _, h2 = _analyze(pd.read_csv(args.results), cfg, out_dir)
        print(json.dumps(h2, ensure_ascii=False, indent=2))
        return

    tracker = Tracker(cfg.tracking.experiment)
    with tracker.run(args.config.stem):
        tracker.log_params({"config": args.config.name, **cfg.split.model_dump(), **cfg.audit.model_dump()})
        incidents = load_incidents(cfg.data)
        results = run_simulation(incidents, cfg)
        res_path = out_dir / "results.csv.gz"
        results.to_csv(res_path, index=False)
        h1, _ = _analyze(results, cfg, out_dir)
        for row in h1.itertuples(index=False):
            key = f"viol_{row.scheme}_b{row.budget}_s{int(float(row.close_share) * 100)}"
            tracker.log_metrics({key: float(row.violation_rate)})
        for path in (
            res_path,
            out_dir / "h1_validity.csv",
            out_dir / "h2_efficiency.json",
            out_dir / "bias.csv",
        ):
            tracker.log_artifact(path)
    print(f"Готово: {out_dir}")


if __name__ == "__main__":
    main()

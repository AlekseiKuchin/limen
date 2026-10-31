"""Командная строка: сквозной сценарий строгого и основного режимов, контроль целостности."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from limen.cli import EXIT_BLOCKED, EXIT_INPUT, EXIT_INTEGRITY, EXIT_OK, main

ROOT = Path(__file__).resolve().parents[1]
MAPPING = str(ROOT / "configs" / "mappings" / "generic_csv.yaml")
CONFIG = str(ROOT / "configs" / "audit.example.yaml")


def _label_from_truth(template: Path, truth: pd.Series, out: Path) -> Path:
    t = pd.read_csv(template, dtype=str, keep_default_na=False)
    t["label"] = ["attack" if truth.get(i, 0) == 1 else "benign" for i in t["alert_id"]]
    t.to_csv(out, index=False)
    return out


def test_bound_and_sample_size(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["bound", "--n", "300", "--k", "0", "--population", "12400", "--attacks-open", "400"]) == 0
    out = capsys.readouterr().out
    assert "0.9936%" in out and ": 121" in out and "23.2246%" in out
    assert main(["sample-size", "--target", "0.02"]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["n_required"] == 149
    assert main(["config-hash", CONFIG]) == EXIT_OK
    assert len(capsys.readouterr().out.strip()) == 64


def test_strict_mode_flow(tmp_path: Path, export_csv: Path, truth: pd.Series) -> None:
    key, log = tmp_path / "k.key", tmp_path / "audit.jsonl"
    alerts, plan, tpl = tmp_path / "alerts.csv", tmp_path / "plan.csv", tmp_path / "tpl.csv"
    page, result = tmp_path / "labeling.html", tmp_path / "result.json"
    common = ["--audit-log", str(log)]
    assert main(["keygen", "--out", str(key), *common]) == EXIT_OK
    assert main(["validate", str(export_csv), "--mapping", MAPPING, *common]) == EXIT_OK
    assert (
        main(["prepare", str(export_csv), "--mapping", MAPPING, "--key", str(key), "--out", str(alerts)]) == 0
    )
    args = ["plan", str(alerts), "--config", CONFIG, "--out", str(plan), "--template-out", str(tpl)]
    assert main([*args, "--page-out", str(page), *common]) == EXIT_OK
    assert "Content-Security-Policy" in page.read_text(encoding="utf-8")

    labels = _label_from_truth(tpl, truth, tmp_path / "labels.csv")
    est = ["--plan", str(plan), "--labels", str(labels), "--config", CONFIG]
    assert main(["estimate", str(alerts), *est, "--out", str(result), *common]) == EXIT_OK
    saved = json.loads(result.read_text(encoding="utf-8"))
    assert set(saved["inputs"]) == {"alerts_sha256", "plan_sha256", "labels_sha256", "config_sha256"}

    assert main(["verify", str(result), "--alerts", str(alerts), *est, *common]) == EXIT_OK
    for fmt in ("md", "html"):
        assert main(["report", str(result), "--format", fmt, "--out", str(tmp_path / f"r.{fmt}")]) == 0
    prom = tmp_path / "limen.prom"
    assert main(["metrics", str(result), "--out", str(prom)]) == EXIT_OK
    assert 'limen_fnr_upper{audit="result"}' in prom.read_text(encoding="utf-8")

    events = [json.loads(line)["action"] for line in log.read_text(encoding="utf-8").splitlines()]
    assert events == ["keygen", "validate", "plan", "estimate", "verify"]


def test_integrity_violations_stop_the_audit(tmp_path: Path, export_csv: Path, truth: pd.Series) -> None:
    key, alerts, plan, tpl = tmp_path / "k", tmp_path / "a.csv", tmp_path / "p.csv", tmp_path / "t.csv"
    main(["keygen", "--out", str(key)])
    main(["prepare", str(export_csv), "--mapping", MAPPING, "--key", str(key), "--out", str(alerts)])
    main(["plan", str(alerts), "--config", CONFIG, "--out", str(plan), "--template-out", str(tpl)])
    labels = _label_from_truth(tpl, truth, tmp_path / "l.csv")
    result = tmp_path / "r.json"
    est = ["--plan", str(plan), "--labels", str(labels), "--config", CONFIG]
    assert main(["estimate", str(alerts), *est, "--out", str(result)]) == EXIT_OK

    # подмена таблицы алертов после построения плана
    tampered = tmp_path / "a2.csv"
    df = pd.read_csv(alerts, dtype=str, keep_default_na=False)
    df.loc[0, "verdict"] = "attack"
    df.to_csv(tampered, index=False)
    assert main(["estimate", str(tampered), *est, "--out", str(tmp_path / "x.json")]) == EXIT_INTEGRITY

    # подмена меток после расчёта
    lab = pd.read_csv(labels, dtype=str, keep_default_na=False)
    lab.loc[0, "label"] = "benign" if lab.loc[0, "label"] == "attack" else "attack"
    lab.to_csv(labels, index=False)
    assert main(["verify", str(result), "--alerts", str(alerts), *est]) == EXIT_INTEGRITY

    # другая конфигурация без явного разрешения
    other = tmp_path / "other.yaml"
    other.write_text("confidence: 0.9\n", encoding="utf-8")
    est_other = ["--plan", str(plan), "--labels", str(labels), "--config", str(other)]
    assert main(["estimate", str(alerts), *est_other, "--out", str(tmp_path / "y.json")]) == EXIT_INTEGRITY
    out = tmp_path / "z.json"
    assert main(["estimate", str(alerts), *est_other, "--out", str(out), "--allow-config-change"]) == 0


def test_main_delivery_mode(tmp_path: Path, export_csv: Path, truth: pd.Series) -> None:
    key, alerts = tmp_path / "k", tmp_path / "alerts.csv"
    main(["keygen", "--out", str(key)])
    main(["prepare", str(export_csv), "--mapping", MAPPING, "--key", str(key), "--out", str(alerts)])
    minimal = tmp_path / "outbox" / "minimal.csv"
    assert main(["export-minimal", str(alerts), "--key", str(key), "--out", str(minimal)]) == EXIT_OK
    cols = set(pd.read_csv(minimal).columns)
    assert not {"user", "src_ip", "user_id", "host_id", "ip_id", "rule_name", "tenant"} & cols

    # исполнитель: план и шаблон по минимальной таблице
    plan, tpl = tmp_path / "outbox" / "plan.csv", tmp_path / "outbox" / "tpl.csv"
    main(["plan", str(minimal), "--config", CONFIG, "--out", str(plan), "--template-out", str(tpl)])
    # заказчик: перевод в исходные ID, разметка, перевод обратно
    local = tmp_path / "local.csv"
    tr = ["--alerts", str(alerts), "--key", str(key)]
    assert main(["translate-ids", str(tpl), *tr, "--to", "original", "--out", str(local)]) == EXIT_OK
    _label_from_truth(local, truth, local)
    back = tmp_path / "outbox" / "labels.csv"
    assert main(["translate-ids", str(local), *tr, "--to", "pseudonym", "--out", str(back)]) == EXIT_OK
    # исполнитель: расчёт по минимальной таблице
    result = tmp_path / "outbox" / "result.json"
    est = ["--plan", str(plan), "--labels", str(back), "--config", CONFIG]
    assert main(["estimate", str(minimal), *est, "--out", str(result)]) == EXIT_OK
    assert json.loads(result.read_text(encoding="utf-8"))["overall"]["attacks_open"] > 0


def test_errors_have_distinct_exit_codes(tmp_path: Path, export_csv: Path) -> None:
    assert main(["validate", str(tmp_path / "missing.csv"), "--mapping", MAPPING]) == EXIT_INPUT
    df = pd.read_csv(export_csv, dtype=str, keep_default_na=False)
    df["closed_by"] = "somebody"
    blocked = tmp_path / "blocked.csv"
    df.to_csv(blocked, index=False)
    assert main(["validate", str(blocked), "--mapping", MAPPING]) == EXIT_BLOCKED
    with pytest.raises(SystemExit):
        main(["plan"])  # argparse: обязательный аргумент не задан

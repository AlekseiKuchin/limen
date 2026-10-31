from __future__ import annotations

from pathlib import Path

import pandas as pd

from limen.audit.pipeline import AuditResult
from limen.monitoring.metrics import render_metrics, write_metrics
from limen.stats.fnr import AuditEstimate


def _result() -> AuditResult:
    overall = AuditEstimate(
        "all", "uniform", "clopper_pearson", 0.95, 1000, 300, 0, 40, 0.0, 0.0099, 9.9, 0.198, True
    )
    per_rule = pd.DataFrame({"rule_id": ['R"1\\x'], "for_upper": [0.02], "decision": ["insufficient"]})
    return AuditResult(overall, per_rule, {}, {}, created_at="2026-10-30T12:00:00+00:00")


def test_prometheus_text_format(tmp_path: Path) -> None:
    text = render_metrics([("pilot-1", _result())])
    lines = text.splitlines()
    assert "# TYPE limen_fnr_upper gauge" in lines
    assert 'limen_fnr_upper{audit="pilot-1"} 0.198' in lines
    assert 'limen_rule_for_upper{audit="pilot-1",rule_id="R\\"1\\\\x"} 0.02' in lines
    assert any(line.startswith("limen_rule_decision{") and line.endswith(" 1") for line in lines)
    assert 'limen_audit_timestamp_seconds{audit="pilot-1"} 1793361600.0' in lines
    p = write_metrics(tmp_path / "textfile" / "limen.prom", text)
    assert p.read_text(encoding="utf-8") == text
    assert not list(p.parent.glob(".limen-*"))  # временные файлы не остаются

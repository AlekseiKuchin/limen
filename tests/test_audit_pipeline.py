from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from limen.audit.labels import read_labels, write_label_template
from limen.audit.pipeline import MINIMAL_COLUMNS, AuditResult, build_plan, evaluate, minimal_export, prepare
from limen.audit.recommend import Decision, decide, decide_from_upper
from limen.config import AuditConfig, EstimationConfig, SamplingConfig
from limen.privacy.pseudonymize import load_key, translate_alert_ids
from limen.report.render import render
from limen.schema import ALERT_ID, LABEL


def _labels_from_truth(plan_ids: list[str], truth: pd.Series) -> pd.DataFrame:
    y = truth.reindex(plan_ids).fillna(0).astype(int).to_numpy()
    return pd.DataFrame(
        {ALERT_ID: plan_ids, LABEL: np.where(y == 1, "attack", "benign"), "seconds_spent": 300}
    )


@pytest.mark.parametrize("scheme", ["uniform", "stratified", "active"])
def test_end_to_end(scheme: str, export_csv: Path, mapping, key_file: Path, truth: pd.Series) -> None:  # type: ignore[no-untyped-def]
    cfg = AuditConfig(sampling=SamplingConfig(scheme=scheme, budget=400, min_per_stratum=3))
    alerts, rep, _ = prepare(export_csv, mapping, load_key(key_file), cfg)
    assert rep.ok
    plan = build_plan(alerts, cfg)
    result = evaluate(alerts, plan, _labels_from_truth(plan.selected_ids(), truth), cfg, rep)
    o = result.overall
    assert 0.0 <= o.for_upper <= 1.0 and 0.0 <= o.fnr_upper <= 1.0
    assert o.n_closed == plan.frame.shape[0]
    assert {"decision", "decision_ru", "extra_sample_needed"} <= set(result.per_rule.columns)
    assert o.finite_sample_valid is (scheme != "active")


def test_result_roundtrip_and_report(
    tmp_path: Path, export_csv: Path, mapping, key_file: Path, truth: pd.Series
) -> None:  # type: ignore[no-untyped-def]
    cfg = AuditConfig(estimation=EstimationConfig(simultaneous_rules=True))
    alerts, rep, _ = prepare(export_csv, mapping, load_key(key_file), cfg)
    plan = build_plan(alerts, cfg)
    result = evaluate(alerts, plan, _labels_from_truth(plan.selected_ids(), truth), cfg, rep)
    path = result.save(tmp_path / "result.json")
    back = AuditResult.load(path)
    assert back.overall == result.overall
    md = render(back, "md")
    html = render(back, "html")
    assert "Верхняя граница доли пропущенных атак" in md
    assert "<table>" in html


def test_unknown_labels_are_conservative(export_csv: Path, mapping, key_file: Path) -> None:  # type: ignore[no-untyped-def]
    cfg = AuditConfig()
    alerts, _rep, _ = prepare(export_csv, mapping, load_key(key_file), cfg)
    plan = build_plan(alerts, cfg)
    ids = plan.selected_ids()
    benign = pd.DataFrame({ALERT_ID: ids, LABEL: "benign"})
    unknown = pd.DataFrame({ALERT_ID: ids, LABEL: "unknown"})
    u_benign = evaluate(alerts, plan, benign, cfg).overall.for_upper
    u_unknown = evaluate(alerts, plan, unknown, cfg).overall.for_upper
    assert u_unknown > u_benign


def test_decisions() -> None:
    assert decide(299, 0, 0.01, 0.95)[0] is Decision.SAFE
    assert decide(100, 20, 0.01, 0.95)[0] is Decision.LEAKS
    d, extra = decide(50, 0, 0.01, 0.95)
    assert d is Decision.INSUFFICIENT and extra == 299 - 50
    assert decide(0, 0, 0.01, 0.95)[0] is Decision.INSUFFICIENT
    assert decide(300, 2, 0.01, 0.95)[0] is Decision.UNCERTAIN


def test_main_delivery_mode_matches_full_data(
    tmp_path: Path, export_csv: Path, mapping, key_file: Path, truth: pd.Series
) -> None:  # type: ignore[no-untyped-def]
    """Основной режим: наружу уходит минимальная таблица с псевдонимами, итог тот же, что внутри контура."""
    cfg = AuditConfig()
    key = load_key(key_file)
    alerts, rep, _ = prepare(export_csv, mapping, key, cfg)
    minimal = minimal_export(alerts, key)
    assert set(minimal.columns) <= set(MINIMAL_COLUMNS)
    assert not {"user", "host", "src_ip", "user_id", "host_id", "ip_id", "rule_name", "tenant"} & set(
        minimal.columns
    )
    assert not set(minimal[ALERT_ID]) & set(alerts[ALERT_ID])

    # исполнитель: план и шаблон по минимальной таблице
    plan_out = build_plan(minimal, cfg)
    tpl_path = write_label_template(plan_out, minimal, tmp_path / "template.csv")
    # заказчик: перевод в исходные ID, разметка, перевод обратно
    tpl = pd.read_csv(tpl_path, dtype=str, keep_default_na=False)
    local = translate_alert_ids(tpl, alerts[ALERT_ID], key, to="original")
    labeled = _labels_from_truth(local[ALERT_ID].tolist(), truth)
    back = translate_alert_ids(labeled, alerts[ALERT_ID], key, to="pseudonym")
    # исполнитель: оценка по минимальной таблице
    outside = evaluate(minimal, plan_out, back, cfg).overall

    plan_in = build_plan(alerts, cfg)  # тот же порядок строк и зерно → те же алерты
    inside = evaluate(alerts, plan_in, _labels_from_truth(plan_in.selected_ids(), truth), cfg, rep).overall
    assert outside.n_sampled == inside.n_sampled
    assert outside.attacks_in_sample == inside.attacks_in_sample
    assert outside.attacks_open == inside.attacks_open > 0
    assert outside.fnr_upper == pytest.approx(inside.fnr_upper)


def test_label_template_neutralizes_formulas(
    tmp_path: Path, export_csv: Path, mapping, key_file: Path
) -> None:  # type: ignore[no-untyped-def]
    cfg = AuditConfig()
    alerts, _rep, _ = prepare(export_csv, mapping, load_key(key_file), cfg)
    alerts["rule_name"] = '=HYPERLINK("http://example.invalid","x")'
    plan = build_plan(alerts, cfg)
    tpl = pd.read_csv(
        write_label_template(plan, alerts, tmp_path / "t.csv"), dtype=str, keep_default_na=False
    )
    assert tpl["rule_name"].str.startswith("'=").all()
    assert tpl[ALERT_ID].tolist() == plan.selected_ids()


def test_active_decisions_use_only_upper_bound() -> None:
    assert decide_from_upper(40, 0, 0.004, 0.01) == (Decision.SAFE, 0)
    assert decide_from_upper(40, 0, 0.03, 0.01) == (Decision.INSUFFICIENT, -1)
    assert decide_from_upper(40, 9, 0.5, 0.01) == (Decision.UNCERTAIN, -1)  # «теряет атаки» не объявляется
    assert decide_from_upper(0, 0, 1.0, 0.01) == (Decision.INSUFFICIENT, -1)


def test_per_rule_bounds_when_strata_are_not_rules(
    export_csv: Path, mapping, key_file: Path, truth: pd.Series
) -> None:  # type: ignore[no-untyped-def]
    """Страты — клиенты MSSP: правило попадает в несколько страт, граница по правилу — через ячейки."""
    cfg = AuditConfig(sampling=SamplingConfig(scheme="stratified", stratum_column="tenant", budget=400))
    alerts, rep, _ = prepare(export_csv, mapping, load_key(key_file), cfg)
    plan = build_plan(alerts, cfg)
    per_rule = evaluate(alerts, plan, _labels_from_truth(plan.selected_ids(), truth), cfg, rep).per_rule
    multi = per_rule.loc[~per_rule["srs_within_rule"]]
    assert len(multi) > 0
    assert (multi["decision"] != "leaks").all()  # без корректной нижней границы «теряет атаки» не объявляется
    assert (multi["for_upper"] >= multi["for_point"].fillna(0)).all()

    by_rule = AuditConfig(sampling=SamplingConfig(scheme="stratified", budget=400))
    plan_r = build_plan(alerts, by_rule)
    res_r = evaluate(alerts, plan_r, _labels_from_truth(plan_r.selected_ids(), truth), by_rule, rep)
    assert res_r.per_rule["srs_within_rule"].all()


def test_attack_techniques_are_counted(tmp_path: Path, export_csv: Path, mapping, key_file: Path) -> None:  # type: ignore[no-untyped-def]
    cfg = AuditConfig()
    alerts, rep, _ = prepare(export_csv, mapping, load_key(key_file), cfg)
    plan = build_plan(alerts, cfg, alerts_sha256="0" * 64)
    assert plan.meta["alerts_sha256"] == "0" * 64 and len(plan.meta["config_sha256"]) == 64
    ids = plan.selected_ids()
    path = tmp_path / "labels.csv"
    pd.DataFrame(
        {
            ALERT_ID: ids[:3],
            LABEL: ["attack", "attack", "benign"],
            "attack_technique": ["t1078", "T1059.001", ""],
        }
    ).to_csv(path, index=False)
    result = evaluate(alerts, plan, read_labels(path), cfg, rep)
    assert result.labeling["attack_techniques"] == {"T1059.001": 1, "T1078": 1}

    pd.DataFrame({ALERT_ID: ids[:1], LABEL: ["attack"], "attack_technique": ["1078"]}).to_csv(
        path, index=False
    )
    with pytest.raises(ValueError, match="ATT&CK"):
        read_labels(path)

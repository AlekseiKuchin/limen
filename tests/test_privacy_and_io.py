from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from limen.io.loaders import load_export
from limen.io.validation import AuditBlockedError, validate
from limen.privacy.pseudonymize import (
    generate_key,
    load_key,
    pseudonym,
    pseudonymize_frame,
    translate_alert_ids,
)
from limen.schema import CLOSING_SOURCE, VERDICT, ClosingSource


def test_pseudonym_is_deterministic_and_key_dependent(tmp_path: Path) -> None:
    k1 = load_key(generate_key(tmp_path / "k1"))
    k2 = load_key(generate_key(tmp_path / "k2"))
    assert pseudonym("ivanov", k1, "user") == pseudonym("ivanov", k1, "user")
    assert pseudonym("ivanov", k1, "user") != pseudonym("ivanov", k2, "user")
    assert pseudonym("ivanov", k1, "user").startswith("user_")


def test_short_key_rejected(tmp_path: Path) -> None:
    p = tmp_path / "short.key"
    p.write_bytes(b"123")
    with pytest.raises(ValueError):
        load_key(p)


def test_existing_key_not_overwritten(tmp_path: Path) -> None:
    p = generate_key(tmp_path / "k")
    with pytest.raises(FileExistsError):
        generate_key(p)


def test_pseudonymize_drops_raw_columns(export_csv: Path, mapping, key_file: Path) -> None:  # type: ignore[no-untyped-def]
    df = load_export(export_csv, mapping)
    out, table = pseudonymize_frame(df, mapping.entities, load_key(key_file), keep_mapping=True)
    for raw in mapping.entities:
        assert raw not in out.columns
    assert {"user_id", "host_id", "ip_id"} <= set(out.columns)
    assert table is not None and set(table.columns) == {"column", "original", "pseudonym"}


def test_mapping_derives_sources_and_verdicts(export_csv: Path, mapping) -> None:  # type: ignore[no-untyped-def]
    df = load_export(export_csv, mapping)
    assert set(df[CLOSING_SOURCE]) <= {s.value for s in ClosingSource}
    assert (df.loc[df[CLOSING_SOURCE] == "analyst", VERDICT] != "unknown").all()
    rep = validate(df, (ClosingSource.AUTO, ClosingSource.SUPPRESSION))
    assert rep.ok and rep.attacks_found_by_analysts > 0


def test_validation_blocks_when_source_unknown(export_csv: Path, mapping) -> None:  # type: ignore[no-untyped-def]
    df = load_export(export_csv, mapping)
    df[CLOSING_SOURCE] = ClosingSource.UNKNOWN.value
    rep = validate(df, (ClosingSource.AUTO,))
    assert not rep.ok
    with pytest.raises(AuditBlockedError):
        rep.raise_if_blocked()


def test_missing_closing_source_field_raises(tmp_path: Path, mapping) -> None:  # type: ignore[no-untyped-def]
    p = tmp_path / "bad.csv"
    pd.DataFrame(
        {
            "id": ["1"],
            "rule_id": ["r"],
            "rule_name": ["x"],
            "closed_at": ["2026-01-01"],
            "closing_reason": ["a"],
            "vendor_score": ["0.1"],
            "tenant": ["t"],
        }
    ).to_csv(p, index=False)
    with pytest.raises(KeyError):
        load_export(p, mapping)


def test_alert_ids_translate_both_ways(tmp_path: Path) -> None:
    key = load_key(generate_key(tmp_path / "k"))
    ids = [f"A{i}" for i in range(50)]
    labels = pd.DataFrame({"alert_id": ids[:5], "label": "benign"})
    hidden = translate_alert_ids(labels, ids, key, to="pseudonym")
    assert hidden["alert_id"].str.startswith("alert_").all()
    assert not set(hidden["alert_id"]) & set(ids)
    back = translate_alert_ids(hidden, ids, key, to="original")
    assert back["alert_id"].tolist() == ids[:5]


def test_translate_rejects_foreign_ids(tmp_path: Path) -> None:
    key = load_key(generate_key(tmp_path / "k"))
    other = load_key(generate_key(tmp_path / "other"))
    hidden = translate_alert_ids(pd.DataFrame({"alert_id": ["A1"]}), ["A1"], other, to="pseudonym")
    with pytest.raises(KeyError):
        translate_alert_ids(hidden, ["A1"], key, to="original")  # чужой ключ


def test_validation_without_verdict_column(export_csv: Path, mapping) -> None:  # type: ignore[no-untyped-def]
    df = load_export(export_csv, mapping).drop(columns=[VERDICT])
    rep = validate(df, (ClosingSource.AUTO, ClosingSource.SUPPRESSION))
    assert rep.ok and rep.attacks_found_by_analysts == 0
    assert any("FNR" in w for w in rep.warnings)

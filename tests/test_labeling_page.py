"""Офлайн-страница разметки: CSP по хешам, данные как текст, служебные поля скрыты."""

from __future__ import annotations

import base64
import hashlib
import json
import re

import pandas as pd

from limen.report.labeling import render_labeling_page


def _template() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "alert_id": ["A1", "A2"],
            "rule_id": ["R1", "R2"],
            "rule_name": ["</script><script>alert(1)</script>", "'=HYPERLINK(1)"],
            "label": ["", ""],
            "analyst": ["", ""],
            "attack_technique": ["", ""],
        }
    )


def _hash(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode() + "'"


def test_csp_allows_only_embedded_script_and_style() -> None:
    html = render_labeling_page(_template())
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html)
    assert csp is not None
    policy = csp.group(1).replace("&#39;", "'")
    assert "default-src 'none'" in policy and "connect-src 'none'" in policy
    scripts = re.findall(r"<script>(.*?)</script>", html, flags=re.S)
    styles = re.findall(r"<style>(.*?)</style>", html, flags=re.S)
    assert len(scripts) == 1 and len(styles) == 1
    assert _hash(scripts[0]) in policy and _hash(styles[0]) in policy


def test_alert_data_cannot_break_out_of_the_data_block() -> None:
    html = render_labeling_page(_template())
    block = re.search(r'<script type="application/json" id="limen-data">(.*?)</script>', html, flags=re.S)
    assert block is not None
    assert "<" not in block.group(1)  # «</script>» из данных экранирован как \\u003c
    data = json.loads(block.group(1))
    assert [r["alert_id"] for r in data["rows"]] == ["A1", "A2"]
    context = data["rows"][0]["context"]
    assert context["rule_name"].startswith("</script>")
    assert "label" not in context and "analyst" not in context and "attack_technique" not in context

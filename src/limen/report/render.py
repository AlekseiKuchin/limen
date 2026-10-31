"""Формирование отчёта аудита для руководителя SOC, клиента MSSP или комиссии."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Literal

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from limen.audit.pipeline import AuditResult

ReportFormat = Literal["md", "html"]


def _pct(value: Any, digits: int = 2) -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "—"
    if math.isnan(v):
        return "—"
    return f"{v * 100:.{digits}f}%".replace(".", ",")


def _num(value: Any, digits: int = 0) -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "—"
    if math.isnan(v):
        return "—"
    return f"{v:,.{digits}f}".replace(",", " ").replace(".", ",")


def environment() -> Environment:
    env = Environment(
        loader=PackageLoader("limen.report", "templates"),
        # HTML экранируется, Markdown — нет
        autoescape=select_autoescape(enabled_extensions=("html.j2",), default_for_string=False),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["pct"] = _pct
    env.filters["num"] = _num
    return env


def render(result: AuditResult, fmt: ReportFormat = "md") -> str:
    data = result.to_dict()
    template = environment().get_template(f"report.{fmt}.j2")
    return str(template.render(r=data, o=data["overall"], rules=data["per_rule"], cfg=data["config"]))


def write_report(result: AuditResult, path: str | Path, fmt: ReportFormat = "md") -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render(result, fmt), encoding="utf-8")
    return p

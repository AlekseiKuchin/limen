"""Экспорт итогов аудита в текстовом формате Prometheus.

«Лимен» не открывает портов и не ходит в сеть: метрики пишутся в файл ``*.prom``, который читает
textfile collector node_exporter на той же машине. Дальше — Prometheus, Grafana и Alertmanager
заказчика (примеры правил и панели — в deploy/monitoring/).
"""

from __future__ import annotations

import math
import os
import tempfile
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from limen.audit.pipeline import AuditResult

_HELP: dict[str, str] = {
    "limen_audit_timestamp_seconds": "Время расчёта аудита (Unix time)",
    "limen_for_upper": "Верхняя граница доли атак среди автозакрытых алертов",
    "limen_fnr_upper": "Верхняя граница доли пропущенных атак (FNR)",
    "limen_closed": "Алертов, закрытых без аналитика, в периоде аудита",
    "limen_sampled": "Перепроверено алертов",
    "limen_attacks_in_sample": "Атак найдено в выборке",
    "limen_attacks_open": "Атак, найденных аналитиками в остальном потоке",
    "limen_finite_sample_valid": "1 — гарантия на конечной выборке, 0 — приближённая",
    "limen_rule_for_upper": "Верхняя граница доли атак среди автозакрытых по правилу",
    "limen_rule_decision": "Решение по правилу (значение 1 у текущего решения)",
}


def _escape(value: str) -> str:
    """Экранирование значения метки: обратная косая черта, перевод строки и кавычка."""
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _escape_help(value: str) -> str:
    """В строке HELP экранируются только обратная косая черта и перевод строки."""
    return value.replace("\\", "\\\\").replace("\n", "\\n")


def _labels(**kv: str) -> str:
    return "{" + ",".join(f'{k}="{_escape(v)}"' for k, v in kv.items()) + "}"


def _num(value: float) -> str:
    if math.isnan(value):
        return "NaN"
    return repr(float(value))


def _timestamp(created_at: str) -> float:
    return datetime.fromisoformat(created_at).timestamp()


def render_metrics(results: Iterable[tuple[str, AuditResult]]) -> str:
    """Текст в формате Prometheus для одного или нескольких аудитов; имя аудита — метка ``audit``."""
    samples: dict[str, list[str]] = {name: [] for name in _HELP}
    for audit, r in results:
        o = r.overall
        base = {"audit": audit}
        samples["limen_audit_timestamp_seconds"].append(f"{_labels(**base)} {_num(_timestamp(r.created_at))}")
        samples["limen_for_upper"].append(f"{_labels(**base)} {_num(o.for_upper)}")
        samples["limen_fnr_upper"].append(f"{_labels(**base)} {_num(o.fnr_upper)}")
        samples["limen_closed"].append(f"{_labels(**base)} {_num(o.n_closed)}")
        samples["limen_sampled"].append(f"{_labels(**base)} {_num(o.n_sampled)}")
        samples["limen_attacks_in_sample"].append(f"{_labels(**base)} {_num(o.attacks_in_sample)}")
        samples["limen_attacks_open"].append(f"{_labels(**base)} {_num(o.attacks_open)}")
        samples["limen_finite_sample_valid"].append(f"{_labels(**base)} {_num(int(o.finite_sample_valid))}")
        for row in r.per_rule.to_dict(orient="records"):
            rule = {"audit": audit, "rule_id": str(row["rule_id"])}
            samples["limen_rule_for_upper"].append(f"{_labels(**rule)} {_num(float(row['for_upper']))}")
            if "decision" in row:
                decision = {**rule, "decision": str(row["decision"])}
                samples["limen_rule_decision"].append(f"{_labels(**decision)} 1")
    lines: list[str] = []
    for name, help_text in _HELP.items():
        if not samples[name]:
            continue
        lines.append(f"# HELP {name} {_escape_help(help_text)}")
        lines.append(f"# TYPE {name} gauge")
        lines.extend(f"{name}{sample}" for sample in samples[name])
    return "\n".join(lines) + "\n"


def write_metrics(path: str | Path, text: str) -> Path:
    """Атомарная запись: textfile collector не должен прочитать недописанный файл."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".limen-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return p

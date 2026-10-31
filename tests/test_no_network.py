"""Ядро «Лимен» не должно содержать сетевых вызовов: это условие поставки «код без сети» для ИБ заказчика."""

from __future__ import annotations

import ast
from pathlib import Path

CORE = Path(__file__).resolve().parents[1] / "src" / "limen"
EXCLUDED = {"research"}  # исследовательский контур — вне ядра
FORBIDDEN = {
    "socket",
    "requests",
    "httpx",
    "aiohttp",
    "urllib.request",
    "http.client",
    "ftplib",
    "smtplib",
    "mlflow",
}
OPTIONAL = {"scipy", "catboost", "mlflow", "limen.research"}  # extra [research]: в ядре их быть не должно


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_core_has_no_network_imports() -> None:
    offenders = {}
    for py in CORE.rglob("*.py"):
        if EXCLUDED & set(py.relative_to(CORE).parts):
            continue
        bad = {n for n in _imports(py) if any(n == f or n.startswith(f + ".") for f in FORBIDDEN)}
        if bad:
            offenders[str(py.relative_to(CORE))] = sorted(bad)
    assert not offenders, f"Сетевые импорты в ядре: {offenders}"


def test_core_does_not_import_optional_parts() -> None:
    for py in CORE.rglob("*.py"):
        if EXCLUDED & set(py.relative_to(CORE).parts):
            continue
        bad = {n for n in _imports(py) if any(n == m or n.startswith(m + ".") for m in OPTIONAL)}
        assert not bad, f"{py.relative_to(CORE)} импортирует необязательные части: {sorted(bad)}"

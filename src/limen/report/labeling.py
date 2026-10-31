"""Офлайн-страница разметки: один HTML-файл, без сервера, без сетевых запросов.

Аналитик открывает файл в браузере на своём рабочем месте, размечает выборку и выгружает метки в CSV.
Политика Content-Security-Policy разрешает только встроенные в страницу скрипт и стили (по их SHA-256)
и запрещает любые обращения наружу. Все значения из выгрузки выводятся как текст, не как HTML.
"""

from __future__ import annotations

import base64
import hashlib
import json
from importlib.resources import files
from pathlib import Path
from typing import Any

import pandas as pd

from limen import __version__
from limen.audit.labels import LABEL_COLUMNS
from limen.integrity import sha256_json
from limen.report.render import environment
from limen.schema import ALERT_ID


def _resource(name: str) -> str:
    return (files("limen.report") / "templates" / name).read_text(encoding="utf-8")


def _csp_source(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def _json_for_html(obj: Any) -> str:
    """JSON, безопасный внутри <script>: символы <, > и & экранируются как \\uXXXX."""
    text = json.dumps(obj, ensure_ascii=False)
    return text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")


def page_rows(template: pd.DataFrame) -> list[dict[str, Any]]:
    """Строки шаблона → алерт и его контекст (служебные поля разметки в контекст не входят)."""
    hidden = set(LABEL_COLUMNS)
    rows = []
    for rec in template.fillna("").astype(str).to_dict(orient="records"):
        context = {k: v for k, v in rec.items() if k not in hidden and v != ""}
        rows.append({ALERT_ID: rec[ALERT_ID], "context": context})
    return rows


def render_labeling_page(template: pd.DataFrame, title: str = "Разметка выборки «Лимен»") -> str:
    rows = page_rows(template)
    js, css = _resource("labeling.js"), _resource("labeling.css")
    csp = (
        f"default-src 'none'; script-src {_csp_source(js)}; style-src {_csp_source(css)}; "
        "img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'"
    )
    plan_id = sha256_json(rows)[:12]
    page = (
        environment()
        .get_template("labeling.html.j2")
        .render(
            title=title,
            csp=csp,
            css=css,
            js=js,
            data_json=_json_for_html({"plan_id": plan_id, "rows": rows}),
            plan_id=plan_id,
            n_rows=len(rows),
            version=__version__,
        )
    )
    return str(page)


def write_labeling_page(template_csv: str | Path, out: str | Path, title: str | None = None) -> Path:
    template = pd.read_csv(template_csv, dtype=str, keep_default_na=False)
    if ALERT_ID not in template:
        raise KeyError(f"В шаблоне разметки нет колонки {ALERT_ID}")
    html = render_labeling_page(template, title) if title else render_labeling_page(template)
    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(html, encoding="utf-8")
    return p

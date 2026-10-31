"""Журнал действий «Лимен» в формате JSON Lines — для SIEM заказчика и разбора инцидентов.

Каждая команда, которая читает или создаёт артефакты аудита, пишет одну строку: время, действие,
пользователь, узел, версия, хеши входов и выходов, результат. Журнал включается параметром
``--audit-log`` или переменной окружения ``LIMEN_AUDIT_LOG``; без них ничего не пишется.
В журнал не попадают содержимое выгрузки, ключ и псевдонимы — только хеши и счётчики.
"""

from __future__ import annotations

import getpass
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from limen import __version__

ENV_AUDIT_LOG = "LIMEN_AUDIT_LOG"


def _node() -> str:
    try:
        return os.uname().nodename
    except AttributeError:  # Windows
        return os.environ.get("COMPUTERNAME", "")


def _user() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError):  # пользователь без записи в passwd внутри контейнера
        return str(os.getuid()) if hasattr(os, "getuid") else ""


def log_event(path: str | Path | None, action: str, status: str = "ok", **fields: Any) -> None:
    """Дописать событие в журнал. Ошибка записи не скрывается: команда завершится с ошибкой."""
    target = path or os.environ.get(ENV_AUDIT_LOG)
    if not target:
        return
    event = {
        "ts": datetime.now(UTC).isoformat(timespec="seconds"),
        "action": action,
        "status": status,
        "user": _user(),
        "host": _node(),
        "limen_version": __version__,
        **fields,
    }
    p = Path(target)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")

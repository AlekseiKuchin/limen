"""Контроль целостности артефактов аудита — принцип нулевого доверия к файлам на границе контура.

Файлы, которые переходят между заказчиком и исполнителем, не принимаются на веру:

* план выборки хранит SHA-256 таблицы алертов и конфигурации, по которым он построен;
* ``estimate`` отказывается считать, если таблица алертов не та, по которой строился план;
* результат хранит SHA-256 всех входов, а ``verify`` пересчитывает их и заново выполняет расчёт.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

_CHUNK = 1 << 20


class IntegrityError(RuntimeError):
    """Входной файл не совпадает с тем, по которому строился план или считался результат."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    """SHA-256 содержимого файла (читается блоками, подходит для больших выгрузок)."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(obj: Any) -> str:
    """SHA-256 канонического JSON: не зависит от порядка ключей и форматирования исходного YAML."""
    canonical = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256_bytes(canonical.encode("utf-8"))


def require_match(what: str, expected: str | None, actual: str) -> None:
    """Остановить работу, если хеш не совпадает. Пустое ожидание означает «не зафиксировано»."""
    if expected and expected != actual:
        raise IntegrityError(
            f"{what}: SHA-256 не совпадает (ожидался {expected[:16]}…, получен {actual[:16]}…). "
            "Файл изменён или подменён — расчёт остановлен."
        )

"""Обезличивание методом введения идентификаторов (приказ Роскомнадзора №140 от 19.06.2025).

Логины, имена хостов и IP-адреса заменяются детерминированными идентификаторами HMAC-SHA256 с секретным
ключом заказчика. Один и тот же исходный идентификатор даёт одинаковый псевдоним во всех файлах
(можно соединять таблицы), а восстановить исходное значение без ключа нельзя.

Правила:
* ключ генерируется и хранится у заказчика, никогда не попадает в выгрузки, отчёты и репозиторий;
* исходные колонки удаляются; таблица соответствия (если нужна) остаётся внутри контура заказчика.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from collections.abc import Iterable
from pathlib import Path
from typing import Literal

import pandas as pd

from limen.schema import ALERT_ID

MIN_KEY_BYTES = 32
ENV_KEY_FILE = "LIMEN_PSEUDO_KEY_FILE"
ALERT_PREFIX = "alert"
ALERT_ID_LENGTH = 16  # 64 бита: на десятках миллионов алертов совпадения практически исключены


def generate_key(path: str | Path, *, force: bool = False) -> Path:
    """Создать новый ключ (32 случайных байта) с правами только для владельца."""
    p = Path(path)
    if p.exists() and not force:
        raise FileExistsError(f"Ключ уже существует: {p}. Используйте force=True, чтобы перезаписать")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(secrets.token_bytes(MIN_KEY_BYTES))
    p.chmod(0o600)
    return p


def load_key(path: str | Path | None = None) -> bytes:
    """Прочитать ключ из файла (путь из аргумента или переменной LIMEN_PSEUDO_KEY_FILE)."""
    resolved = path or os.environ.get(ENV_KEY_FILE)
    if not resolved:
        raise ValueError(f"Не задан ключ обезличивания: передайте путь или задайте {ENV_KEY_FILE}")
    key = Path(resolved).read_bytes()
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"Ключ короче {MIN_KEY_BYTES} байт — сгенерируйте новый командой `limen keygen`")
    return key


def pseudonym(value: str, key: bytes, prefix: str, length: int = 12) -> str:
    """Псевдоним значения: префикс + первые ``length`` hex-символов HMAC-SHA256."""
    digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{prefix}_{digest[:length]}"


def pseudonymize_frame(
    df: pd.DataFrame,
    columns: dict[str, str],
    key: bytes,
    *,
    keep_mapping: bool = False,
) -> tuple[pd.DataFrame, pd.DataFrame | None]:
    """Заменить значения колонок псевдонимами.

    :param columns: колонка → префикс псевдонима (``{"user": "user", "src_ip": "ip"}``)
    :param keep_mapping: вернуть таблицу соответствия (хранить только у заказчика!)
    :return: обезличенная таблица и, при необходимости, таблица соответствия
    """
    out = df.copy()
    pairs: list[pd.DataFrame] = []
    for col, prefix in columns.items():
        if col not in out.columns:
            continue
        original = out[col].astype(str)
        uniques = pd.unique(original)
        lookup = {v: ("" if v in {"", "nan", "None"} else pseudonym(v, key, prefix)) for v in uniques}
        out[f"{prefix}_id"] = original.map(lookup)
        out = out.drop(columns=[col])
        if keep_mapping:
            pairs.append(
                pd.DataFrame({"column": col, "original": list(lookup), "pseudonym": list(lookup.values())})
            )
    out.attrs = {k: v for k, v in df.attrs.items() if k != "entity_columns"}
    mapping = pd.concat(pairs, ignore_index=True) if pairs else None
    return out, mapping


# ----------------------------------------------------------------------------- идентификаторы алертов
def alert_id_lookup(alert_ids: Iterable[str], key: bytes) -> dict[str, str]:
    """Соответствие «исходный alert_id → псевдоним» для основного режима поставки.

    Таблицу не нужно хранить: заказчик пересчитывает её своим ключом, когда переводит
    план выборки и метки между псевдонимами и исходными идентификаторами.
    """
    lookup = {str(a): pseudonym(str(a), key, ALERT_PREFIX, ALERT_ID_LENGTH) for a in alert_ids}
    if len(set(lookup.values())) != len(lookup):
        raise ValueError("Совпадение псевдонимов alert_id — увеличьте ALERT_ID_LENGTH")
    return lookup


def translate_alert_ids(
    df: pd.DataFrame,
    alert_ids: Iterable[str],
    key: bytes,
    *,
    to: Literal["original", "pseudonym"],
    column: str = ALERT_ID,
) -> pd.DataFrame:
    """Перевести колонку alert_id (шаблон разметки, метки) в исходные ID или в псевдонимы.

    Работает только внутри контура заказчика: нужны ключ и исходные идентификаторы.
    """
    forward = alert_id_lookup(alert_ids, key)
    lookup = forward if to == "pseudonym" else {v: k for k, v in forward.items()}
    out = df.copy()
    mapped = out[column].astype(str).map(lookup)
    n_unknown = int(mapped.isna().sum())
    if n_unknown:
        raise KeyError(
            f"{n_unknown} идентификаторов не найдено среди алертов выгрузки: "
            "проверьте ключ, файл и направление перевода"
        )
    out[column] = mapped
    return out

"""Модель-«автозакрыватель» на CatBoost: имитирует автоматизацию вендора, которую проверяет аудит."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from limen.research.config import AutocloserCfg
from limen.research.guide import CATEGORICAL, NUMERIC


def _features(df: pd.DataFrame) -> pd.DataFrame:
    x = df[NUMERIC + CATEGORICAL].copy()
    for c in CATEGORICAL:
        x[c] = x[c].astype(str)
    return x


def train_autocloser(train: pd.DataFrame, cfg: AutocloserCfg, seed: int) -> Any:
    """Обучить CatBoost на организациях обучающей части (только CPU)."""
    from catboost import CatBoostClassifier  # extra [research]

    if len(train) > cfg.max_train_rows:
        train = train.sample(cfg.max_train_rows, random_state=seed)
    model = CatBoostClassifier(
        iterations=cfg.iterations,
        depth=cfg.depth,
        learning_rate=cfg.learning_rate,
        loss_function="Logloss",
        random_seed=seed,
        thread_count=cfg.thread_count,
        verbose=False,
        allow_writing_files=False,
    )
    model.fit(_features(train), train["y"].to_numpy(), cat_features=CATEGORICAL)
    return model


def predict_attack_proba(model: Any, df: pd.DataFrame) -> np.ndarray:
    return np.asarray(model.predict_proba(_features(df))[:, 1], dtype=float)


def close_lowest(scores: np.ndarray, share: float) -> np.ndarray:
    """Маска автозакрытия: закрывается доля ``share`` инцидентов с наименьшей оценкой атаки."""
    n_close = round(share * len(scores))
    mask = np.zeros(len(scores), dtype=bool)
    mask[np.argsort(scores, kind="stable")[:n_close]] = True
    return mask

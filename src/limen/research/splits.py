"""Разбиения по организациям: модель учится на одних организациях, аудит проходит на других."""

from __future__ import annotations

from collections.abc import Iterator

import numpy as np
import numpy.typing as npt


def org_splits(
    orgs: npt.ArrayLike, train_frac: float, n_reps: int, seed: int
) -> Iterator[tuple[int, np.ndarray, np.ndarray]]:
    """Генерировать (номер разбиения, организации для обучения, организации для аудита)."""
    uniq = np.unique(np.asarray(orgs))
    if len(uniq) < 2:
        raise ValueError("Нужно хотя бы две организации")
    rng = np.random.default_rng(seed)
    cut = max(1, min(len(uniq) - 1, round(train_frac * len(uniq))))
    for rep in range(n_reps):
        perm = rng.permutation(uniq)
        yield rep, perm[:cut], perm[cut:]

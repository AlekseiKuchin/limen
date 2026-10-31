"""Необязательное логирование экспериментов в MLflow.

Включается только для исследовательского контура переменной LIMEN_MLFLOW_URI (например, http://127.0.0.1:5000
или file:./mlruns). Если MLflow не установлен или адрес не задан — все методы ничего не делают.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

ENV_URI = "LIMEN_MLFLOW_URI"


class Tracker:
    def __init__(self, experiment: str) -> None:
        self._mlflow: Any = None
        uri = os.environ.get(ENV_URI)
        if not uri:
            return
        try:
            import mlflow
        except ImportError:
            return
        mlflow.set_tracking_uri(uri)
        mlflow.set_experiment(experiment)
        self._mlflow = mlflow

    @property
    def enabled(self) -> bool:
        return self._mlflow is not None

    @contextmanager
    def run(self, name: str) -> Iterator[None]:
        if not self.enabled:
            yield
            return
        with self._mlflow.start_run(run_name=name):
            yield

    def log_params(self, params: dict[str, Any]) -> None:
        if self.enabled:
            self._mlflow.log_params({k: str(v) for k, v in params.items()})

    def log_metrics(self, metrics: dict[str, float]) -> None:
        if self.enabled:
            self._mlflow.log_metrics(metrics)

    def log_artifact(self, path: Path) -> None:
        if self.enabled:
            self._mlflow.log_artifact(str(path))

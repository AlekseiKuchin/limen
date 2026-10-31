# syntax=docker/dockerfile:1.7
# Образ «Лимен». Зависимости собираются из исходников внутри сборочного этапа
# (docs/adr/0003-build-from-source.md); запуск — без сети, без root, с файловой системой
# только для чтения (docker-compose.yml). Нужен BuildKit.
#
#   make lock          # requirements/runtime.txt с хешами
#   docker build -t limen:0.2.0 .
#
# В контуре заказчика базовый образ берётся из Harbor и закрепляется по digest:
#   --build-arg PYTHON_IMAGE=<harbor>/proxy/python:3.12-slim-trixie@sha256:<digest>
ARG PYTHON_IMAGE=python:3.12-slim-trixie

# ----------------------------------------------------------------------------- сборка колёс
FROM ${PYTHON_IMAGE} AS wheels
# Компиляторы и системные библиотеки — из пакетов ОС: numpy и pandas (C/C++, meson), pydantic-core (Rust).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config ninja-build patchelf libopenblas-dev rustc cargo \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY toolchain/python-wheels/build-wheels.sh requirements/runtime.txt ./
RUN ./build-wheels.sh runtime.txt /wheels
COPY pyproject.toml README.md ./
COPY src ./src
RUN PIP_NO_BINARY=":all:" python -m pip wheel --no-deps --no-cache-dir --wheel-dir /wheels .

# ----------------------------------------------------------------------------- запуск
FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="limen" \
      org.opencontainers.image.version="0.2.0" \
      org.opencontainers.image.description="Независимый статистический аудит автозакрытия алертов в SOC"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_INDEX=1 \
    HOME=/tmp
# libopenblas0 — библиотека, с которой собран numpy на предыдущем этапе.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libopenblas0 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 limen \
 && useradd --system --uid 10001 --gid limen --home-dir /app --shell /usr/sbin/nologin limen
WORKDIR /app
# Установка только из собранных колёс: индекс пакетов недоступен (PIP_NO_INDEX=1).
RUN --mount=type=bind,from=wheels,source=/wheels,target=/wheels \
    python -m pip install --no-cache-dir --no-index --find-links=/wheels limen
COPY --chown=limen:limen configs ./configs
USER limen
ENTRYPOINT ["limen"]
CMD ["--help"]

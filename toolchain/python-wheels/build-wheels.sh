#!/usr/bin/env bash
# Сборка колёс зависимостей «Лимен» из исходных дистрибутивов (sdist).
#
#   toolchain/python-wheels/build-wheels.sh requirements/runtime.txt /wheels
#
# * готовые бинарные колёса запрещены (PIP_NO_BINARY=:all:): всё компилируется здесь;
# * каждый sdist сверяется с SHA-256 из lock-файла (--require-hashes);
# * компиляторы и системные библиотеки берутся из пакетов ОС сборочного образа (см. Dockerfile).
# Ограничение pip: зависимости самой сборки (setuptools, meson-python, Cython и т. п.) ставятся
# в изолированное окружение без проверки хешей — их источником должен быть доверенный репозиторий
# (docs/adr/0003-build-from-source.md).
set -euo pipefail

REQ="${1:?укажите файл зависимостей с хешами, например requirements/runtime.txt}"
OUT="${2:?укажите каталог для колёс}"

mkdir -p "$OUT"
export PIP_NO_BINARY=":all:"
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PIP_NO_CACHE_DIR=1

python -m pip wheel --require-hashes --no-deps --wheel-dir "$OUT" -r "$REQ"
echo "Собрано колёс: $(find "$OUT" -name '*.whl' | wc -l) → $OUT"

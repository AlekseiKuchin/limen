#!/usr/bin/env bash
# Сборка Trivy из исходников с проверкой коммита тега — для рабочего места разработчика.
#
#   TRIVY_VERSION=v0.XX.Y TRIVY_COMMIT=<sha коммита тега> toolchain/trivy/build.sh
#
# SHA коммита сверяется вручную со страницей релиза и записывается в .gitlab-ci.yml (TRIVY_COMMIT).
# GOTOOLCHAIN=local запрещает Go самому скачивать другую версию компилятора; модули проверяются
# по go.sum. Источник кода и модулей можно заменить зеркалом: TRIVY_SRC_URL, GOPROXY.
set -euo pipefail

VERSION="${TRIVY_VERSION:?укажите TRIVY_VERSION, например v0.XX.Y}"
EXPECTED="${TRIVY_COMMIT:?укажите SHA коммита тега, сверенный со страницей релиза}"
SRC_URL="${TRIVY_SRC_URL:-https://github.com/aquasecurity/trivy.git}"
OUT_DIR="$(mkdir -p "${OUT_DIR:-.tools/bin}" && cd "${OUT_DIR:-.tools/bin}" && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git clone --quiet --depth 1 --branch "$VERSION" "$SRC_URL" "$WORK/trivy"
ACTUAL="$(git -C "$WORK/trivy" rev-parse HEAD)"
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "Коммит тега $VERSION не совпадает: $ACTUAL вместо $EXPECTED — сборка остановлена" >&2
  exit 1
fi

cd "$WORK/trivy"
GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/trivy" ./cmd/trivy
echo "Trivy $VERSION ($ACTUAL) собран: $OUT_DIR/trivy"

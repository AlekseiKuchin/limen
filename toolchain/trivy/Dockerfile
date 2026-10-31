# syntax=docker/dockerfile:1.7
# Образ Trivy, собранный из исходников, — для заданий CI (SCA, секреты, конфигурации, SBOM, образы).
#   docker build -f toolchain/trivy/Dockerfile \
#     --build-arg TRIVY_VERSION=v0.XX.Y --build-arg TRIVY_COMMIT=<sha> -t <harbor>/limen/trivy:v0.XX.Y .
# Версия Go в GO_IMAGE — не ниже требуемой go.mod выбранного тега; базовые образы закрепить по digest.
ARG GO_IMAGE=golang:1.24-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${GO_IMAGE} AS build
ARG TRIVY_VERSION
ARG TRIVY_COMMIT
ARG TRIVY_SRC_URL=https://github.com/aquasecurity/trivy.git
ENV GOTOOLCHAIN=local CGO_ENABLED=0
RUN test -n "${TRIVY_VERSION}" && test -n "${TRIVY_COMMIT}" \
 && git clone --quiet --depth 1 --branch "${TRIVY_VERSION}" "${TRIVY_SRC_URL}" /src \
 && test "$(git -C /src rev-parse HEAD)" = "${TRIVY_COMMIT}"
WORKDIR /src
RUN go build -trimpath -ldflags "-s -w" -o /out/trivy ./cmd/trivy

FROM ${RUNTIME_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /tmp --shell /usr/sbin/nologin trivy
COPY --from=build /out/trivy /usr/local/bin/trivy
USER trivy
ENTRYPOINT ["trivy"]

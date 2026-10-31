#!/bin/sh
# Получить секрет из Vault по JWT задания GitLab CI — без долгоживущих паролей в переменных CI.
#
#   PASSWORD="$(toolchain/ci/vault-secret.sh limen/harbor password)"
#
# Нужны: VAULT_ADDR, VAULT_ID_TOKEN (id_tokens задания), роль VAULT_ROLE (по умолчанию limen-ci)
# в методе аутентификации jwt; движок секретов KV версии 2 смонтирован в VAULT_KV_MOUNT (по умолчанию secret).
set -eu

SECRET_PATH="${1:?путь секрета в KV, например limen/harbor}"
FIELD="${2:?поле секрета, например password}"
ROLE="${VAULT_ROLE:-limen-ci}"
MOUNT="${VAULT_KV_MOUNT:-secret}"

TOKEN="$(curl -sS --fail -X POST -H 'Content-Type: application/json' \
  -d "{\"role\":\"${ROLE}\",\"jwt\":\"${VAULT_ID_TOKEN:?нет VAULT_ID_TOKEN}\"}" \
  "${VAULT_ADDR:?нет VAULT_ADDR}/v1/auth/jwt/login" | jq -r '.auth.client_token')"

curl -sS --fail -H "X-Vault-Token: ${TOKEN}" "${VAULT_ADDR}/v1/${MOUNT}/data/${SECRET_PATH}" \
  | jq -r --arg f "$FIELD" '.data.data[$f]'

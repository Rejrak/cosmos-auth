#!/usr/bin/env bash
set -euo pipefail

HOME_DIR="${ALPHA_HOME:-/root/.alpha}"
CHAIN_ID="${CHAIN_ID:-alpha-1}"
MONIKER="${MONIKER:-val}"
KEYRING_BACKEND="${KEYRING_BACKEND:-test}"

VALIDATOR_KEY="${VALIDATOR_KEY:-alice}"
VALIDATOR_BOND="${VALIDATOR_BOND:-100000000stake}"

GENESIS_ACCOUNTS="${GENESIS_ACCOUNTS:-alice:5000000token,100000000stake bob:50000000token,100000stake}"
MINIMUM_GAS_PRICES="${MINIMUM_GAS_PRICES:-0stake}"

init_chain() {
  echo ">> init home=${HOME_DIR} chain-id=${CHAIN_ID} moniker=${MONIKER}"
  alphad init "${MONIKER}" --chain-id "${CHAIN_ID}" --home "${HOME_DIR}"

  # set minimum gas prices (se esiste app.toml)
  APP_TOML="${HOME_DIR}/config/app.toml"
  if [ -f "${APP_TOML}" ]; then
    sed -i 's/^minimum-gas-prices *=.*/minimum-gas-prices = "'"${MINIMUM_GAS_PRICES//\//\\/}"'"/' "${APP_TOML}" || true
  fi

  echo ">> create validator key: ${VALIDATOR_KEY}"
  # evita prompt: keyring-backend=test non chiede password
  alphad keys add "${VALIDATOR_KEY}" --keyring-backend "${KEYRING_BACKEND}" --home "${HOME_DIR}" >/dev/null

  # aggiungi accounts al genesis (NOTA: comando sotto "genesis")
  echo ">> add genesis accounts"
  for item in ${GENESIS_ACCOUNTS}; do
    name="${item%%:*}"
    coins="${item#*:}"
    addr="$(alphad keys show "${name}" -a --keyring-backend "${KEYRING_BACKEND}" --home "${HOME_DIR}" 2>/dev/null || true)"
    if [ -z "${addr}" ]; then
      echo ">> create key: ${name}"
      alphad keys add "${name}" --keyring-backend "${KEYRING_BACKEND}" --home "${HOME_DIR}" >/dev/null
      addr="$(alphad keys show "${name}" -a --keyring-backend "${KEYRING_BACKEND}" --home "${HOME_DIR}")"
    fi
    echo "   - ${name} -> ${addr} : ${coins}"
    alphad genesis add-genesis-account "${addr}" "${coins}" --home "${HOME_DIR}"
  done

  echo ">> gentx + collect-gentxs"
  alphad genesis gentx "${VALIDATOR_KEY}" "${VALIDATOR_BOND}" \
    --chain-id "${CHAIN_ID}" \
    --keyring-backend "${KEYRING_BACKEND}" \
    --home "${HOME_DIR}"

  alphad genesis collect-gentxs --home "${HOME_DIR}"
  alphad genesis validate-genesis --home "${HOME_DIR}"

  echo ">> done. genesis at: ${HOME_DIR}/config/genesis.json"
}

# se non esiste genesis.json, inizializza
if [ ! -f "${HOME_DIR}/config/genesis.json" ]; then
  init_chain
else
  echo ">> existing genesis found, skip init"
fi

# start di default
exec alphad "$@" --home "${HOME_DIR}"
#!/usr/bin/env bash
set -euo pipefail

HOME_DIR="${ALPHA_HOME:-/root/.alpha}"
CHAIN_ID="${CHAIN_ID:-alpha-1}"
MONIKER="${MONIKER:-val}"
KEYRING_BACKEND="${KEYRING_BACKEND:-test}"

VALIDATOR_KEY="${VALIDATOR_KEY:-alice}"
VALIDATOR_BOND="${VALIDATOR_BOND:-100000000stake}"

GENESIS_ACCOUNTS="${GENESIS_ACCOUNTS:-alice:5000000token,100000000stake bob:50000000token,100000stake}"
MINIMUM_GAS_PRICES="${MINIMUM_GAS_PRICES:-0stake}"

init_chain() {
  echo ">> init home=${HOME_DIR} chain-id=${CHAIN_ID} moniker=${MONIKER}"
  alphad init "${MONIKER}" --chain-id "${CHAIN_ID}" --home "${HOME_DIR}"

  # set minimum gas prices (se esiste app.toml)
  APP_TOML="${HOME_DIR}/config/app.toml"
  if [ -f "${APP_TOML}" ]; then
    sed -i 's/^minimum-gas-prices *=.*/minimum-gas-prices = "'"${MINIMUM_GAS_PRICES//\//\\/}"'"/' "${APP_TOML}" || true
  fi

  echo ">> create validator key: ${VALIDATOR_KEY}"
  # evita prompt: keyring-backend=test non chiede password
  alphad keys add "${VALIDATOR_KEY}" --keyring-backend "${KEYRING_BACKEND}" --home "${HOME_DIR}" >/dev/null

  # aggiungi accounts al genesis (NOTA: comando sotto "genesis")
  echo ">> add genesis accounts"
  for item in ${GENESIS_ACCOUNTS}; do
    name="${item%%:*}"
    coins="${item#*:}"
    addr="$(alphad keys show "${name}" -a --keyring-backend "${KEYRING_BACKEND}" --home "${HOME_DIR}" 2>/dev/null || true)"
    if [ -z "${addr}" ]; then
      echo ">> create key: ${name}"
      alphad keys add "${name}" --keyring-backend "${KEYRING_BACKEND}" --home "${HOME_DIR}" >/dev/null
      addr="$(alphad keys show "${name}" -a --keyring-backend "${KEYRING_BACKEND}" --home "${HOME_DIR}")"
    fi
    echo "   - ${name} -> ${addr} : ${coins}"
    alphad genesis add-genesis-account "${addr}" "${coins}" --home "${HOME_DIR}"
  done

  echo ">> gentx + collect-gentxs"
  alphad genesis gentx "${VALIDATOR_KEY}" "${VALIDATOR_BOND}" \
    --chain-id "${CHAIN_ID}" \
    --keyring-backend "${KEYRING_BACKEND}" \
    --home "${HOME_DIR}"

  alphad genesis collect-gentxs --home "${HOME_DIR}"
  alphad genesis validate-genesis --home "${HOME_DIR}"

  echo ">> done. genesis at: ${HOME_DIR}/config/genesis.json"
}

# se non esiste genesis.json, inizializza
if [ ! -f "${HOME_DIR}/config/genesis.json" ]; then
  init_chain
else
  echo ">> existing genesis found, skip init"
fi

# start di default
exec alphad "$@" --home "${HOME_DIR}"

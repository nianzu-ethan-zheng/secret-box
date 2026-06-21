#!/usr/bin/env bash
# Source me: source env.sh
# After sourcing: `app login`, `app list`, `app cat <name>`, `app add <path>`,
# `app rm <name>`, `app status`, `app logout`, `secretbox-web`.

if [ -z "${BASH_SOURCE[0]:-}" ]; then
    echo "env.sh: must be sourced, not executed" >&2
    return 1 2>/dev/null || exit 1
fi

export SECRETBOX_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$SECRETBOX_HOME/.venv" ]; then
    echo "secretbox: creating venv at $SECRETBOX_HOME/.venv"
    if python3 -m venv "$SECRETBOX_HOME/.venv" 2>/dev/null; then
        :
    elif command -v virtualenv >/dev/null 2>&1; then
        virtualenv "$SECRETBOX_HOME/.venv"
    else
        python3 -m virtualenv "$SECRETBOX_HOME/.venv" || {
            echo "secretbox: could not create venv. Install python3-venv or virtualenv." >&2
            return 1 2>/dev/null || exit 1
        }
    fi
    "$SECRETBOX_HOME/.venv/bin/pip" install -q -e "$SECRETBOX_HOME"
fi

# shellcheck source=/dev/null
source "$SECRETBOX_HOME/.venv/bin/activate"

mkdir -p "$SECRETBOX_HOME/data"

app() {
    python -m secretbox.cli "$@"
}

secretbox-web() {
    python -m secretbox.web "$@"
}

echo "secretbox: ready. Try \`app status\` or \`app add <path>\`."

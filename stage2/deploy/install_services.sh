#!/usr/bin/env bash
#
# Install (or update) the Cubic Castles relay + Discord bot as systemd services,
# so both start on boot and restart on failure. Idempotent — safe to re-run after
# a `git pull` to pick up code changes (it re-renders the units and restarts).
#
#   cd <repo>/stage2/deploy
#   sudo ./install_services.sh
#
# It does NOT touch your secrets: the first run drops an env template at
# /etc/cubic-castles/cubic-castles.env for you to fill in; later runs leave it be.
# The public tunnel / reverse proxy fronting the relay is a SEPARATE service — see README.
set -euo pipefail

ENVDIR="/etc/cubic-castles"
ENVFILE="$ENVDIR/cubic-castles.env"
UNITDIR="/etc/systemd/system"

# --- must be root -----------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "Run me with sudo:  sudo ./install_services.sh" >&2
    exit 1
fi

# --- resolve paths / user ---------------------------------------------------
DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE2="$(cd "$DEPLOY_DIR/.." && pwd)"     # the folder holding cc_relay.py

if [[ ! -f "$STAGE2/cc_relay.py" || ! -f "$STAGE2/cc_discord_bot.py" ]]; then
    echo "ERROR: cc_relay.py / cc_discord_bot.py not found in $STAGE2" >&2
    echo "Run this from the repo's stage2/deploy directory." >&2
    exit 1
fi

# The service should run as the human who owns the checkout, not root.
RUN_USER="${SUDO_USER:-$(logname 2>/dev/null || true)}"
if [[ -z "$RUN_USER" || "$RUN_USER" == "root" ]]; then
    RUN_USER="$(stat -c '%U' "$STAGE2/cc_relay.py")"
fi
# Prefer the project's own venv if there is one (that's where discord.py is
# installed on this box); fall back to system python3.
if [[ -x "$STAGE2/venv/bin/python" ]]; then
    PYTHON="$STAGE2/venv/bin/python"
elif [[ -x "$STAGE2/venv/bin/python3" ]]; then
    PYTHON="$STAGE2/venv/bin/python3"
else
    PYTHON="$(command -v python3 || true)"
fi
if [[ -z "$PYTHON" ]]; then
    echo "ERROR: no python found (no venv, and python3 not on PATH)." >&2
    exit 1
fi

echo "Repo (stage2): $STAGE2"
echo "Run as user:   $RUN_USER"
echo "Python:        $PYTHON"
echo

# --- env file (secrets) -----------------------------------------------------
mkdir -p "$ENVDIR"
if [[ ! -f "$ENVFILE" ]]; then
    cp "$DEPLOY_DIR/cubic-castles.env.example" "$ENVFILE"
    chmod 600 "$ENVFILE"
    chown root:root "$ENVFILE"
    echo "Created $ENVFILE from the template."
    NEED_EDIT=1
else
    chmod 600 "$ENVFILE"; chown root:root "$ENVFILE"
    echo "Kept existing $ENVFILE (not overwritten)."
fi

# --- ensure the bot's one dependency (discord.py) is importable -------------
echo "Checking discord.py in $PYTHON ..."
if ! sudo -u "$RUN_USER" "$PYTHON" -c "import discord" 2>/dev/null; then
    # Inside a venv, install into the venv; with system python, use --user.
    if [[ "$PYTHON" == "$STAGE2/venv/"* ]]; then
        PIP_ARGS=(install --upgrade discord.py)
    else
        PIP_ARGS=(install --user --upgrade discord.py)
    fi
    echo "  installing discord.py (${PIP_ARGS[*]}) ..."
    set +e
    sudo -u "$RUN_USER" "$PYTHON" -m pip "${PIP_ARGS[@]}"
    sudo -u "$RUN_USER" "$PYTHON" -c "import discord" 2>/dev/null
    OK=$?
    set -e
    if [[ $OK -ne 0 ]]; then
        echo "  WARNING: discord.py still not importable. On a managed Python" >&2
        echo "  (PEP 668) install it in the venv, or re-run pip with" >&2
        echo "  --break-system-packages, then restart cc-discord-bot." >&2
    fi
else
    echo "  discord.py already present."
fi

# --- render + install the unit files ---------------------------------------
render() {   # render <template> <dest>
    sed -e "s|@USER@|$RUN_USER|g" \
        -e "s|@STAGE2@|$STAGE2|g" \
        -e "s|@PYTHON@|$PYTHON|g" \
        -e "s|@ENVFILE@|$ENVFILE|g" \
        "$1" > "$2"
}
render "$DEPLOY_DIR/cc-relay.service"       "$UNITDIR/cc-relay.service"
render "$DEPLOY_DIR/cc-discord-bot.service" "$UNITDIR/cc-discord-bot.service"
echo "Installed unit files to $UNITDIR."

systemctl daemon-reload
systemctl enable cc-relay.service cc-discord-bot.service >/dev/null
echo "Enabled both services (start on boot)."

# --- start now (unless secrets are still placeholders) ----------------------
if grep -q "CHANGE_ME" "$ENVFILE"; then
    echo
    echo "==> Services are ENABLED but NOT started: $ENVFILE still has CHANGE_ME."
    echo "    1) sudo nano $ENVFILE      # set RELAY_ADMIN_TOKEN and DISCORD_TOKEN"
    echo "    2) sudo systemctl start cc-relay cc-discord-bot"
else
    systemctl restart cc-relay.service
    systemctl restart cc-discord-bot.service
    echo "Started (restarted) both services."
fi

echo
echo "Status / logs:"
echo "  systemctl status cc-relay cc-discord-bot"
echo "  journalctl -u cc-relay -f"
echo "  journalctl -u cc-discord-bot -f"
if [[ "${NEED_EDIT:-0}" == "1" ]]; then
    echo
    echo "REMINDER: fill in $ENVFILE and (if you pasted the old admin token in"
    echo "chat) ROTATE it before real use."
fi

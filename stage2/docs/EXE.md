# The exe — the game bot + GUI

A single self-contained Windows program each operator runs on their own PC. It logs into Cubic Castles, drives an in-game bot, and (optionally) exposes that bot to Discord through the relay. Unlike the relay and Discord bot, the exe code **is** in the repo (others build it) and gets bundled into the binary.

## Two builds, one codebase

Built by [`build_exe.ps1`](../build_exe.ps1) from `cc_bot_launcher.py`:

| File | Mode | Has |
|---|---|---|
| `cubic-bot.exe` | **simple** | Logs / Market / Scan / Status |
| `cubic-bot-full.exe` | **full** | everything + a **Controls** tab (Teleport, Park, Help/Where/Players/Friends) |

The GUI picks its mode from the **exe's own filename**. Nothing account-specific is baked in — the first run captures whoever runs it.

## The pieces inside

| Module | Role |
|---|---|
| `cc_bot_launcher.py` | Entry point — starts the GUI. |
| `cc_gui.py` | The always-on **tkinter GUI** (dark, sidebar tabs). Spawns and supervises the game-bot child and drives it over a local web-control server. |
| `cc_client.py` | The **game bot** itself — connects to the game server over WebSocket using the saved login, runs the protocol, and hosts the local control server. Runs as a headless child of the GUI (`--headless`). |
| `cc_remote.py` | The relay **poll loop** + the **permission guard**. |
| `cc_provision.py` | One-time **login capture** (frida), the `bot_id`, and remote config. |

The GUI and the game bot are separate processes. The GUI talks to the bot over `http://127.0.0.1:<random port>?token=…` — the same local API the buttons and the remote worker use.

## First run — login capture

No login is baked in. The **Set up login** dialog (`cc_provision.LoginCapture`) uses the bundled frida runtime + `nopoll_agent.js` to attach to a running `Cubic.exe`, capture the login the moment you sign in, and save it. After that every launch reuses it. (Frida is used **only** for this capture; the bot itself connects to the game server directly over WebSocket afterward.)

## Where it keeps data — `%APPDATA%\CubicBot`

A frozen `--onefile` exe unpacks to a fresh temp dir each launch and deletes it on exit, so anything written next to the exe is wiped. `_resolve_app_dir()` therefore points all state at a stable per-user folder:

```
%APPDATA%\CubicBot   (e.g. C:\Users\<you>\AppData\Roaming\CubicBot)
```

What lives there: the market DB (`cubic_market.db`), the orders DB, `vends.json` / `realms.json` / `watchlist.json`, `webhook.json`, `approved_users.json`, `quiz_learned.json`, the saved login, `bot_id.json`, `remote.json`, and the bot log. Running **from source** (`python cc_client.py`) instead writes next to the script.

## The local web-control server

Hosted by `cc_client.py` (`start_control_server`) on `127.0.0.1:<port>` with a token. The GUI, the browser tools, and the remote worker all call it. Selected endpoints:

| Endpoint | Purpose |
|---|---|
| `/status` | account / connection / current realm |
| `/logs?since=` | rolling log feed |
| `/cmd?line=` | queue any console command |
| `/runcmd?line=` | run a command and return **only** the lines it produced (precise capture for remote) |
| `/scan` | start a full realm scan (async) |
| `/scanstatus` | is a scan running + vend count + a monotonic completion counter |
| `/items` | distinct scanned item names (fed to the relay for `/market` autocomplete) |
| `/hwarp?on=`, `/park`, `/tp?name=` | movement controls |

## Remote control (talking to the relay)

`cc_remote.RemoteWorker` runs a background thread that, **only while linked/enabled**:

1. `POST <relay>/poll` (Bearer `bot_id`) — pick up queued commands, and every ~30s push the scanned **item list** for autocomplete.
2. Check each command against the **permission guard**, then run allowed ones via the local control API.
3. `POST <relay>/result` — hand the output back.

### The permission guard — `command_allowed(command, role)`

The **real** security boundary (the Discord bot's list is only for UX). Two tiers:

- **`GUEST_COMMANDS`** — `guid`, `tp`, `market`, `status`, `where`, `players`, `friends`, `dbstats`, `help` (+ the read-only `scan status` poll). Teleport-to-scan and read data only.
- **`OWNER_COMMANDS`** — the guest set **plus** `scan` (bare rescan), `park`, `queue`, `hwarp`/`autowarp`, `webhook`.

A bare `scan` is owner-only, but `scan status` is allowed to anyone (so a guest's `/guid` teleport-and-scan can watch for completion). The relay tags each command `owner`/`guest`; the exe refuses a guest's owner command with a `🔒 owner only` note.

### The `bot_id`

The exe's password to the relay. Generated on first run (`secrets.token_urlsafe(24)`), stored in `%APPDATA%\CubicBot\bot_id.json`, sent only in the `Authorization` header, **never shown in Discord**. "Unlinking" rotates it.

## Resilience — Cloudflare rate limits

The game's front end is behind Cloudflare, which can answer a burst of reconnects with **HTTP 429 / `error code 1015`** (IP-level) plus a `Retry-After` header. The auto-reconnect reads that header and waits the **full** requested time (overriding its normal backoff cap) instead of hammering — retrying sooner just feeds the limit. In the moment, `reconnect off` and wait out the window.

## Building

```powershell
# from stage2, with the exe not currently running:
.\build_exe.ps1                 # both; -Only simple / -Only full for one
```

Or directly (avoids the script's stderr quirks):

```bash
python -m PyInstaller --onefile --windowed --name cubic-bot \
  --add-data "nopoll_agent.js;." --collect-all frida \
  --hidden-import websocket --hidden-import cc_protocol --hidden-import send_cipher \
  --hidden-import xxtea --hidden-import cc_storage --hidden-import cc_orders \
  --hidden-import cc_quiz --hidden-import cc_provision --hidden-import cc_remote \
  --hidden-import cc_gui --hidden-import cc_client cc_bot_launcher.py
```

Close any running `cubic-bot*.exe` first (PyInstaller "Access is denied" otherwise). Built exes land in `dist\` (~57 MB) and are published as GitHub Releases.

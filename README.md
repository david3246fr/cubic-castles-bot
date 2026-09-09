# Cubic Castles Bot

An unofficial **vend & market scanner** for **Cubic Castles**. It logs into the
game with your own account and sweeps shop (vend) prices into a searchable local
database, so you can look up what any item is selling for. It also handles
teleport / navigation and player GUID lookup, and can be driven remotely from
Discord.

**What it does:**
- **Vend & market scanning** — sweep a realm's shops and store every price
- **Price lookup** — search your scanned data for any item
- **Teleport / navigation** — move around and jump to players or realms
- **Player GUID lookup** — resolve a player's id
- **Discord remote control** — run it from a Discord server (optional)

> **Two ways to use it:**
> 1. **The app (default, easiest)** — download one `.exe`, run it, done. No coding.
> 2. **The source code (advanced)** — run it with Python if you don't want the exe.

> ⚠️ **Unofficial & experimental.** Only use it with an account you own and are
> allowed to operate. The game may rate-limit, flag, or ban unofficial clients.
> Use at your own risk.

---

## Option 1 — Just use the app (recommended)

**No installing Python, no code.** One file.

### Step 1 — Download the app

Go to the [**Releases**](../../releases/latest) page and download **`cubic-bot.exe`**.

That's the app — Logs, Market, Scan, and Status in one window.

*(Windows may warn about an unknown publisher because the app isn't code-signed —
click **More info → Run anyway** if you trust it.)*

### Step 2 — Run it

Double-click the `.exe`. A window opens with tabs down the side.

### Step 3 — Set up your login (one time)

The app has **no account built in** — you connect **your own** account the first time:

1. Make sure **Steam** is running and open **Cubic Castles**.
2. In the app, click **Set up login**.
3. **Log in** to the game as you normally would — the app captures that login the moment you sign in.
4. Click **Finish**.

That's it. Every time you open the app after this, it reuses your saved login
automatically. (Your login is stored privately on **your** PC only — see
[Is this safe?](#is-this-safe) below.)

### Step 4 — Use it

Pick a tab and go:

- **Logs** — live activity, plus a box where you can type commands.
- **Market** — search item prices (run a **Scan** first so it has data).
- **Scan** — sweep the current realm's shops into the price database.
- **Status** — your account, connection, and current realm.

**More detail:** [stage2/docs/EXE.md](stage2/docs/EXE.md) explains every tab and where the
app saves its data.

### Optional — control it from Discord

The bot can be driven from a Discord server through a small relay, with a
guest/owner permission system so you decide who can do what. See
[stage2/docs/README.md](stage2/docs/README.md) for the remote-control setup.

---

## Option 2 — Run from source (advanced)

Prefer not to use the exe? Run the same bot directly with Python.

### Requirements
- Python 3.10+
- Windows (login capture uses the official Windows client)

### Steps

```bash
# 1. Get the code
git clone https://github.com/david3246fr/cubic-castles-bot.git
cd cubic-castles-bot

# 2. Install dependencies
python -m venv .venv
.venv\Scripts\activate            # Windows
pip install frida frida-tools websocket-client
```

Then capture your login once and run it. The full walkthrough (capturing your
login, building your profile, and running) is in:

- **[SETUP.md](SETUP.md)** — get your own copy running, step by step.

Quick version once you have a `profile.json`:

```bash
run --login-from profile.json        # Windows
./run.sh --login-from profile.json   # Linux/macOS
```

---

## What's in this repo

| Path | What it is |
|---|---|
| [`stage2/dist/`](stage2/dist) | The ready-to-run app (`cubic-bot.exe`). |
| [`stage2/cc_client.py`](stage2/cc_client.py) | The bot itself — login, realms, scanning, commands. |
| [`stage2/cc_gui.py`](stage2/cc_gui.py) | The desktop control panel (the window you see). |
| [`stage2/cc_protocol.py`](stage2/cc_protocol.py) | Talks the game's network protocol. |
| [`stage2/docs/`](stage2/docs) | Deeper docs — the app, the Discord relay, architecture. |
| [`SETUP.md`](SETUP.md) | Run-from-source walkthrough. |
| [`run.cmd`](run.cmd) / [`run.sh`](run.sh) | Launchers for the source version. |

---

## Is this safe?

**Your account stays private.** The app never uploads your login. It's captured
from your own session and saved only on your PC (in `%APPDATA%\CubicBot`).

Nothing account-specific is ever committed to this repo — `.gitignore` blocks
login profiles, captures, logs, and databases. **Never** share your `profile.json`,
your captures, or your logs: they contain your account token.

If the game returns rate-limit errors (Cloudflare `error code 1015`), stop and
wait a while before reconnecting — retrying immediately makes it worse.

---

## License / disclaimer

This is a personal, unofficial project and is **not** affiliated with or endorsed
by Cubic Castles or its developers. Provided as-is, with no warranty. You are
responsible for how you use it.

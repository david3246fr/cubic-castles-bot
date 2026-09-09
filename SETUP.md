# Setup — getting your own copy running

This repository ships with **no account data**. Login profiles, captures, logs,
and databases are excluded by `.gitignore` and never uploaded. To run the tools
against **your own** account you generate your own login profile once.

> Cubic Castles login is not a username/password you can paste into a config.
> The client replays the exact login frames the real game sent. Those frames
> encode your machine-id, Steam session, and account token, so they have to be
> **captured from your own login**, not typed. This is a one-time step.

## 1. Install Python dependencies

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate      Linux/macOS:  source .venv/bin/activate
pip install frida frida-tools websocket-client
```

## 2. Capture your own login (one time)

Start Steam, then run the capture tool. It launches/attaches to the official
client; log in normally while it records:

```bash
python stage2/cc_capture.py --plaintext --tag mylogin
```

This writes a capture file (a `.jsonl`) under `stage2/captures/`. That file is
**private** — it is gitignored and must never be shared or committed.

## 3. Turn the capture into your profile

```bash
python stage2/cc_login.py stage2/captures/<your-capture>.jsonl -o profile.json
```

`profile.json` is your personal login profile. It is gitignored. See
`profile.example.json` for the shape it will have.

## 4. Run

```bash
# Windows:
run --login-from profile.json
# Linux/macOS:
./run.sh --login-from profile.json
```

### Before exposing the web control panel

The `run` scripts set `--control-token pickAsecret` as a placeholder. If you
bind the control panel to the network (`--control-host 0.0.0.0`), change that
token to something private first — anyone who can reach the port and knows the
token can drive the bot.

## What stays private (never committed)

`.gitignore` blocks all of these automatically:

- `profile.json`, `config.json`, and any `*profile*.json` (your login frames)
- `stage2/captures/` and any `*.jsonl` / `*.log` (raw traffic, session keys)
- `*.db` (scraped market / order databases)

If you ever add a new file that holds a token, key, or account id, add its name
to `.gitignore` **before** you commit. A secret pushed once stays in the Git
history even after you delete the file.

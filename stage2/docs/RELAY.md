# The relay — `cc_relay.py`

The public meeting point between the at-home exe (behind NAT) and the Discord bot. It's a **stdlib-only** HTTP server (`http.server.ThreadingHTTPServer`, HTTP/1.1) — no pip installs — so it's trivial to run and audit. It runs on the Linux server, bound to localhost, and is exposed publicly by your own tunnel / reverse proxy.

> **Server-only file — not in git.** Deliver/update it with `scp`, then restart the service. See [../deploy/README.md](../deploy/README.md).

## What it is (and isn't)

- It is a **dumb pipe with a binding table**. It parks commands for a bot and hands back results.
- It does **not** interpret game commands. The allow/deny of *what* may run is enforced by the exe (`cc_remote.command_allowed`); the relay only tags each command with the caller's **role**.
- It holds two kinds of trust: `bot_id` authenticates an exe; `RELAY_ADMIN_TOKEN` authenticates the Discord bot.

## Endpoints

Auth is a `Bearer` token in the `Authorization` header. Two classes:

### Exe-facing (auth = `Bearer <bot_id>`)

| Endpoint | Purpose |
|---|---|
| `POST /poll` | Register the bot as online, drain + return its queued commands, and (optionally) push its scanned **item list** for autocomplete. Returns `{commands, linked, discord_user}`. |
| `POST /result` | Hand back one command's output: `{id, output, ok}`. Wakes the blocked `/enqueue` caller. |
| `POST /linkcode` | Mint a one-time 6-char link code mapping to this `bot_id`. Rate limited (≤5 per bot per 5 min). |

### Discord-bot-facing (auth = `Bearer <RELAY_ADMIN_TOKEN>`)

| Endpoint | Purpose |
|---|---|
| `POST /link` | Redeem a code → bind `discord_user` ↔ `bot_id` (+ record the guild). First-linker-wins. |
| `POST /enqueue` | Queue a command for the caller's target bot and **block up to 25s** for its result. Body `{discord_user, guild, command}`. |
| `POST /items` | Autocomplete lookup: `{discord_user, guild, query, limit}` → item names the target bot has scanned, filtered (prefix hits first, then substring). |

There is deliberately **no `/unlink`** — an exe "unlinks" by rotating its `bot_id`; the old binding then points at a `bot_id` that never polls again and is inert. Keeping the surface small is a security property.

## State

All in memory except the bindings, which persist to `relay_state.json` (next to the script, or `RELAY_STATE_FILE`):

| Field | Shape | Persisted? |
|---|---|---|
| `bindings` | `bot_id → {discord_user, guild, at}` — the authoritative "who owns which bot" | ✅ |
| `by_user` | `discord_user → bot_id` (reverse: this user **owns** that bot) | ✅ |
| `by_guild` | `guild → bot_id` (which bot a server's **guests** may drive) | ✅ |
| `bots` | `bot_id → {inbox, last_poll, items}` (online status, queued cmds, cached item names) | ✗ (ephemeral) |
| `results` | `cmd_id → {output, ok, done_at}` (kept `RESULT_TTL` = 120s) | ✗ |
| `codes` | `code → {bot_id, expires}` (link codes, 5-min TTL, single-use) | ✗ |

## Permission resolution — `_resolve_target(discord_user, guild)`

Decides `(bot_id, role)` for a Discord caller. **The server you're in wins:**

1. **You own the bot linked in *this* guild** → `role = owner`, target that bot.
2. **Else a bot is linked in this guild** → `role = guest`, target it (`_guest_bot_for_guild` prefers the one **online right now**, so guests reach the live bot even if `by_guild` is stale or was never recorded).
3. **Else fall back to your own bot** (`by_user`) as owner — lets an owner drive their bot from a DM or a bot-less server.
4. Nothing linked for you → `not_linked` (Discord shows "not linked yet").

> Why step 1 matters: a user who owns a bot in *another* server must still be a **guest** of the bot linked where they're typing — otherwise `by_user` would wrongly route them to their own (possibly offline) bot. This exact bug produced "bot didn't answer" for a cross-server guest; the guild-first order fixes it.

The chosen `role` is attached to the inbox item (`{id, command, role, enqueued}`); the exe trusts it because it arrives over the admin-authed channel and is computed from the authoritative bindings, never supplied by the caller.

## Safety limits

- Link codes: `LINKCODE_MAX_PER_WINDOW` = 5 per bot per 300s; alphabet omits `0/O/1/I/L`.
- `/link` brute-force guard: `LINK_MAX_PER_WINDOW` = 20 per source IP per 60s.
- `/enqueue` blocks at most `ENQUEUE_WAIT` = 25s (then returns `status:timeout`).
- Request bodies capped at 64 KB; `bot_id` must match `^[A-Za-z0-9_-]{16,128}$`.
- Secrets are never logged in full — `_mask()` prints a fingerprint.

## Running it

```bash
RELAY_ADMIN_TOKEN=<long-random-secret> python3 cc_relay.py
```

Environment:

| Var | Default | Meaning |
|---|---|---|
| `RELAY_ADMIN_TOKEN` | *(required)* | The Discord bot's password to the relay. |
| `RELAY_HOST` | `127.0.0.1` | Bind address (keep localhost; your public endpoint fronts it). |
| `RELAY_PORT` | `8788` | Bind port. |
| `RELAY_STATE_FILE` | `relay_state.json` beside the script | Where bindings persist. |

In production it runs as the **`cc-relay`** systemd service — see [../deploy/README.md](../deploy/README.md).

### Fronting it publicly

Bind the relay to localhost and forward to it from your own public endpoint (a tunnel or reverse proxy). Keep the forward target on the same IPv4 loopback the relay listens on.

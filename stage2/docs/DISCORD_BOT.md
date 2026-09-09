# The Discord bot — `cc_discord_bot.py`

The human-facing front end. People type slash commands in Discord; this bot relays them to the linked exe (through the relay) and shows the answer. It runs on the Linux server next to the relay and needs `discord.py`.

> **Server-only file — not in git.** Deliver/update it with `scp`, then restart the service. See [../deploy/README.md](../deploy/README.md).

## It is stateless and holds no `bot_id`

- The only secret it holds is `RELAY_ADMIN_TOKEN` (its password to the relay).
- **Identity is supplied by Discord**, not typed: every interaction carries a verified `interaction.user.id`. The bot sends that (and `interaction.guild_id`) to the relay, which resolves it to the right bot and role. The bot never sees or handles a `bot_id`.
- Every reply is **ephemeral** (private to the person who ran the command).

## Commands

### Anyone in the server (guest tier)

| Command | Does |
|---|---|
| `/guid <player>` | Teleport the bot to a player and auto-scan their realm; reports the vend count. Waits for it to finish (polls in the background). |
| `/tp <player\|guid>` | Teleport to a known player name or a 32-hex GUID. |
| `/market <item>` | Look up an item's price. **Autocompletes** to items the bot has scanned (see below). |
| `/dbstats` | Market database stats. |
| `/status` | Account, connection, current realm. |
| `/cmd <text>` | Run one allowed command directly — also reaches `where` / `players` / `friends`. |
| `/help` | List commands (split by tier). |
| `/link <code>` | Bind your Discord account to a bot with its one-time code. |

### Owner only (whoever linked the bot)

| Command | Does |
|---|---|
| `/scan` | Rescan the realm the bot is sitting in; reports the vend count. |
| `/park` | Send the bot back to the park realm. |
| `/hwarp on\|off` | Auto-Hollawarp — join + scan every Hollawarp broadcast. |
| `/cmd queue`, `/cmd webhook …` | Move queue + alert-webhook settings. |

A guest who invokes an owner command gets a `🔒 owner only` refusal (enforced by the exe). Owner vs guest is decided by the relay from the bindings — **the server you're in wins** (see [RELAY.md](RELAY.md)).

## How it talks to the relay

A blocking `urllib` POST wrapped in `asyncio.to_thread` so it never blocks the event loop. Every call sends `discord_user` and `guild`:

```python
await relay("/enqueue", {"discord_user": uid, "guild": guild, "command": "market green balloon"})
```

`format_result()` turns the reply into a message: `404` → "not linked", `status:timeout` → "bot didn't answer", otherwise the command's output (prefixed ⚠️ if it failed).

### Short vs long commands

- **Short** (`/market`, `/status`, `/tp`, `/dbstats`, `/park`, `/hwarp`, `/cmd`) go through `_run_command`: one `/enqueue`, show the result.
- **Long** (`/scan`, `/guid`) can outlast the relay's 25s window, so they use a **poll pattern**: kick the job off, note a completion counter, then poll `scan status` every ~4s (editing the private message with progress) until the counter advances — then report `Realm X scanned — N vends`. The JSON contract between the bot and the exe is parsed by `_json_reply`.

## `/market` autocomplete

`@market.autocomplete("item")` fires as the user types and must answer fast, so it does **not** round-trip to the exe. It asks the relay's **cache** (`POST /items {discord_user, guild, query}`), which the exe keeps fresh by pushing its scanned item list on poll. Returns up to 25 `Choice`s — prefix matches first. Not linked / no scans yet → no suggestions (graceful empty).

## Command sync (multi-server)

Non-privileged `guilds` intent is on. With **no** `DISCORD_GUILD_ID`, commands sync per-guild in `on_ready` / `on_guild_join`, so they appear in every server the bot joins. Setting `DISCORD_GUILD_ID` pins commands to one server (instant sync, for dev).

## Running it

```bash
DISCORD_TOKEN=<bot token> RELAY_ADMIN_TOKEN=<same secret the relay uses> python3 cc_discord_bot.py
```

| Var | Default | Meaning |
|---|---|---|
| `DISCORD_TOKEN` | *(required)* | The Discord bot token. |
| `RELAY_ADMIN_TOKEN` | *(required)* | Must **match** the relay's value. |
| `RELAY_URL` | `http://127.0.0.1:8788` | Relay address — localhost (same box), not the public URL. |
| `DISCORD_GUILD_ID` | *(unset)* | Set only for single-server dev; leave empty for the normal model. |

In production it runs as the **`cc-discord-bot`** systemd service — see [../deploy/README.md](../deploy/README.md).

## Keeping the allowlist in sync

`ALLOWED_COMMANDS` here is a UX mirror for `/cmd`'s friendly rejection and `/help`. The **real** guard is `cc_remote.ALLOWED_COMMANDS` / `command_allowed` in the exe — keep the two lists roughly aligned when you add a command.

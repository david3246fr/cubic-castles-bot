# Running the relay + Discord bot as systemd services

This makes the two server-side pieces start on boot and restart on failure:

- **`cc-relay`** — the NAT-friendly relay (`cc_relay.py`), listens on
  localhost, fronted publicly by your own tunnel / reverse proxy.
- **`cc-discord-bot`** — the Discord front-end (`cc_discord_bot.py`), talks to the
  relay over localhost.

Both run **on the Linux PC**, not the Windows dev box. The exe (the game client)
is unrelated and runs on each user's own machine.

> **`cc_relay.py` and `cc_discord_bot.py` are NOT in the GitHub repo** — they are
> server-only and gitignored on purpose. Deliver + update them by copying from the
> dev box, never with `git pull`. From the Windows dev box's `stage2` folder:
>
> ```bash
> scp cc_relay.py cc_discord_bot.py <user>@<your-server>:~/cubic-castles-bot/stage2/
> ```
>
> Only these two are out-of-band; the deploy scripts below and the shared client
> modules stay in git.

## Install

On the Linux PC, once `cc_relay.py` + `cc_discord_bot.py` are in place (see above):

```bash
cd <repo>/stage2/deploy
sudo ./install_services.sh
```

The installer:

1. figures out the repo path, the owning user, and `python3`;
2. drops a secrets template at `/etc/cubic-castles/cubic-castles.env` (only if it
   doesn't exist — it never overwrites your real one);
3. makes sure `discord.py` is importable for the run user;
4. renders and installs both unit files, `daemon-reload`, and `enable`s them;
5. starts them **unless** the env file still has `CHANGE_ME` placeholders.

## Fill in the secrets

Edit `/etc/cubic-castles/cubic-castles.env` (root-only, `chmod 600`):

```bash
sudo nano /etc/cubic-castles/cubic-castles.env   # set RELAY_ADMIN_TOKEN + DISCORD_TOKEN
sudo systemctl restart cc-relay cc-discord-bot
```

- `RELAY_ADMIN_TOKEN` — shared secret; the bot authenticates to the relay with it
  (generate: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`).
- `DISCORD_TOKEN` — the Discord bot token.

Picking up code changes later:

```bash
# from the Windows dev box (stage2 folder): push the updated server files
scp cc_relay.py cc_discord_bot.py <user>@<your-server>:~/cubic-castles-bot/stage2/
# then on the Linux PC: just restart (no re-install needed for code-only changes)
sudo systemctl restart cc-relay cc-discord-bot
```

Re-run `sudo ./install_services.sh` only when the unit templates themselves
change (paths, hardening, a new EnvironmentFile key).

## Everyday commands

```bash
systemctl status cc-relay cc-discord-bot     # health
journalctl -u cc-relay -f                    # follow relay logs
journalctl -u cc-discord-bot -f              # follow bot logs
sudo systemctl restart cc-discord-bot        # restart one
sudo systemctl stop cc-relay cc-discord-bot  # stop both
```

## Exposing the relay publicly

The relay binds to localhost only. Put your own public HTTPS endpoint in front of
it (a tunnel or reverse proxy) so the at-home exe can reach it. That's a separate
service these units don't manage — set it up however you host it.

## Notes

- The units run as the checkout's owner (not root), with light hardening
  (`NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome=read-only`). The relay is
  given write access to its own `stage2` dir for `relay_state.json`; if you point
  `RELAY_STATE_FILE` elsewhere, add that path to `ReadWritePaths=` in
  `cc-relay.service`.
- The env file is shared by both services (the relay ignores `DISCORD_TOKEN`).
- There is deliberately no unlink endpoint; a bot "unlinks" by rotating its
  `bot_id` in the exe.

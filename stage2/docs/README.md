# Remote-control documentation

How the Discord-driven remote control works, one doc per piece:

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — start here. How the three programs fit together, the trust model, and a command's full round trip (with diagrams).
- **[RELAY.md](RELAY.md)** — the relay service (`cc_relay.py`): endpoints, state, permission resolution, running it.
- **[DISCORD_BOT.md](DISCORD_BOT.md)** — the Discord bot (`cc_discord_bot.py`): commands, tiers, autocomplete, running it.
- **[EXE.md](EXE.md)** — the exe (game bot + GUI): builds, login capture, data location, the permission guard.

For **deploying / running the services** (systemd + secrets), see [../deploy/README.md](../deploy/README.md).

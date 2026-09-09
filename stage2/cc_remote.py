#!/usr/bin/env python3
"""
Remote-control client for the exe (Stage 3) — the half that runs on the user's
PC and phones out to the relay.

The exe is behind NAT, so it can only reach OUT. This module runs a background
loop that, while enabled:

    1. POST <relay>/poll  (Bearer bot_id)  -> pick up any queued commands
    2. run each ALLOWED command through the local bot (the executor callback)
    3. POST <relay>/result (Bearer bot_id) -> hand the output back

The Discord user's command therefore arrives ~one poll later, runs on the bot,
and the answer travels back the same way. It also mints the one-time LINK CODE
the GUI shows (POST /linkcode).

SECURITY — this module is the REAL command guard. The Discord bot has its own
allowlist for UX, but a command only actually runs if it passes command_allowed()
HERE, on the machine that would execute it. Keep ALLOWED_COMMANDS tight: read /
lookup / gentle-move commands only, nothing that spends currency, trades, builds,
cracks prizes, snipes, or speaks in chat as the user. The bot_id is a secret and
is sent only in the Authorization header, never logged.

stdlib only (urllib) so it bundles into the frozen exe with no new deps.
"""
import json
import threading
import time
import urllib.error
import urllib.request


# Commands that may be run over Discord, split into two permission tiers. Matched
# on the FIRST word, so "market ruby helm" is allowed via "market". Deliberately
# conservative — add consciously; every entry is something the given tier of
# Discord user could make your bot do.
#
# GUEST = any member of a server where the bot is linked. Per the owner's rule,
# guests may ONLY tell the bot to teleport somewhere to scan a realm, and read
# data back. Nothing that reconfigures the bot or moves it on the owner's behalf.
GUEST_COMMANDS = {
    "guid",       # teleport to a player by name, then auto-scan their realm
    "tp",         # teleport to a known player / GUID (gentle move, no spend)
    "market",     # price lookup: "market <item>"   (data)
    "status",     # connection / realm            (data; special-cased executor)
    "where",      # bot position                  (data)
    "players",    # who's in the realm            (data)
    "friends",    # online friends                (data)
    "dbstats",    # market DB stats               (data)
    "help",
}
# OWNER = the user who LINKED the bot. Everything a guest can do, PLUS the
# controls the owner reserved to themselves: rescan-in-place, park, the move
# queue, and webhook/alert settings.
OWNER_COMMANDS = GUEST_COMMANDS | {
    "scan",       # rescan the realm the bot is sitting in
    "park",       # send it back to the park realm
    "queue",      # view / clear the pending-move queue
    "webhook",    # Discord alert webhook settings
    "hwarp",      # auto-Hollawarp on/off (+ "hwarp cooldown <s>")
    "autowarp",   # alias the console accepts for hwarp
}
# Back-compat alias (some call sites / the Discord mirror import this name): the
# full owner set is the superset of everything runnable remotely.
ALLOWED_COMMANDS = OWNER_COMMANDS


def command_allowed(command, role="owner"):
    """True if `command` may run at permission `role` ("owner" or "guest").

    Special case: a bare `scan` (rescan the current realm) is OWNER-only, but the
    read-only `scan status` / `scan wait` / `scan poll` poll — which a guest's
    `/guid` teleport-and-scan needs to watch for completion — is allowed to
    anyone. Everything else is a plain first-word membership test."""
    parts = (command or "").strip().split(None, 1)
    if not parts:
        return False
    head = parts[0].lower()
    allowed = OWNER_COMMANDS if role == "owner" else GUEST_COMMANDS
    if head == "scan":
        sub = parts[1].strip().lower() if len(parts) > 1 else ""
        if sub in ("status", "wait", "poll"):
            return True                 # read-only scan poll — any tier
        return "scan" in allowed        # bare "scan" / "scan near" — owner only
    return head in allowed


class RelayClient:
    """Thin HTTPS client for the relay. `url_fn` and `bot_id_fn` are callables so
    a rotated bot_id or a re-resolved relay URL is always picked up live."""

    def __init__(self, url_fn, bot_id_fn, timeout=8.0):
        self._url_fn = url_fn
        self._bot_id_fn = bot_id_fn
        self.timeout = timeout

    def _post(self, path, obj):
        base = (self._url_fn() or "").rstrip("/")
        bot_id = (self._bot_id_fn() or "").strip()
        if not base or not bot_id:
            return None, "not_configured"
        data = json.dumps(obj or {}).encode("utf-8")
        req = urllib.request.Request(base + path, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        # A real User-Agent: the default "Python-urllib/x" can trip bot rules on
        # the public endpoint (403 before the request ever reaches the relay).
        req.add_header("User-Agent", "CubicBot/1.0 (+relay-client)")
        req.add_header("Authorization", f"Bearer {bot_id}")   # secret, header only
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8", "replace")), None
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode("utf-8", "replace"))
            except Exception:
                body = {}
            return body, f"http_{e.code}"
        except Exception:
            return None, "unreachable"

    def poll(self, items=None):
        # Optionally piggyback the scanned item-name list so the relay can serve
        # /market autocomplete. Omitted on most polls (throttled by the worker).
        return self._post("/poll", {} if items is None else {"items": items})

    def post_result(self, cmd_id, output, ok):
        return self._post("/result",
                          {"id": cmd_id, "output": output, "ok": bool(ok)})

    def request_linkcode(self):
        return self._post("/linkcode", {})


class RemoteWorker:
    """Background poll loop. Runs its thread the whole time but only talks to the
    relay while `enabled` — the feature stays fully off until the user opts in.

    executor(command) -> (ok: bool, output: str) is supplied by the GUI; it is
    what actually drives the local bot. on_status(resp) is called with each poll
    response so the GUI can reflect link state; both may run on this worker
    thread, so a GUI must marshal them onto its own loop.
    """

    def __init__(self, client, executor, on_status=None, interval=3.0,
                 items_provider=None):
        self.client = client
        self.executor = executor
        self.on_status = on_status
        self.interval = interval
        # items_provider() -> list[str] | None. Called at most every
        # items_period seconds; its result is pushed to the relay for /market
        # autocomplete. Keeping it periodic (not every poll) avoids shipping the
        # whole catalogue through the tunnel every few seconds.
        self.items_provider = items_provider
        self.items_period = 30.0
        self._last_items_push = 0.0
        self._enabled = threading.Event()
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def enable(self, on):
        if on:
            self._enabled.set()
        else:
            self._enabled.clear()

    def is_enabled(self):
        return self._enabled.is_set()

    def stop(self):
        self._stop.set()
        self._enabled.clear()

    def _run(self):
        while not self._stop.is_set():
            if self._enabled.is_set():
                try:
                    self._tick_once()
                except Exception:
                    pass                      # a bad tick must never kill the loop
            self._stop.wait(self.interval)

    def _tick_once(self):
        # Periodically attach the scanned item list to this poll (for autocomplete).
        items = None
        if self.items_provider and (
                time.time() - self._last_items_push) >= self.items_period:
            try:
                items = self.items_provider()
            except Exception:
                items = None
            if items is not None:
                self._last_items_push = time.time()
        resp, err = self.client.poll(items)
        if err or not resp:
            return
        if self.on_status:
            try:
                self.on_status(resp)
            except Exception:
                pass
        for c in resp.get("commands", []) or []:
            cmd_id = c.get("id")
            command = (c.get("command") or "").strip()
            role = (c.get("role") or "owner").lower()   # relay-tagged; trusted
            if not cmd_id:
                continue
            if not command_allowed(command, role):
                head = command.split(None, 1)[0] if command else "(empty)"
                # If a guest asked for something only the owner may do, say so —
                # otherwise it's simply not a remotely-runnable command.
                if role != "owner" and command_allowed(command, "owner"):
                    msg = (f"🔒 `{head}` is for the bot's owner only. As a guest "
                           f"you can teleport the bot to scan a realm (guid/tp) "
                           f"and read data (market/status/where/players/friends/"
                           f"dbstats).")
                else:
                    msg = f"Command not allowed over Discord: {head}"
                self.client.post_result(cmd_id, msg, False)
                continue
            try:
                ok, out = self.executor(command)
            except Exception as e:
                ok, out = False, f"error running command: {e}"
            self.client.post_result(cmd_id, (out or "(no output)")[:1800], bool(ok))

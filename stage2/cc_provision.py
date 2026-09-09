#!/usr/bin/env python3
"""
First-run login provisioning for the packaged bot exe.

The bot authenticates by replaying the two cleartext login frames the official
client sends (hello_empty + hello_auth); hello_auth carries the account token.
Instead of shipping one baked-in account, the exe captures those frames from
whoever runs it:

    1. They open Cubic Castles (via Steam) and sit at the title screen.
    2. They run the exe and choose "attach".
    3. This module attaches Frida to Cubic.exe and starts recording frames.
    4. They log in normally in the game.
    5. They come back and press ENTER ("stop").
    6. We pull hello_empty/hello_auth out of what we captured and write the
       profile next to the exe, so every later run just uses it.

This is deliberately NOT the full cc_capture.py checklist driver — it only needs
the login handshake, so there is no F9 stepping and NO redaction (redaction would
mask the very token the profile must keep).
"""
import json
import os
import secrets
import struct
import sys
import threading
import time


AGENT_NAME = "nopoll_agent.js"
GAME_EXE = "Cubic.exe"
# Default install path; overridable so a different Steam library still works.
DEFAULT_GAME_DIR = r"D:\SteamLibrary\steamapps\common\Cubic Castles"


def resource_path(name):
    """Locate a bundled data file both when frozen (PyInstaller) and from src."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        p = os.path.join(meipass, name)
        if os.path.exists(p):
            return p
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name)


def exe_dir():
    """Directory the .exe itself sits in (when frozen), else the script dir."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def app_dir():
    """Stable per-user data folder shared with cc_client's _APP_DIR.

    Frozen: %APPDATA%\\CubicBot (created). Dev: next to this script. The login
    profile and all bot state live here so a --onefile temp unpack never eats
    them.
    """
    if getattr(sys, "frozen", False):
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        target = os.path.join(base, "CubicBot")
        try:
            os.makedirs(target, exist_ok=True)
            return target
        except OSError:
            return exe_dir()
    return os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------
# remote control (Discord relay) — local identity + config, stdlib only
# --------------------------------------------------------------------------
#
# VERIFICATION MODEL (read before touching this):
#   * bot_id is this exe's PASSWORD to the relay. It authenticates the
#     exe<->relay channel ONLY and must NEVER appear in Discord, in a log, or
#     in an alert. It is generated once, on first run, and lives only on this
#     PC in %APPDATA%\CubicBot\bot_id.json.
#   * "Which exe is yours?" is later proven to Discord by a one-time link CODE
#     that is shown only inside this exe's own GUI window (Stage 2+). The code
#     is single-use and short-lived, which is what makes the binding safe; the
#     bot_id itself is never the thing typed into Discord.
#   * "Who are you on Discord?" is supplied by Discord on every slash command.
#
# Stage 1 is deliberately LOCAL-ONLY: we generate + persist the bot_id and the
# remote config here, and the GUI shows them. No network call is made yet.

# Where the exe finds the relay. Regular users never see or type any of this.
# Set ONE of the two constants below, ONCE, before building the exe:
#
#   RELAY_DISCOVERY_URL  (recommended) — a STABLE public URL you control whose
#       body is just the CURRENT relay address. The exe fetches it at startup to
#       discover where the relay is right now, so you can move/rename the relay
#       anytime by editing that one file — NO rebuild, every exe follows. The
#       body may be plain text (the URL on its own line) or JSON
#       {"relay_url": "https://..."} . Host it anywhere stable you can edit: a
#       public gist's raw URL, an S3 object, a path on your own site, etc.
#
#   DEFAULT_RELAY_URL  — a direct relay URL baked straight in. Simplest, but if
#       it ever changes you must rebuild. Good when the relay has a permanent
#       hostname on your own domain.
#
# Resolution order at runtime: CUBICBOT_RELAY_URL env override (operator local
# testing only) > last value discovered from RELAY_DISCOVERY_URL (cached in
# remote.json, so a discovery outage still works) > DEFAULT_RELAY_URL. Blank
# everywhere => remote feature OFF (the Link button says so).
# Backend endpoints below are stored OBFUSCATED (XOR + base64) via _veil() rather
# than as plaintext, so hostnames / ids aren't visible in the source or the built
# exe. To point at a different relay or bot, encode the new value the same way.
_VEIL_KEY = b"cc-veil-7f3a"


def _veil(blob):
    import base64
    raw = base64.b64decode(blob)
    return bytes(c ^ _VEIL_KEY[i % len(_VEIL_KEY)]
                 for i, c in enumerate(raw)).decode()


# The bot's Discord invite link, baked in (obfuscated). The exe shows it so a user
# can add the bot to their Discord server BEFORE linking (a link code is useless if
# the bot isn't in a server they can run /link in). Blank => the exe skips the
# "add the bot" step. To use your own bot, _veil-encode its invite URL here.
DISCORD_INVITE_URL = _veil("CxdZBhZTQwJTD0ACDBFJWAYGAQJYB0YVC1ECFxAdBEJFD0kEXABBHwAHGHJeAg5QVlcYQ1BaXB4DUQRZVFQcQ1VfSl5UCUMEXgFCAk4IHF1bD1AAFwpCGBZHD0JaC1IPBxALBgAbAUREFVoODRAQRg==")

RELAY_DISCOVERY_URL = ""

DEFAULT_RELAY_URL = _veil("CxdZBhZTQwJFA18AGk1fGQodH15SFEUEERADFQoE")


def _looks_like_url(u):
    u = (u or "").strip().lower()
    return u.startswith("http://") or u.startswith("https://")


def _parse_pointer(raw):
    """A discovery-pointer body -> a relay URL. Accepts JSON {"relay_url": ...}
    or plain text (first non-empty line)."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    try:
        d = json.loads(raw)
        if isinstance(d, dict):
            return (d.get("relay_url") or "").strip()
    except ValueError:
        pass
    for line in raw.splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _read_cached_relay():
    try:
        with open(remote_config_path(), "r", encoding="utf-8") as fh:
            return (json.load(fh).get("cached_relay_url") or "").strip()
    except (OSError, ValueError):
        return ""


def effective_relay_url():
    """The relay URL to use RIGHT NOW, without any network call: env override,
    else the last-discovered value cached in remote.json, else the baked-in
    direct default. Safe to call from the UI thread."""
    env = (os.environ.get("CUBICBOT_RELAY_URL") or "").strip()
    if env:
        return env
    return _read_cached_relay() or DEFAULT_RELAY_URL


def refresh_relay_url(timeout=4.0):
    """Re-resolve the relay via the discovery pointer and cache the result, then
    return the current URL. Does a network fetch, so call it off the UI thread.
    Any failure falls back to effective_relay_url() (cache/default), so a
    discovery outage never breaks a bot that already knows where the relay is."""
    env = (os.environ.get("CUBICBOT_RELAY_URL") or "").strip()
    if env:
        return env
    disc = (RELAY_DISCOVERY_URL or "").strip()
    if not disc:
        return DEFAULT_RELAY_URL or effective_relay_url()
    try:
        import urllib.request
        raw = urllib.request.urlopen(disc, timeout=timeout).read()
        url = _parse_pointer(raw.decode("utf-8", "replace"))
        if _looks_like_url(url):
            cfg = load_remote_config()
            cfg["cached_relay_url"] = url
            save_remote_config(cfg)
            return url
    except Exception:
        pass                       # keep using whatever we already had
    return effective_relay_url()

BOT_ID_NAME = "bot_id.json"
REMOTE_CFG_NAME = "remote.json"


def bot_id_path():
    return os.path.join(app_dir(), BOT_ID_NAME)


def _write_private(path, text):
    """Write a small secret file as privately as the OS lets us. On POSIX the
    file is created 0600; on Windows the %APPDATA% profile is already per-user,
    so default ACLs are fine. Errors are swallowed by callers."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        raise


def read_bot_id():
    """Return the saved bot_id, or None if this exe has never generated one.
    Never creates the file (use get_or_create_bot_id for that)."""
    try:
        with open(bot_id_path(), "r", encoding="utf-8") as fh:
            bid = (json.load(fh).get("bot_id") or "").strip()
            return bid or None
    except (OSError, ValueError):
        return None


def _save_bot_id(bid):
    try:
        _write_private(bot_id_path(), json.dumps({"bot_id": bid}, indent=1))
    except OSError:
        # Couldn't persist (read-only dir?). Still usable this session.
        pass


def get_or_create_bot_id():
    """The exe's secret relay password. Generated once with a strong CSPRNG and
    persisted; every later run returns the same value. Treat like a password:
    never log it, never send it to Discord."""
    existing = read_bot_id()
    if existing:
        return existing
    bid = secrets.token_urlsafe(24)
    _save_bot_id(bid)
    return bid


def rotate_bot_id():
    """Generate a fresh bot_id, replacing the old one. This is how the exe
    UNLINKS: the relay's old binding then points at an id that never polls again
    and is inert, so the Discord user is disconnected until they link afresh.
    Returns the new id."""
    bid = secrets.token_urlsafe(24)
    _save_bot_id(bid)
    return bid


def remote_config_path():
    return os.path.join(app_dir(), REMOTE_CFG_NAME)


def load_remote_config():
    """Local remote-control settings. The relay URL is NOT user-configurable —
    it always comes from effective_relay_url() (baked-in build constant / operator
    env override). Only `linked` (set once the exe links to a Discord user via the
    relay) and `enabled` are persisted per install."""
    cfg = {"relay_url": effective_relay_url(), "enabled": False,
           "linked": None, "cached_relay_url": "", "invite_ack": False}
    try:
        with open(remote_config_path(), "r", encoding="utf-8") as fh:
            d = json.load(fh)
        if isinstance(d, dict):
            cfg["enabled"] = bool(d.get("enabled", False))
            cfg["linked"] = d.get("linked") or None
            cfg["cached_relay_url"] = (d.get("cached_relay_url") or "").strip()
            cfg["invite_ack"] = bool(d.get("invite_ack", False))
    except (OSError, ValueError):
        pass
    return cfg


def save_remote_config(cfg):
    """Persist the remote config; returns True on success. The configured relay
    address (build constant / discovery pointer) is not per-install state, but
    the last value DISCOVERED from the pointer is cached here so a discovery
    outage still works. The bot_id is never written here (own file)."""
    data = {"enabled": bool(cfg.get("enabled", False)),
            "linked": cfg.get("linked") or None,
            "cached_relay_url": (cfg.get("cached_relay_url") or "").strip(),
            "invite_ack": bool(cfg.get("invite_ack", False))}
    try:
        with open(remote_config_path(), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# login-frame extraction (same rule as cc_login.py)
# --------------------------------------------------------------------------

def _strings_in(b):
    out = []
    i = 0
    while i + 4 <= len(b):
        n = struct.unpack_from("<I", b, i)[0]
        if 1 <= n <= 80 and i + 4 + n <= len(b):
            s = b[i + 4:i + 4 + n].rstrip(b"\x00")
            if s and all(32 <= c < 127 for c in s):
                out.append(s.decode("latin1"))
                i += 4 + n
                continue
        i += 1
    return out


def build_profile(tx_frames):
    """Find the two login frames in captured tx frames and build a profile dict.

    Returns None if both login frames were not seen (e.g. they attached after
    logging in, or the login never happened).
    """
    hello_empty = hello_auth = None
    for b in tx_frames:
        if len(b) >= 8 and b[:2] == b"\x02\x00":
            toklen = struct.unpack_from("<I", b, 2)[0]
            if toklen <= 1 and hello_empty is None:
                hello_empty = b
            elif toklen > 1 and hello_auth is None:
                hello_auth = b
        if hello_empty and hello_auth:
            break

    if not (hello_empty and hello_auth):
        return None

    strs = _strings_in(hello_auth)
    return {
        "hello_empty": hello_empty.hex(),
        "hello_auth": hello_auth.hex(),
        "identity": {
            "token": strs[0] if strs else None,
            "display_name": strs[1] if len(strs) > 1 else None,
            "account_id": strs[2] if len(strs) > 2 else None,
            "steam_id": strs[-1] if strs else None,
        },
    }


# --------------------------------------------------------------------------
# live capture of the login handshake via Frida
# --------------------------------------------------------------------------

def _list_game_procs(frida):
    try:
        procs = frida.get_local_device().enumerate_processes()
    except Exception:
        try:
            procs = frida.enumerate_processes()
        except Exception:
            return []
    return [p for p in procs if p.name.lower() == GAME_EXE.lower()]


def list_game_pids():
    """Return [pid, ...] of running Cubic.exe processes (empty if none/frida
    missing). Used by the GUI to decide whether setup can proceed."""
    try:
        import frida
    except ImportError:
        return []
    return [p.pid for p in _list_game_procs(frida)]


class LoginCapture:
    """GUI-driveable version of the login capture.

    Attach to a running Cubic.exe and start collecting tx frames immediately.
    The caller lets the user log in, polls has_login(), then calls stop() and
    build() — no console input() anywhere, so a Tkinter button can drive it.
    """

    def __init__(self, pid=None):
        self.error = None
        self._session = None
        self._frames = []
        self._lock = threading.Lock()
        self._attach(pid)

    def _attach(self, pid):
        try:
            import frida
        except ImportError:
            self.error = "frida is not available in this build."
            return
        agent = resource_path(AGENT_NAME)
        if not os.path.exists(agent):
            self.error = f"capture agent not found ({AGENT_NAME})."
            return
        if pid is None:
            pids = [p.pid for p in _list_game_procs(frida)]
            if not pids:
                self.error = ("Cubic.exe is not running. Open Cubic Castles via "
                              "Steam, sit at the login screen, then try again.")
                return
            pid = pids[0]
        try:
            self._session = frida.attach(pid)
            with open(agent, "r", encoding="utf-8") as fh:
                source = fh.read()
            script = self._session.create_script(source)
            script.on("message", self._on_message)
            script.load()
        except Exception as exc:
            self.error = f"could not attach/inject: {exc}"
            self._session = None

    def _on_message(self, message, data):
        if message.get("type") == "error":
            return
        p = message.get("payload") or {}
        if p.get("type") == "frame" and p.get("dir") == "tx" and data:
            with self._lock:
                self._frames.append(bytes(data))

    @property
    def attached(self):
        return self._session is not None and self.error is None

    def has_login(self):
        """True once both login frames have been captured."""
        with self._lock:
            return build_profile(self._frames) is not None

    def build(self):
        with self._lock:
            return build_profile(list(self._frames))

    def stop(self):
        if self._session is not None:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None


def capture_login(game_dir=None, pid=None):
    """Attach to Cubic.exe, record tx frames until the user presses ENTER, and
    return the list of captured tx frame bytes. Returns None on a hard failure.
    """
    try:
        import frida
    except ImportError:
        print("  ERROR: frida is not available in this build.")
        return None

    agent = resource_path(AGENT_NAME)
    if not os.path.exists(agent):
        print(f"  ERROR: capture agent not found ({AGENT_NAME}).")
        return None

    procs = _list_game_procs(frida)
    if pid is None:
        if not procs:
            print("  Cubic.exe is not running.")
            print("  Open Cubic Castles (via Steam) and sit at the title/login")
            print("  screen, THEN run this again and choose attach.")
            return None
        if len(procs) > 1:
            print("  More than one Cubic.exe is running:")
            for p in procs:
                print(f"     pid {p.pid}")
            try:
                pid = int(input("  Type the pid to attach to: ").strip())
            except (ValueError, EOFError):
                print("  no pid chosen.")
                return None
        else:
            pid = procs[0].pid

    tx_frames = []
    got = {"login": False}
    lock = threading.Lock()

    def on_message(message, data):
        if message.get("type") == "error":
            return
        p = message.get("payload") or {}
        if p.get("type") == "frame" and p.get("dir") == "tx" and data:
            with lock:
                tx_frames.append(bytes(data))
                # Flag the moment we have both login frames so the prompt can hint.
                if not got["login"] and build_profile(tx_frames):
                    got["login"] = True
                    print("\n  >> login handshake captured. Press ENTER here to "
                          "finish. <<\n", flush=True)

    try:
        print(f"  attaching to Cubic.exe (pid {pid}) ...")
        session = frida.attach(pid)
        with open(agent, "r", encoding="utf-8") as fh:
            source = fh.read()
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
    except Exception as exc:
        print(f"  ERROR: could not attach/inject: {exc}")
        return None

    print("  attached. Now LOG IN inside the game.")
    print("  When you are in the world, come back here and press ENTER to stop.")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass

    try:
        session.detach()
    except Exception:
        pass

    with lock:
        return list(tx_frames)


def provision(profile_path, game_dir=None):
    """Run the whole first-time setup: capture a login and save the profile.

    Returns True on success (profile written), False otherwise.
    """
    print("=" * 66)
    print(" First-time setup: capture this account's login")
    print("=" * 66)
    print(" 1. Make sure Cubic Castles is OPEN (via Steam) at the login screen.")
    print(" 2. Press ENTER here to attach to the game.")
    print(" 3. Log in normally in the game.")
    print(" 4. Come back here and press ENTER to finish.")
    print("-" * 66)
    try:
        input(" Ready? Press ENTER to attach... ")
    except (EOFError, KeyboardInterrupt):
        return False

    tx_frames = capture_login(game_dir=game_dir)
    if not tx_frames:
        return False

    prof = build_profile(tx_frames)
    if not prof:
        print("\n  Could not find the login frames in what was captured.")
        print("  This usually means you attached AFTER logging in. Restart the")
        print("  game, run setup again, and log in only after attaching.")
        return False

    with open(profile_path, "w", encoding="utf-8") as fh:
        json.dump(prof, fh, indent=2)

    ident = prof["identity"]
    print("\n" + "=" * 66)
    print(f"  Saved login for: {ident.get('display_name')} "
          f"({ident.get('account_id')})")
    print(f"  Profile written to: {profile_path}")
    print("  From now on this exe will use it automatically.")
    print("=" * 66 + "\n")
    return True

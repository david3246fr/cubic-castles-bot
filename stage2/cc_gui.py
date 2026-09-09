#!/usr/bin/env python3
"""
Native desktop GUI for the Cubic Castles bot (Tkinter, no third-party deps).

A thin, modern control panel around the EXISTING bot: Start launches the bot as
a headless child process with its local web-control server on (127.0.0.1, random
token), and every panel drives that server's HTTP API — the same one the in-game
web console uses:

    /status            connection + account + realm
    /logs?since=N      the rolling essentials log (the live Logs pane)
    /cmd?line=...       run ANY console command (market search, scan, quit, ...)
    /scan /hwarp /park  one-click actions

All bot state (market DB, watchlist, login profile, ...) lives in
%APPDATA%\\CubicBot via cc_client's _APP_DIR, so nothing is lost when the
--onefile exe's temp dir is cleaned up.
"""
import json
import os
import queue
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser

import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import font as tkfont

import cc_provision
import cc_remote


PROFILE_NAME = "cc_profile.json"

# Log lines the bot emits continuously regardless of any command — live chat,
# whispers, server join/leave, realm-entry and dialog notices. They share the
# one log stream with command output, so remote command results filter them out.
_AMBIENT_LOG_TAGS = ("[chat]", "[whisper]", "[server]", "[realm]", "[dialog]")


def _is_ambient_log(text):
    s = (text or "").lstrip().lower()
    return any(s.startswith(tag) for tag in _AMBIENT_LOG_TAGS)


def _log_tag_for(text):
    """Which colour tag (if any) a log line should be drawn with. Category-codes
    the shared log stream so chat, whispers, server and dialog notices read apart
    from plain output, and echoes the user's own commands in the accent colour."""
    s = (text or "").lstrip().lower()
    if s.startswith("> ") or s.startswith("›") or s.startswith("---"):
        return "cmd"
    for tag in ("chat", "whisper", "server", "realm", "dialog"):
        if s.startswith("[" + tag + "]"):
            return tag
    return None

# --- palette (dark slate + grassy Cubic Castles colour) -------------------
BG        = "#0f1420"   # app background (deep slate-navy)
SIDEBAR   = "#141b29"   # slightly raised bands
SURFACE   = "#18202f"   # cards / bars
SURFACE2  = "#212c40"   # raised chips / hover
FIELD     = "#0b0f18"   # input interior / console
BORDER    = "#2c3852"
TEXT      = "#eef3fb"
MUTED     = "#93a1bd"
ACCENT    = "#2fd07a"   # bright grass green (primary)
ACCENT_H  = "#48e08d"   # green hover
INK       = "#08210f"   # dark text that sits on the green/gold accents
GOLD      = "#ffc53d"   # secondary (cubits / coins)
GOLD_H    = "#ffd464"
SUCCESS   = "#2fd07a"
WARN      = "#ffb020"
DANGER    = "#ff5d6c"
DANGER_H  = "#ff7480"
CONSOLE_BG = "#0b0f18"

# category-coded log line colours (readability in the shared log stream)
LOG_CHAT    = "#5bc8ff"   # public chat
LOG_WHISPER = "#c79bff"   # whispers
LOG_SERVER  = "#8698ba"   # join/leave, server notices
LOG_REALM   = "#2fd07a"   # realm entry
LOG_DIALOG  = "#ffc53d"   # dialogs / prompts
LOG_CMD     = "#5bc8ff"   # the user's own command echoes / section rules

# monochrome tab glyphs (render cleanly in Segoe UI on Windows)
NAV_ICONS = {"Logs": "≡", "Market": "⚑", "Scan": "◎", "Controls": "⚙",
             "Status": "◈", "Remote": "⇄"}


def _is_full_build():
    """FULL build = the everything version (adds the Controls tab: teleport,
    park realm, ...). Decided by the exe's own filename (cubic-bot-full.exe), so
    ONE codebase produces both exes. Running from source is always full so
    everything is testable in dev."""
    try:
        if getattr(sys, "frozen", False):
            return "full" in os.path.basename(sys.executable).lower()
    except Exception:
        pass
    return True


FULL = _is_full_build()


# --------------------------------------------------------------------------
# profile location (AppData), with migrate from older builds
# --------------------------------------------------------------------------

def profile_path():
    return os.path.join(cc_provision.app_dir(), PROFILE_NAME)


def _migrate_profile():
    new = profile_path()
    if os.path.exists(new):
        return
    old = os.path.join(cc_provision.exe_dir(), PROFILE_NAME)
    if os.path.exists(old):
        try:
            with open(old, "r", encoding="utf-8") as fh:
                data = fh.read()
            with open(new, "w", encoding="utf-8") as fh:
                fh.write(data)
        except OSError:
            pass


def load_identity():
    try:
        with open(profile_path(), "r", encoding="utf-8") as fh:
            return json.load(fh).get("identity", {})
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# rounded, soft widgets (canvas-drawn: buttons, inputs, chips)
# --------------------------------------------------------------------------

# kind -> (fill, hover-fill, text-colour)
BTN_COLORS = {
    "accent":    (ACCENT, ACCENT_H, INK),
    "gold":      (GOLD, GOLD_H, INK),
    "danger":    (DANGER, DANGER_H, "#ffffff"),
    "secondary": (SURFACE2, BORDER, TEXT),
    "ghost":     (SURFACE, SURFACE2, MUTED),
}


def _round_rect(c, x1, y1, x2, y2, r, **kw):
    """Draw a rounded rectangle on canvas c via a smoothed polygon."""
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
           x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
           x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return c.create_polygon(pts, smooth=True, **kw)


class RoundedButton(tk.Canvas):
    """A soft, rounded button drawn on a canvas. Exposes just enough of the
    tk.Button surface (config/cget of text+state, __getitem__) that the rest of
    the app can drive it exactly as it drove the old flat buttons."""

    def __init__(self, parent, text="", command=None, kind="secondary",
                 padx=16, pady=9, radius=11, font=None):
        self._pbg = parent.cget("bg")
        self._font = tkfont.Font(font=font or ("Segoe UI", 10, "bold"))
        self._text = text
        self._cmd = command
        self._kind = kind
        self._radius = radius
        self._padx, self._pady = padx, pady
        self._state = "normal"
        self._hover = self._press = False
        w, h = self._measure()
        super().__init__(parent, width=w, height=h, bg=self._pbg,
                         highlightthickness=0, bd=0, cursor="hand2")
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
        self._draw()

    def _measure(self):
        return (self._font.measure(self._text) + 2 * self._padx,
                self._font.metrics("linespace") + 2 * self._pady)

    def _fill_fg(self):
        fill, hover, fg = BTN_COLORS.get(self._kind, BTN_COLORS["secondary"])
        if self._state == "disabled":
            return SURFACE2, MUTED
        if self._hover or self._press:
            return hover, fg
        return fill, fg

    def _draw(self):
        self.delete("all")
        w = int(self["width"]); h = int(self["height"])
        off = 1 if self._press else 0
        fill, fg = self._fill_fg()
        _round_rect(self, 1, 1, w - 1, h - 1, self._radius, fill=fill,
                    outline=fill)
        self.create_text(w / 2, h / 2 + 1 + off, text=self._text, fill=fg,
                         font=self._font)

    # tk-Button-compatible surface -----------------------------------
    def configure(self, cnf=None, **kw):
        if cnf:
            kw.update(cnf)
        redraw = resize = False
        if "text" in kw:
            self._text = kw.pop("text"); redraw = resize = True
        if "state" in kw:
            self._state = str(kw.pop("state")); redraw = True
            super().configure(
                cursor="arrow" if self._state == "disabled" else "hand2")
        if "command" in kw:
            self._cmd = kw.pop("command")
        result = super().configure(**kw) if kw else None
        if resize:
            w, h = self._measure(); super().configure(width=w, height=h)
        if redraw:
            self._draw()
        return result
    config = configure

    def __getitem__(self, key):
        if key in ("text", "state"):
            return getattr(self, "_" + key)
        return super().__getitem__(key)

    def cget(self, key):
        if key in ("text", "state"):
            return getattr(self, "_" + key)
        return super().cget(key)

    def set_kind(self, kind):
        self._kind = kind
        self._draw()

    # events ----------------------------------------------------------
    def _on_enter(self, _):
        if self._state != "disabled":
            self._hover = True; self._draw()

    def _on_leave(self, _):
        self._hover = self._press = False; self._draw()

    def _on_press(self, _):
        if self._state != "disabled":
            self._press = True; self._draw()

    def _on_release(self, e):
        was = self._press
        self._press = False; self._draw()
        if (was and self._state != "disabled" and self._cmd
                and 0 <= e.x <= int(self["width"])
                and 0 <= e.y <= int(self["height"])):
            self._cmd()


class RoundedEntry(tk.Frame):
    """A rounded input field: a tk.Entry floated on a canvas whose rounded
    rectangle forms the visible border (green when focused). Proxies the few
    Entry methods the app calls (get/insert/delete/bind/focus_set)."""

    def __init__(self, parent, height=38, radius=11, font=None):
        self._pbg = parent.cget("bg")
        super().__init__(parent, bg=self._pbg)
        self._radius = radius
        self._focused = False
        self.canvas = tk.Canvas(self, height=height, bg=self._pbg,
                                highlightthickness=0, bd=0)
        self.canvas.pack(fill="both", expand=True)
        self.entry = tk.Entry(self.canvas, bd=0, relief="flat", bg=FIELD,
                              fg=TEXT, disabledbackground=FIELD,
                              insertbackground=ACCENT,
                              font=font or ("Segoe UI", 10),
                              highlightthickness=0)
        self._win = self.canvas.create_window(0, 0, window=self.entry,
                                              anchor="w")
        self.canvas.bind("<Configure>", self._redraw)
        self.entry.bind("<FocusIn>", self._focus(True))
        self.entry.bind("<FocusOut>", self._focus(False))

    def _focus(self, on):
        def handler(_):
            self._focused = on
            self._redraw()
        return handler

    def _redraw(self, _=None):
        c = self.canvas
        c.delete("box")
        w = c.winfo_width(); h = c.winfo_height()
        if w <= 1:
            return
        _round_rect(c, 1, 1, w - 1, h - 1, self._radius, fill=FIELD,
                    outline=ACCENT if self._focused else BORDER, width=2,
                    tags="box")
        c.tag_lower("box")
        pad = 13
        c.coords(self._win, pad, h / 2)
        c.itemconfigure(self._win, width=max(1, w - 2 * pad))

    def get(self):
        return self.entry.get()

    def delete(self, *a):
        return self.entry.delete(*a)

    def insert(self, *a):
        return self.entry.insert(*a)

    def bind(self, *a, **k):
        return self.entry.bind(*a, **k)

    def focus_set(self):
        return self.entry.focus_set()


def make_button(parent, text, command, kind="secondary", **kw):
    return RoundedButton(parent, text=text, command=command, kind=kind,
                         padx=kw.pop("padx", 16), pady=kw.pop("pady", 9))


def set_button_kind(b, kind):
    b.set_kind(kind)


def make_panel(parent, padx=20, pady=18, radius=14, inset=3, outline=BORDER):
    """A rounded card. Returns (holder, body): pack/grid the holder, and put
    content into body (a normal Frame, bg=SURFACE, with internal padding)."""
    bg = parent.cget("bg")
    cv = tk.Canvas(parent, bg=bg, highlightthickness=0, bd=0)
    body = tk.Frame(cv, bg=SURFACE, padx=padx, pady=pady)
    win = cv.create_window(inset, inset, window=body, anchor="nw")

    def resync(_=None):
        cv.configure(height=body.winfo_reqheight() + 2 * inset)

    def on_cfg(e):
        cv.itemconfigure(win, width=e.width - 2 * inset)
        cv.delete("panel")
        _round_rect(cv, 1, 1, e.width - 1, e.height - 1, radius,
                    fill=SURFACE, outline=outline, width=1.5, tags="panel")
        cv.tag_lower("panel")
    body.bind("<Configure>", resync)
    cv.bind("<Configure>", on_cfg)
    return cv, body


# --------------------------------------------------------------------------
# bot subprocess + HTTP control
# --------------------------------------------------------------------------

def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class BotController:
    def __init__(self):
        self.proc = None
        self.port = None
        self.token = None
        self._logfh = None

    def is_running(self):
        return self.proc is not None and self.proc.poll() is None

    def _child_cmd(self, prof):
        common = ["live", "--i-accept-live-risk",
                  "--login-from", prof,
                  "--control-host", "127.0.0.1",
                  "--control-port", str(self.port),
                  "--control-token", self.token,
                  "--command-fifo", "",
                  "--headless"]        # no keyboard input: a windowed exe has no
                                       # console, so the input path would spin and
                                       # flood the log (and never run commands)
        if not FULL:
            # Simple build: lock the bot to the core feature set (teleport/nav,
            # guid, vend/market scanning, Discord). The child enforces it on
            # EVERY command path (command box, /cmd, /runcmd, remote).
            common.append("--simple")
        if getattr(sys, "frozen", False):
            return [sys.executable] + common
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "cc_client.py")
        return [sys.executable, script] + common

    def start(self):
        if self.is_running():
            return
        prof = profile_path()
        if not os.path.exists(prof):
            raise RuntimeError("no saved login (run setup first)")
        self.port = _free_port()
        self.token = secrets.token_hex(8)
        logpath = os.path.join(cc_provision.app_dir(), "bot.stdout.log")
        # Safety: never let this debug log grow without bound (a misbehaving bot
        # could otherwise fill the disk). Start fresh if it's already large.
        try:
            if os.path.exists(logpath) and os.path.getsize(logpath) > 50 * 1024 * 1024:
                os.remove(logpath)
        except OSError:
            pass
        self._logfh = open(logpath, "a", encoding="utf-8", errors="replace")
        self._logfh.write(f"\n===== bot start {time.strftime('%Y-%m-%d %H:%M:%S')} "
                          f"port={self.port} =====\n")
        self._logfh.flush()
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.proc = subprocess.Popen(
            self._child_cmd(prof),
            stdin=subprocess.DEVNULL,
            stdout=self._logfh, stderr=subprocess.STDOUT,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            creationflags=creationflags,
        )

    def stop(self, timeout=6.0):
        if not self.is_running():
            self._cleanup()
            return
        try:
            self.cmd("quit")
        except Exception:
            pass
        end = time.time() + timeout
        while time.time() < end and self.is_running():
            time.sleep(0.15)
        if self.is_running():
            try:
                self.proc.terminate()
            except Exception:
                pass
            try:
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self._cleanup()

    def _cleanup(self):
        if self._logfh is not None:
            try:
                self._logfh.close()
            except Exception:
                pass
            self._logfh = None

    def _url(self, path, params=None):
        q = dict(params or {})
        if self.token:
            q["token"] = self.token
        return f"http://127.0.0.1:{self.port}{path}?" + urllib.parse.urlencode(q)

    def _get(self, path, params=None, timeout=4.0):
        try:
            with urllib.request.urlopen(self._url(path, params),
                                        timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            return None

    def status(self):
        return self._get("/status")

    def logs(self, since):
        return self._get("/logs", {"since": since})

    def cmd(self, line):
        return self._get("/cmd", {"line": line})

    def runcmd(self, line):
        # Run a command and get back ONLY the lines it produced (precise capture
        # for remote control). Longer timeout since the bot waits for output.
        return self._get("/runcmd", {"line": line}, timeout=12.0)

    def scan(self):
        return self._get("/scan")

    def scanstatus(self):
        return self._get("/scanstatus")

    def items(self):
        return self._get("/items")

    def hwarp(self, on):
        return self._get("/hwarp", {"on": "1" if on else "0"})

    def park(self):
        return self._get("/park")


# --------------------------------------------------------------------------
# setup dialog (first run)
# --------------------------------------------------------------------------

class SetupDialog(tk.Toplevel):
    def __init__(self, master, on_done):
        super().__init__(master)
        self.title("Set up login")
        self.configure(bg=BG)
        self.on_done = on_done
        self.capture = None
        self.geometry("560x380")
        self.resizable(False, False)
        self._poll_job = None

        wrap = tk.Frame(self, bg=BG, padx=26, pady=22)
        wrap.pack(fill="both", expand=True)
        tk.Label(wrap, text="One-time login capture", bg=BG, fg=TEXT,
                 font=("Segoe UI", 15, "bold")).pack(anchor="w")
        tk.Label(wrap, text="Nothing is stored until you finish. Your login "
                            "token is saved only on this PC.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w",
                                                             pady=(2, 16))
        steps = ("1.   Open Cubic Castles via Steam — sit at the login screen.\n\n"
                 "2.   Click  Attach to game  below.\n\n"
                 "3.   Log in normally in the game.\n\n"
                 "4.   Back here, click  Finish & Save.")
        holder, card = make_panel(wrap, padx=18, pady=16)
        holder.pack(fill="x")
        tk.Label(card, text=steps, bg=SURFACE, fg=TEXT, justify="left",
                 font=("Segoe UI", 10)).pack(anchor="w")

        self.status = tk.Label(wrap, text="Waiting to attach…", bg=BG, fg=MUTED,
                               font=("Segoe UI", 10))
        self.status.pack(anchor="w", pady=(16, 12))

        btns = tk.Frame(wrap, bg=BG)
        btns.pack(fill="x")
        self.attach_btn = make_button(btns, "Attach to game", self._attach,
                                      "accent")
        self.attach_btn.pack(side="left")
        self.finish_btn = make_button(btns, "Finish & Save", self._finish,
                                      "secondary")
        self.finish_btn.pack(side="left", padx=8)
        self.finish_btn.config(state="disabled")
        make_button(btns, "Cancel", self._cancel, "ghost").pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.transient(master)
        self.grab_set()

    def _set(self, text, color=MUTED):
        self.status.config(text=text, fg=color)

    def _attach(self):
        self.attach_btn.config(state="disabled")
        self._set("Attaching…")
        def work():
            cap = cc_provision.LoginCapture()
            self.after(0, lambda: self._attached(cap))
        threading.Thread(target=work, daemon=True).start()

    def _attached(self, cap):
        if not cap.attached:
            self._set(cap.error or "attach failed", DANGER)
            self.attach_btn.config(state="normal")
            return
        self.capture = cap
        self._set("Attached. Log in now…", SUCCESS)
        self.finish_btn.config(state="normal")
        self._poll()

    def _poll(self):
        if self.capture and self.capture.has_login():
            self._set("Login captured — click Finish & Save.", SUCCESS)
        self._poll_job = self.after(600, self._poll)

    def _finish(self):
        if not self.capture:
            return
        self.capture.stop()
        prof = self.capture.build()
        if not prof:
            self._set("No login found. Restart the game, attach, THEN log in.",
                      DANGER)
            self.finish_btn.config(state="disabled")
            self.attach_btn.config(state="normal")
            self.capture = None
            return
        try:
            with open(profile_path(), "w", encoding="utf-8") as fh:
                json.dump(prof, fh, indent=2)
        except OSError as e:
            messagebox.showerror("Save failed", str(e), parent=self)
            return
        if self._poll_job:
            self.after_cancel(self._poll_job)
        name = (prof.get("identity") or {}).get("display_name")
        messagebox.showinfo("Login saved", f"Saved login for {name}.",
                            parent=self)
        self.on_done()
        self.destroy()

    def _cancel(self):
        if self._poll_job:
            self.after_cancel(self._poll_job)
        if self.capture:
            self.capture.stop()
        self.destroy()


# --------------------------------------------------------------------------
# main window
# --------------------------------------------------------------------------

class App(tk.Tk):
    POLL_MS = 500

    def __init__(self):
        super().__init__()
        # FULL build adds the Controls tab (teleport, park realm, ...). The
        # simple build is Logs / Market / Scan / Status only.
        self.pages_list = (["Logs", "Market", "Scan"]
                           + (["Controls"] if FULL else [])
                           + ["Status", "Remote"])
        self.title("Cubic Bot" + (" — Full" if FULL else ""))
        self.geometry("940x640")
        self.minsize(820, 540)
        self.configure(bg=BG)

        self.bot = BotController()
        self.log_seq = 0
        self.evq = queue.Queue()
        self._poll_inflight = False
        self.capture = {"widget": None, "until": 0.0}
        self.nav_btns = {}
        self.pages = {}

        # Remote/Discord (Stage 1, local only): generate this exe's secret relay
        # id on first run and load the local remote config. No network yet.
        self.bot_id = cc_provision.get_or_create_bot_id()
        self.remote_cfg = cc_provision.load_remote_config()
        self._bot_id_revealed = False

        # Stage 3: the poll loop that phones the relay. The client reads the
        # (possibly rotated) bot_id and the (possibly re-discovered) relay URL
        # live via callables. The worker's thread always runs but only talks to
        # the relay while enabled — the feature is off until the user links.
        self.relay_client = cc_remote.RelayClient(
            url_fn=cc_provision.effective_relay_url,
            bot_id_fn=lambda: self.bot_id)
        self.remote_worker = cc_remote.RemoteWorker(
            self.relay_client, self._execute_remote,
            on_status=self._on_remote_status,
            items_provider=self._remote_items)

        _migrate_profile()
        self._setup_style()
        self._build_ui()
        self._show_page("Logs")
        self._refresh_identity()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(0, self._apply_dark_titlebar)
        self.after(self.POLL_MS, self._tick)
        # Resolve the relay via the discovery pointer in the background so the
        # baked-in address can be changed operator-side without a rebuild.
        self.after(80, self._kick_relay_discovery)
        # Start the remote poll loop. It only reaches the relay once enabled,
        # which persists across runs, so a user who linked stays linked.
        self.remote_worker.start()
        if self.remote_cfg.get("enabled"):
            self.remote_worker.enable(True)

    def _apply_dark_titlebar(self):
        """Win11: paint the OS title bar dark so it matches the app."""
        if os.name != "nt":
            return
        try:
            import ctypes
            from ctypes import wintypes
            self.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            val = ctypes.c_int(1)
            for attr in (20, 19):   # DWMWA_USE_IMMERSIVE_DARK_MODE (new, old)
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(val), ctypes.sizeof(val))
            # nudge a repaint so the change shows immediately
            self.withdraw()
            self.deiconify()
        except Exception:
            pass

    # -- style -------------------------------------------------------------

    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=TEXT,
                        font=("Segoe UI", 10))
        style.configure("TEntry", fieldbackground=SURFACE2, foreground=TEXT,
                        bordercolor=BORDER, lightcolor=BORDER,
                        darkcolor=BORDER, insertcolor=TEXT, padding=7)
        style.map("TEntry", bordercolor=[("focus", ACCENT)],
                  lightcolor=[("focus", ACCENT)])
        style.configure("Vertical.TScrollbar", background=SURFACE2,
                        troughcolor=BG, bordercolor=BG, arrowcolor=MUTED,
                        relief="flat")
        style.map("Vertical.TScrollbar",
                  background=[("active", BORDER)])

    # -- layout ------------------------------------------------------------

    def _build_ui(self):
        # ---- top app bar: brand · account | status · start · setup ------
        appbar = tk.Frame(self, bg=SURFACE, height=70)
        appbar.pack(side="top", fill="x")
        appbar.pack_propagate(False)

        brand = tk.Frame(appbar, bg=SURFACE)
        brand.pack(side="left", padx=22)
        tk.Label(brand, text="◆", bg=SURFACE, fg=ACCENT,
                 font=("Segoe UI", 18, "bold")).pack(side="left", padx=(0, 11))
        idcol = tk.Frame(brand, bg=SURFACE)
        idcol.pack(side="left")
        tk.Label(idcol, text="Cubic Bot" + (" · Full" if FULL else " · Simple"),
                 bg=SURFACE, fg=TEXT,
                 font=("Segoe UI", 13, "bold")).pack(anchor="w")
        self.account_lbl = tk.Label(idcol, text="no login", bg=SURFACE,
                                    fg=MUTED, font=("Segoe UI", 9))
        self.account_lbl.pack(anchor="w")

        right = tk.Frame(appbar, bg=SURFACE)
        right.pack(side="right", fill="y", padx=(0, 18))
        self.start_btn = make_button(right, "Start bot", self._start, "accent")
        self.start_btn.pack(side="right", pady=16, padx=(10, 0))
        # status pill: a rounded chip with a coloured "● word"
        self._pill_font = tkfont.Font(font=("Segoe UI", 10, "bold"))
        self._pill_cv = tk.Canvas(right, bg=SURFACE, highlightthickness=0,
                                  bd=0, height=32)
        self._pill_cv.pack(side="right", padx=10, pady=18)
        self._pill_txt = self._pill_cv.create_text(0, 0, text="● stopped",
                                                   anchor="w", fill=MUTED,
                                                   font=self._pill_font)
        self._render_pill("stopped", MUTED)
        self.setup_btn = make_button(right, "Set up login…", self._open_setup,
                                     "ghost")
        self.setup_btn.pack(side="right", pady=16, padx=(0, 4))

        # ---- tab strip: horizontal rounded segmented tabs ---------------
        tabband = tk.Frame(self, bg=SIDEBAR)
        tabband.pack(side="top", fill="x")
        tabrow = tk.Frame(tabband, bg=SIDEBAR)
        tabrow.pack(side="left", padx=16, pady=10)
        for name in self.pages_list:
            icon = NAV_ICONS.get(name, "•")
            b = RoundedButton(tabrow, text=f"{icon}  {name}",
                              command=lambda n=name: self._show_page(n),
                              kind="secondary", padx=15, pady=8)
            b.pack(side="left", padx=(0, 8))
            self.nav_btns[name] = b
        self._nav_current = None
        tk.Label(tabband, text=("Full build" if FULL else "Simple build"),
                 bg=SIDEBAR, fg=MUTED, font=("Segoe UI", 8)).pack(
            side="right", padx=18)
        tk.Frame(self, bg=BORDER, height=1).pack(side="top", fill="x")

        # ---- content: page header + stacked pages -----------------------
        content = tk.Frame(self, bg=BG)
        content.pack(side="top", fill="both", expand=True)
        header = tk.Frame(content, bg=BG)
        header.pack(fill="x", padx=18, pady=(16, 0))
        self.page_title = tk.Label(header, text="Logs", bg=BG, fg=TEXT,
                                   font=("Segoe UI", 16, "bold"))
        self.page_title.pack(anchor="w")

        container = tk.Frame(content, bg=BG)
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        for name in self.pages_list:
            f = tk.Frame(container, bg=BG)
            f.grid(row=0, column=0, sticky="nsew")
            self.pages[name] = f
        self._build_logs(self.pages["Logs"])
        self._build_market(self.pages["Market"])
        self._build_scan(self.pages["Scan"])
        if "Controls" in self.pages:
            self._build_controls(self.pages["Controls"])
        self._build_status(self.pages["Status"])
        self._build_remote(self.pages["Remote"])

    def _render_pill(self, text, color):
        """Draw the status chip: a rounded pill holding a coloured '● word'."""
        cv, label = self._pill_cv, "● " + text
        cv.itemconfigure(self._pill_txt, text=label, fill=color)
        w = self._pill_font.measure(label) + 26
        h = 32
        cv.configure(width=w, height=h)
        cv.delete("pbox")
        _round_rect(cv, 1, 1, w - 1, h - 1, 11, fill=SURFACE2,
                    outline=SURFACE2, tags="pbox")
        cv.tag_lower("pbox")
        cv.coords(self._pill_txt, 13, h / 2 + 1)

    def _text(self, parent, **kw):
        """A dark, scrolled, read-only console inside a rounded panel."""
        bg = parent.cget("bg")
        holder = tk.Frame(parent, bg=bg)
        cv = tk.Canvas(holder, bg=bg, highlightthickness=0, bd=0)
        cv.pack(fill="both", expand=True)
        inner = tk.Frame(cv, bg=CONSOLE_BG)
        t = tk.Text(inner, wrap="word", state="disabled", bg=CONSOLE_BG,
                    fg=kw.pop("fg", "#d7dbe2"), insertbackground=TEXT,
                    relief="flat", bd=0, highlightthickness=0, padx=8, pady=8,
                    font=("Consolas", 10), **kw)
        for tname, col in (("chat", LOG_CHAT), ("whisper", LOG_WHISPER),
                           ("server", LOG_SERVER), ("realm", LOG_REALM),
                           ("dialog", LOG_DIALOG), ("cmd", LOG_CMD),
                           ("muted", MUTED), ("ok", SUCCESS), ("bad", DANGER)):
            t.tag_configure(tname, foreground=col)
        sb = ttk.Scrollbar(inner, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        t.pack(side="left", fill="both", expand=True)
        win = cv.create_window(0, 0, window=inner, anchor="nw")
        R = 14

        def on_cfg(e):
            cv.delete("frame")
            _round_rect(cv, 1, 1, e.width - 1, e.height - 1, R,
                        fill=CONSOLE_BG, outline=BORDER, width=1, tags="frame")
            cv.tag_lower("frame")
            inset = R - 3
            cv.coords(win, inset, inset)
            cv.itemconfigure(win, width=e.width - 2 * inset,
                             height=e.height - 2 * inset)
        cv.bind("<Configure>", on_cfg)
        return holder, t

    def _build_logs(self, f):
        pad = tk.Frame(f, bg=BG, padx=18, pady=16)
        pad.pack(fill="both", expand=True)
        card, self.log = self._text(pad)
        card.pack(fill="both", expand=True)
        bar = tk.Frame(pad, bg=BG)
        bar.pack(fill="x", pady=(12, 0))
        self.cmd_entry = RoundedEntry(bar)
        self.cmd_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.cmd_entry.bind("<Return>", lambda e: self._send_cmd())
        make_button(bar, "Send", self._send_cmd, "secondary").pack(side="right")

    def _build_market(self, f):
        pad = tk.Frame(f, bg=BG, padx=18, pady=16)
        pad.pack(fill="both", expand=True)
        bar = tk.Frame(pad, bg=BG)
        bar.pack(fill="x", pady=(0, 12))
        tk.Label(bar, text="Search item", bg=BG, fg=MUTED,
                 font=("Segoe UI", 9)).pack(anchor="w")
        row = tk.Frame(pad, bg=BG)
        row.pack(fill="x", pady=(0, 12))
        self.market_entry = RoundedEntry(row)
        self.market_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.market_entry.bind("<Return>", lambda e: self._market_search())
        make_button(row, "Search", self._market_search, "accent").pack(
            side="right")
        tk.Label(pad, text="Results come from realms you've SCANNED. If it says "
                           "“catalogue empty”, run a Scan or turn on "
                           "Auto-Hollawarp first.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9), justify="left",
                 wraplength=640).pack(anchor="w", pady=(0, 10))
        card, self.market_out = self._text(pad, fg="#cfe4ff")
        card.pack(fill="both", expand=True)

    def _build_scan(self, f):
        pad = tk.Frame(f, bg=BG, padx=18, pady=16)
        pad.pack(fill="both", expand=True)
        row = tk.Frame(pad, bg=BG)
        row.pack(fill="x", pady=(0, 6))
        make_button(row, "Scan this realm", self._scan, "accent").pack(
            side="left")
        self.hwarp_on = tk.BooleanVar(value=False)
        self.hwarp_btn = make_button(row, "Auto-Hollawarp: OFF",
                                     self._toggle_hwarp, "secondary")
        self.hwarp_btn.pack(side="left", padx=8)
        make_button(row, "Go to park realm", self._park, "secondary").pack(
            side="left")
        self.scan_msg = tk.Label(pad, text="", bg=BG, fg=MUTED,
                                 font=("Segoe UI", 9))
        self.scan_msg.pack(anchor="w", pady=(10, 8))
        card, self.scan_out = self._text(pad, fg="#d6f5d6")
        card.pack(fill="both", expand=True)

    def _labeled_input(self, parent, label, placeholder, btn_text, on_go):
        """A titled row: label, entry (Enter=go), and an accent button."""
        tk.Label(parent, text=label, bg=BG, fg=MUTED, justify="left",
                 wraplength=680, font=("Segoe UI", 9)).pack(anchor="w")
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x", pady=(2, 14))
        entry = RoundedEntry(row)
        entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        entry.bind("<Return>", lambda e: on_go(entry.get().strip()))
        make_button(row, btn_text, lambda: on_go(entry.get().strip()),
                    "accent").pack(side="right")
        return entry

    def _build_controls(self, f):
        pad = tk.Frame(f, bg=BG, padx=18, pady=16)
        pad.pack(fill="both", expand=True)

        self.park_entry = self._labeled_input(
            pad, "Park realm  (exact realm name — bot returns here after each "
                 "scan)", "", "Set park realm", self._set_park)
        self.tp_entry = self._labeled_input(
            pad, "Teleport to player  (must be online)", "", "Teleport",
            self._tp_player)

        quick = tk.Frame(pad, bg=BG)
        quick.pack(fill="x", pady=(0, 10))
        for label, cmd in (("Help", "help"), ("Where am I", "where"),
                           ("Park now", "park"), ("Players", "players"),
                           ("Friends", "friends")):
            make_button(quick, label,
                        lambda c=cmd: self._run_into(c, self.controls_out),
                        "secondary").pack(side="left", padx=(0, 8))

        card, self.controls_out = self._text(pad, fg="#e9e2ff")
        card.pack(fill="both", expand=True)

    def _set_park(self, name):
        if not name or not self._require_running():
            return
        self._run_into(f"parkrealm {name}", self.controls_out)

    def _tp_player(self, name):
        if not name or not self._require_running():
            return
        self._run_into(f"tp {name}", self.controls_out)

    def _build_status(self, f):
        pad = tk.Frame(f, bg=BG, padx=18, pady=18)
        pad.pack(fill="both", expand=True)
        card, grid = make_panel(pad)
        card.pack(fill="x")
        self.status_vars = {}
        rows = [("Account", "account"), ("Connection", "connection"),
                ("Realm", "realm"), ("Bot process", "proc")]
        for i, (label, key) in enumerate(rows):
            tk.Label(grid, text=label, bg=SURFACE, fg=MUTED,
                     font=("Segoe UI", 10)).grid(row=i, column=0, sticky="w",
                                                 pady=7, padx=(0, 30))
            v = tk.Label(grid, text="—", bg=SURFACE, fg=TEXT,
                         font=("Segoe UI", 11, "bold"))
            v.grid(row=i, column=1, sticky="w", pady=7)
            self.status_vars[key] = v
        grid.grid_columnconfigure(1, weight=1)
        make_button(pad, "Refresh stats (dbstats)",
                    lambda: self._run_into("dbstats", self.scan_out),
                    "secondary").pack(anchor="w", pady=(16, 0))

        # Discord alerts (optional). Paste a channel webhook URL to get a ping
        # whenever a prize machine is cracked or a snipe is snagged. Available
        # in both builds; leaving it blank keeps alerts off. The two checkboxes
        # let the user pick which alert types they want.
        tk.Frame(pad, bg=BORDER, height=1).pack(fill="x", pady=(22, 16))
        self.webhook_entry = self._labeled_input(
            pad, "Discord alerts  (paste a channel webhook URL — pings you when "
                 "a prize is cracked or a snipe is snagged; blank = off)",
            "", "Save alerts", self._set_webhook)

        # Per-alert on/off. `_wh_syncing` guards the vars while polling writes
        # into them, so a programmatic refresh doesn't fire a command back.
        self._wh_syncing = False
        self.wh_prize = tk.BooleanVar(value=True)
        self.wh_snipe = tk.BooleanVar(value=True)
        toggles = tk.Frame(pad, bg=BG)
        toggles.pack(fill="x", pady=(0, 8))
        for text, var, key in (("Alert on prize cracks", self.wh_prize, "prize"),
                               ("Alert on snipe snags", self.wh_snipe, "snipe")):
            tk.Checkbutton(
                toggles, text=text, variable=var,
                command=lambda k=key, v=var: self._toggle_webhook(k, v),
                bg=BG, fg=TEXT, selectcolor=ACCENT, activebackground=BG,
                activeforeground=TEXT, font=("Segoe UI", 9),
                highlightthickness=0, bd=0, anchor="w",
            ).pack(side="left", padx=(0, 20))

        wbtns = tk.Frame(pad, bg=BG)
        wbtns.pack(fill="x", pady=(0, 10))
        make_button(wbtns, "Send test ping",
                    lambda: self._run_into("webhook test", self.status_out),
                    "secondary").pack(side="left", padx=(0, 8))
        make_button(wbtns, "Turn all alerts off",
                    lambda: self._run_into("webhook off", self.status_out),
                    "secondary").pack(side="left")
        card, self.status_out = self._text(pad, fg="#e9e2ff")
        card.pack(fill="both", expand=True, pady=(10, 0))

    def _set_webhook(self, url):
        if not url or not self._require_running():
            return
        self._run_into(f"webhook set {url}", self.status_out)

    def _toggle_webhook(self, key, var):
        # Ignore the change if it came from a polling refresh, not a real click.
        if self._wh_syncing:
            return
        if not self._require_running():
            var.set(not var.get())         # snap back — nothing was applied
            return
        self._run_into(f"webhook {key} {'on' if var.get() else 'off'}",
                       self.status_out)

    # -- remote / discord --------------------------------------------------

    def _build_remote(self, f):
        """Remote-control panel (Stage 1: local only, no network).

        Shows this exe's secret relay id (masked, like a password), the relay
        URL, and a link section. The one-time link code, live link status, and
        the poll loop arrive in later stages; here the Link/Unlink buttons are
        stubs that explain what's coming and confirm the local state is saved.
        """
        pad = tk.Frame(f, bg=BG, padx=18, pady=16)
        pad.pack(fill="both", expand=True)

        tk.Label(pad, text="Control this bot from Discord",
                 bg=BG, fg=TEXT, font=("Segoe UI", 13, "bold")).pack(anchor="w")
        tk.Label(pad, text="Your bot phones out to a relay you host; a Discord "
                           "bot sends it commands. Nothing connects INTO your "
                           "PC. This is off until you link it.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9), justify="left",
                 wraplength=660).pack(anchor="w", pady=(2, 14))

        # --- secret id card ---------------------------------------------
        idholder, idcard = make_panel(pad, padx=18, pady=14)
        idholder.pack(fill="x")
        tk.Label(idcard, text="This bot's secret ID", bg=SURFACE, fg=MUTED,
                 font=("Segoe UI", 9)).pack(anchor="w")
        row = tk.Frame(idcard, bg=SURFACE)
        row.pack(fill="x", pady=(4, 2))
        self.bot_id_lbl = tk.Label(row, text=self._bot_id_display(), bg=SURFACE2,
                                   fg=TEXT, font=("Consolas", 11), padx=12,
                                   pady=7, anchor="w")
        self.bot_id_lbl.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.reveal_btn = make_button(row, "Reveal", self._toggle_reveal_id,
                                      "secondary")
        self.reveal_btn.pack(side="left", padx=(0, 8))
        make_button(row, "Copy", self._copy_bot_id, "secondary").pack(
            side="left")
        tk.Label(idcard, text="Treat this like a password. It is how your bot "
                             "signs in to the relay — never paste it into "
                             "Discord or share it.",
                 bg=SURFACE, fg=WARN, font=("Segoe UI", 8), justify="left",
                 wraplength=620).pack(anchor="w", pady=(8, 0))

        # --- link section ----------------------------------------------
        # There is deliberately NO relay-URL box: the relay address is baked
        # into the build, so users never see or type it. They just link.
        tk.Frame(pad, bg=BORDER, height=1).pack(fill="x", pady=(18, 14))
        tk.Label(pad, text="Step 1: add the bot to your Discord server.   "
                           "Step 2: click Link to Discord for a code.   "
                           "Step 3: run /link <code> in Discord.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9), justify="left",
                 wraplength=660).pack(anchor="w", pady=(0, 8))
        linkrow = tk.Frame(pad, bg=BG)
        linkrow.pack(fill="x", pady=(0, 8))
        if getattr(cc_provision, "DISCORD_INVITE_URL", ""):
            self.invite_btn = make_button(linkrow, "Add bot to Discord",
                                          self._open_invite, "secondary")
            self.invite_btn.pack(side="left", padx=(0, 8))
        self.link_btn = make_button(linkrow, "Link to Discord",
                                    self._link_to_discord, "accent")
        self.link_btn.pack(side="left", padx=(0, 8))
        self.unlink_btn = make_button(linkrow, "Unlink", self._unlink,
                                      "secondary")
        self.unlink_btn.pack(side="left")
        self.link_status_lbl = tk.Label(pad, text="", bg=BG, fg=MUTED,
                                        font=("Segoe UI", 9))
        self.link_status_lbl.pack(anchor="w", pady=(2, 10))

        # One-time link code (hidden until "Link to Discord" mints one).
        self.code_card, codebody = make_panel(pad, padx=16, pady=12,
                                              outline=ACCENT)
        tk.Label(codebody, text="Type this in Discord within 5 minutes:",
                 bg=SURFACE, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w")
        crow = tk.Frame(codebody, bg=SURFACE)
        crow.pack(fill="x", pady=(4, 0))
        self.code_lbl = tk.Label(crow, text="", bg=SURFACE, fg=ACCENT,
                                 font=("Consolas", 20, "bold"))
        self.code_lbl.pack(side="left")
        make_button(crow, "Copy code", self._copy_code, "secondary").pack(
            side="left", padx=12)
        # (packed/unpacked dynamically by _show_code)

        self._remote_card, self.remote_out = self._text(pad, fg="#cfe4ff")
        self._remote_card.pack(fill="both", expand=True)
        self._refresh_link_status()

    def _bot_id_display(self):
        if self._bot_id_revealed:
            return self.bot_id
        return "•" * 28

    def _toggle_reveal_id(self):
        self._bot_id_revealed = not self._bot_id_revealed
        self.bot_id_lbl.config(text=self._bot_id_display())
        self.reveal_btn.config(text="Hide" if self._bot_id_revealed else "Reveal")

    def _copy_bot_id(self):
        try:
            self.clipboard_clear()
            self.clipboard_append(self.bot_id)
            self.update()
            self._append(self.remote_out,
                         "Secret ID copied to clipboard. Keep it private — it "
                         "is not for Discord.\n")
        except Exception as e:
            self._append(self.remote_out, f"(copy failed: {e})\n")

    def _open_invite(self):
        invite = getattr(cc_provision, "DISCORD_INVITE_URL", "")
        if not invite:
            self._append(self.remote_out,
                         "No bot invite link is configured in this build.\n")
            return
        # Remember they've been sent to add the bot, so the next Link click goes
        # straight to a code instead of re-opening the invite.
        self.remote_cfg["invite_ack"] = True
        cc_provision.save_remote_config(self.remote_cfg)
        try:
            webbrowser.open(invite)
            self._append(self.remote_out,
                         "Opened the bot invite page in your browser. Add the "
                         "bot to your server, then click “Link to Discord”.\n")
        except Exception as e:
            self._append(self.remote_out,
                         f"(couldn't open the browser: {e})\nInvite link:\n"
                         f"{invite}\n")

    def _link_to_discord(self):
        # Ask the relay for a one-time code, show it, and turn the feature on so
        # the poll loop starts. Completing the link happens in Discord (/link
        # <code>); the poll response then reports us as linked.
        if not cc_provision.effective_relay_url():
            self._append(self.remote_out,
                         "This build has no relay configured yet, so remote "
                         "control is off. (Nothing for you to do — whoever set "
                         "up the bot bakes the relay address into the build.)\n")
            return
        # First-time users: send them to add the bot to their server before
        # handing out a code (a code is useless if the bot isn't in a server
        # they can run /link in). Once acknowledged, go straight to the code.
        invite = getattr(cc_provision, "DISCORD_INVITE_URL", "")
        if (invite and not self.remote_cfg.get("invite_ack")
                and not self.remote_cfg.get("linked")):
            self._open_invite()
            self._append(self.remote_out,
                         "When the bot is in your server, click “Link to "
                         "Discord” again to get your code.\n")
            return
        self.link_btn.config(state="disabled")
        self._append(self.remote_out, "Requesting a link code from the relay…\n")

        def work():
            res, err = self.relay_client.request_linkcode()
            self.after(0, lambda: self._linkcode_done(res, err))
        threading.Thread(target=work, daemon=True).start()

    def _linkcode_done(self, res, err):
        self.link_btn.config(state="normal")
        if err == "not_configured":
            self._append(self.remote_out, "No relay configured.\n")
            return
        if err == "unreachable" or res is None:
            self._append(self.remote_out,
                         "Couldn't reach the relay. Check your internet and try "
                         "again.\n")
            return
        if err and err.startswith("http_429"):
            self._append(self.remote_out,
                         "Too many code requests — wait a minute and retry.\n")
            return
        if err and err.startswith("http_"):
            num = err.split("_", 1)[1]
            detail = (res or {}).get("error") or "(no details from the relay)"
            hint = (" — a 502 usually means the relay process isn't running "
                    "behind the tunnel." if num == "502" else "")
            self._append(self.remote_out,
                         f"Relay returned HTTP {num}: {detail}{hint}\n")
            return
        code = (res or {}).get("code")
        if not code:
            self._append(self.remote_out, f"Unexpected relay reply: {res}\n")
            return
        # Opt in: enable the loop and remember it across runs.
        self.remote_cfg["enabled"] = True
        cc_provision.save_remote_config(self.remote_cfg)
        self.remote_worker.enable(True)
        self._show_code(code)
        self._append(self.remote_out,
                     f"Link code ready: {code}\nIn Discord, run  /link {code}  "
                     "within 5 minutes. This window will show “Linked” once it "
                     "goes through.\n")

    def _show_code(self, code):
        self._link_code = code
        self.code_lbl.config(text=code)
        self.code_card.pack(fill="x", pady=(0, 10), before=self._remote_card)

    def _copy_code(self):
        try:
            self.clipboard_clear()
            self.clipboard_append(getattr(self, "_link_code", ""))
            self.update()
            self._append(self.remote_out, "Code copied.\n")
        except Exception as e:
            self._append(self.remote_out, f"(copy failed: {e})\n")

    def _unlink(self):
        # Disconnect from Discord by ROTATING the bot_id: the relay's binding
        # then points at an id that never polls again, so nothing can command
        # this bot until it links afresh. Also stops the loop locally.
        self.remote_worker.enable(False)
        self.bot_id = cc_provision.rotate_bot_id()
        self._bot_id_revealed = False
        self.bot_id_lbl.config(text=self._bot_id_display())
        self.reveal_btn.config(text="Reveal")
        self.remote_cfg["enabled"] = False
        self.remote_cfg["linked"] = None
        cc_provision.save_remote_config(self.remote_cfg)
        try:
            self.code_card.pack_forget()
        except Exception:
            pass
        self._append(self.remote_out,
                     "Unlinked. Your secret ID was rotated, so the old Discord "
                     "link no longer controls this bot.\n")
        self._refresh_link_status()

    def _on_remote_status(self, resp):
        # Called from the worker thread on every poll — marshal onto the UI loop.
        linked = None
        if resp.get("linked"):
            linked = {"discord_user": resp.get("discord_user")}
        self.after(0, lambda: self._apply_remote_status(linked))

    def _apply_remote_status(self, linked):
        prev = self.remote_cfg.get("linked")
        self.remote_cfg["linked"] = linked
        if linked and not prev:
            # Just became linked — persist and hide the now-used code.
            cc_provision.save_remote_config(self.remote_cfg)
            try:
                self.code_card.pack_forget()
            except Exception:
                pass
            self._append(self.remote_out, "Linked to Discord. ✓\n")
        self._refresh_link_status()

    def _remote_items(self):
        """Scanned item names for the relay to serve /market autocomplete, or None
        when the bot isn't running (nothing to offer). Runs on the worker thread."""
        if not self.bot.is_running():
            return None
        d = self.bot.items()
        return d.get("items") if d else None

    def _execute_remote(self, command):
        """Run one allowed remote command on the local bot and return (ok, text).
        Runs on the worker thread; uses the same local control API the GUI does.
        The allowlist is enforced in cc_remote before we get here."""
        if not self.bot.is_running():
            return False, ("The bot isn't running. Start it in the app, then "
                           "try again.")
        head = command.split(None, 1)[0].lower()
        if head == "status":
            st = self.bot.status()
            if not st:
                return False, "Couldn't read status."
            if st.get("connected") and not st.get("offline"):
                conn = "connected"
            elif st.get("offline"):
                conn = "offline"
            else:
                conn = "connecting"
            return True, (f"Account: {st.get('account', '?')}\n"
                          f"Connection: {conn}\n"
                          f"Realm: {st.get('realm') or '—'}")
        if head == "scan":
            # Scan is asynchronous and can take a while, so the remote side drives
            # it in two steps and we answer each with a small JSON blob it parses:
            #   "scan"         -> start the scan (returns seq/realm to poll against)
            #   "scan status"  -> is it still running + vends so far + seq
            # The Discord bot starts a scan, notes the seq, then polls "scan
            # status" until seq advances = the whole realm has been scanned.
            rest = command.split(None, 1)
            sub = rest[1].strip().lower() if len(rest) > 1 else ""
            if sub in ("status", "wait", "poll"):
                data = self.bot.scanstatus()
                if data is None:
                    return False, "The bot didn't respond — is it still running?"
                data = dict(data)
                data["kind"] = "scanstatus"
                return True, json.dumps(data)
            data = self.bot.scan()
            if data is None:
                return False, "The bot didn't respond — is it still running?"
            data = dict(data)
            data["kind"] = "scanstart"
            return bool(data.get("ok", True)), json.dumps(data)
        if head == "guid":
            # `guid <player>` teleports to that player and AUTO-scans their realm
            # on landing. Run it to get the immediate confirmation, and attach the
            # current scan counter + realm so the remote side can poll "scan
            # status" until the auto-scan lands and finishes (seq advances).
            res = self.bot.runcmd(command)
            if res is None:
                return False, "The bot didn't respond — is it still running?"
            lines = [t for t in (res.get("lines") or [])
                     if not _is_ambient_log(t)]
            text = "\n".join(lines).strip()
            st = self.bot.scanstatus() or {}
            return True, json.dumps({
                "kind": "guid",
                "started": "teleport" in text.lower(),
                "text": text or "(no output)",
                "seq": st.get("seq", 0),
                "realm": st.get("realm")})
        # Everything else: run it via /runcmd, which returns exactly the lines
        # the command produced (the bot captures them at the source). The bot's
        # log is a SHARED stream — live chat, whispers and server events land in
        # it too — so we still drop those ambient tagged lines and keep only the
        # command's own output.
        res = self.bot.runcmd(command)
        if res is None:
            return False, "The bot didn't respond — is it still running?"
        lines = [t for t in (res.get("lines") or []) if not _is_ambient_log(t)]
        out = "\n".join(lines).strip()
        return True, (out or "(command ran — no text output)")

    def _kick_relay_discovery(self):
        def work():
            url = cc_provision.refresh_relay_url()
            self.after(0, lambda: self._on_relay_resolved(url))
        threading.Thread(target=work, daemon=True).start()

    def _on_relay_resolved(self, url):
        # Pick up the freshly-cached relay and re-render the link status.
        self.remote_cfg = cc_provision.load_remote_config()
        self._refresh_link_status()

    def _refresh_link_status(self):
        linked = self.remote_cfg.get("linked")
        if linked:
            who = linked.get("discord_user") or "a Discord user"
            self.link_status_lbl.config(text=f"Linked to {who}.", fg=SUCCESS)
        elif cc_provision.effective_relay_url():
            self.link_status_lbl.config(
                text="Not linked yet. Click “Link to Discord”.", fg=MUTED)
        else:
            self.link_status_lbl.config(
                text="Remote control isn't set up in this build.", fg=MUTED)

    # -- nav ---------------------------------------------------------------

    def _style_tab(self, b, active):
        b.set_kind("accent" if active else "secondary")

    def _show_page(self, name):
        self.pages[name].tkraise()
        self.page_title.config(text=name)
        for n, b in self.nav_btns.items():
            self._style_tab(b, n == name)
            if n == name:
                self._nav_current = b

    # -- identity ----------------------------------------------------------

    def _refresh_identity(self):
        ident = load_identity()
        if ident:
            name = ident.get("display_name") or "account"
            self.account_lbl.config(text=name)
            self.status_vars["account"].config(text=name)
            self.start_btn.config(state="normal")
        else:
            self.account_lbl.config(text="no login — click “Set up login…”")
            self.start_btn.config(state="disabled")
            self._append(self.log,
                         "Welcome! No login saved yet.\n"
                         "Click “Set up login…” (bottom-left) to capture one.\n")

    # -- actions -----------------------------------------------------------

    def _open_setup(self):
        if self.bot.is_running():
            messagebox.showinfo("Stop first",
                                "Stop the bot before re-running setup.",
                                parent=self)
            return
        SetupDialog(self, on_done=self._refresh_identity)

    def _start(self):
        if self.bot.is_running():
            self._stop()
            return
        try:
            self.bot.start()
        except Exception as e:
            messagebox.showerror("Could not start", str(e), parent=self)
            return
        self.log_seq = 0
        self.start_btn.config(text="Stop bot")
        set_button_kind(self.start_btn, "danger")
        self.setup_btn.config(state="disabled")
        self._set_state("starting…", WARN, pulse=True)
        self._append(self.log, "\n--- bot starting ---\n")

    def _stop(self):
        self._set_state("stopping…", WARN, pulse=True)
        self.update_idletasks()
        threading.Thread(target=self._stop_worker, daemon=True).start()

    def _stop_worker(self):
        self.bot.stop()
        self.evq.put(("stopped", None))

    def _send_cmd(self):
        line = self.cmd_entry.get().strip()
        if not line:
            return
        self.cmd_entry.delete(0, "end")
        if not self.bot.is_running():
            self._append(self.log, "(bot is not running)\n")
            return
        self._append(self.log, f"> {line}\n")
        threading.Thread(target=lambda: self.bot.cmd(line), daemon=True).start()

    def _market_search(self):
        item = self.market_entry.get().strip()
        if not item:
            return
        self._run_into(f"market {item}", self.market_out)

    def _scan(self):
        if not self._require_running():
            return
        self._arm_capture(self.scan_out)
        threading.Thread(
            target=lambda: self.evq.put(("scanmsg", self.bot.scan())),
            daemon=True).start()

    def _toggle_hwarp(self):
        if not self._require_running():
            return
        on = not self.hwarp_on.get()
        self.hwarp_on.set(on)
        self.hwarp_btn.config(text=f"Auto-Hollawarp: {'ON' if on else 'OFF'}")
        set_button_kind(self.hwarp_btn, "accent" if on else "secondary")
        threading.Thread(
            target=lambda: self.evq.put(("scanmsg", self.bot.hwarp(on))),
            daemon=True).start()

    def _park(self):
        if not self._require_running():
            return
        threading.Thread(
            target=lambda: self.evq.put(("scanmsg", self.bot.park())),
            daemon=True).start()

    def _run_into(self, line, widget, seed=None):
        if not self._require_running():
            return
        self._arm_capture(widget, seed=seed or f"› {line}\n")
        self._append(self.log, f"> {line}\n")
        threading.Thread(target=lambda: self.bot.cmd(line), daemon=True).start()

    def _arm_capture(self, widget, window=8.0, seed=None):
        self._clear(widget)
        if seed:
            self._append(widget, seed)
        self.capture = {"widget": widget, "until": time.time() + window}

    def _require_running(self):
        if not self.bot.is_running():
            messagebox.showinfo("Not running", "Start the bot first.",
                                parent=self)
            return False
        return True

    # -- polling -----------------------------------------------------------

    def _set_state(self, text, color, pulse=False):
        self._render_pill(text, color)
        self._stop_pulse()
        if pulse:
            self._pulse_color = color
            self._pulse(True)

    def _stop_pulse(self):
        job = getattr(self, "_pulse_job", None)
        if job:
            try:
                self.after_cancel(job)
            except Exception:
                pass
            self._pulse_job = None

    def _pulse(self, on):
        # Fade the status pill's text in/out while connecting so an in-progress
        # state reads as "working", not stalled. Dims toward the chip fill.
        self._pill_cv.itemconfigure(
            self._pill_txt,
            fill=getattr(self, "_pulse_color", MUTED) if on else BORDER)
        self._pulse_job = self.after(520, lambda: self._pulse(not on))

    def _tick(self):
        try:
            while True:
                kind, payload = self.evq.get_nowait()
                if kind == "stopped":
                    self._on_stopped()
                elif kind == "scanmsg" and payload:
                    self.scan_msg.config(text=payload.get("msg", ""))
        except queue.Empty:
            pass

        if self.bot.is_running():
            if not self._poll_inflight:
                self._poll_inflight = True
                threading.Thread(target=self._poll_worker, daemon=True).start()
        elif self.start_btn["text"] == "Stop bot":
            self._on_stopped()

        self.after(self.POLL_MS, self._tick)

    def _poll_worker(self):
        try:
            st = self.bot.status()
            lg = self.bot.logs(self.log_seq)
        finally:
            self._poll_inflight = False
        self.after(0, lambda: self._apply_poll(st, lg))

    def _apply_poll(self, st, lg):
        if st:
            connected = st.get("connected")
            offline = st.get("offline")
            if connected and not offline:
                self._set_state("running", SUCCESS)
                self.status_vars["connection"].config(text="connected",
                                                      fg=SUCCESS)
            elif offline:
                self._set_state("offline", WARN)
                self.status_vars["connection"].config(text="offline", fg=WARN)
            else:
                self._set_state("connecting…", WARN, pulse=True)
                self.status_vars["connection"].config(text="connecting",
                                                      fg=WARN)
            self.status_vars["realm"].config(text=st.get("realm") or "—")
            self.status_vars["account"].config(text=st.get("account") or "—")
            self.status_vars["proc"].config(text="running")
            # Mirror the bot's saved webhook toggles into the checkboxes without
            # re-firing a command (guarded by _wh_syncing).
            if hasattr(self, "wh_prize"):
                self._wh_syncing = True
                self.wh_prize.set(bool(st.get("webhook_prize", True)))
                self.wh_snipe.set(bool(st.get("webhook_snipe", True)))
                self._wh_syncing = False
        if lg and lg.get("lines"):
            for row in lg["lines"]:
                text = row["text"] + "\n"
                self._append(self.log, text)
                cap = self.capture
                if cap["widget"] is not None and time.time() < cap["until"]:
                    self._append(cap["widget"], text)
                    cap["until"] = time.time() + 1.5
            self.log_seq = lg.get("seq", self.log_seq)

    def _on_stopped(self):
        self.start_btn.config(text="Start bot", state="normal")
        set_button_kind(self.start_btn, "accent")
        self.setup_btn.config(state="normal")
        self._set_state("stopped", MUTED)
        self.status_vars["connection"].config(text="—", fg=TEXT)
        self.status_vars["proc"].config(text="stopped")
        self._append(self.log, "--- bot stopped ---\n")

    # -- text helpers ------------------------------------------------------

    def _append(self, widget, text, tag="auto"):
        if tag == "auto":
            tag = _log_tag_for(text)
        widget.config(state="normal")
        if tag:
            widget.insert("end", text, (tag,))
        else:
            widget.insert("end", text)
        widget.see("end")
        widget.config(state="disabled")

    def _clear(self, widget):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.config(state="disabled")

    def _on_close(self):
        try:
            self.remote_worker.stop()
        except Exception:
            pass
        if self.bot.is_running():
            if not messagebox.askokcancel(
                    "Quit", "The bot is running. Stop it and quit?", parent=self):
                return
            try:
                self.bot.stop(timeout=5)
            except Exception:
                pass
        self.destroy()


def run():
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(run())

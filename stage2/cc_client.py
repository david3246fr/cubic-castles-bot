#!/usr/bin/env python3
"""
Cubic Castles terminal client (Stage 4).

Two modes:

  replay  (default, SAFE)  — drives the full protocol stack against a captured
                             session file. No network. Proves the client can
                             decode a real login->gameplay flow end to end.

  live    (GATED)          — actually connects to the server. Refuses to run
                             unless --i-accept-live-risk is passed, because
                             connecting a third-party client to live.castles.cc
                             can get the account flagged. This is your call.

The live path is intentionally minimal and stops at the login handshake: it
connects, performs the cleartext hello, extracts the server-issued XXTEA key,
and then decodes/prints incoming traffic. It does not automate gameplay.
"""
import argparse
import collections
import csv
import io
import json
import os
import random
import re
import sys

import cc_protocol as P
import send_cipher as SEND_CIPHER

try:
    import cc_storage
except Exception:                       # storage is optional; JSON still works
    cc_storage = None

try:
    import cc_orders                     # buy-order escrow ledger (Stage 10)
except Exception:                       # optional; the client runs without it
    cc_orders = None

try:
    import cc_quiz                       # offline instant quiz brain (Stage 18)
except Exception:                       # optional; the client runs without it
    cc_quiz = None

try:
    import cc_translate                 # live chat translator (Stage 27)
except Exception:                       # optional; the client runs without it
    cc_translate = None

try:
    import cc_live_builder               # verified blueprint/live-test adapter
except Exception:                        # the legacy client can still start
    cc_live_builder = None


def _resolve_app_dir():
    """Directory the bot keeps ALL persistent state in (market/orders DBs, the
    realms/vends/watchlist JSON, logs, etc.).

    Running from source: right next to this script, exactly as before.
    Frozen into the PyInstaller exe: %APPDATA%\\CubicBot — a STABLE per-user
    folder. This matters because a --onefile exe unpacks to a fresh temp dir
    every launch (sys._MEIPASS) and deletes it on exit, so anything written
    beside __file__ when frozen would be wiped between runs.
    """
    if getattr(sys, "frozen", False):
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        target = os.path.join(base, "CubicBot")
        try:
            os.makedirs(target, exist_ok=True)
            return target
        except OSError:
            # last resort: sit beside the exe (still better than the temp dir)
            return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


# Computed once at import. Every data-file path in this module joins onto it.
_APP_DIR = _resolve_app_dir()


def _retry_after_seconds(exc):
    """Seconds a server asked us to wait, pulled from a 429's Retry-After header,
    or None if there isn't one. Cloudflare's rate limit (HTTP 429, `error code
    1015`) is IP-level, so a reconnect can't succeed until this elapses — we honor
    it instead of hammering. Reads the exception's resp_headers when the websocket
    library exposes them, else scrapes the header out of the exception's text."""
    hdrs = getattr(exc, "resp_headers", None)
    ra = None
    if hdrs is not None:
        try:
            ra = hdrs.get("retry-after", hdrs.get("Retry-After"))
        except AttributeError:                     # header list, not a dict
            try:
                ra = {str(k).lower(): v for k, v in hdrs}.get("retry-after")
            except Exception:
                ra = None
    if ra is None:
        m = re.search(r"[Rr]etry-[Aa]fter'?\s*[:=]\s*'?(\d+)", str(exc))
        ra = m.group(1) if m else None
    try:
        return max(1, int(float(ra))) if ra is not None else None
    except (TypeError, ValueError):
        return None


def _is_rate_limited(exc):
    """True if an exception looks like a Cloudflare/HTTP rate limit (429 / 1015),
    even without a Retry-After header — so we can still back off harder."""
    if getattr(exc, "status_code", None) == 429:
        return True
    s = str(exc)
    return "429" in s or "1015" in s


def _build_scanbot_chat(before_thumbs_up, after_thumbs_up):
    """Build one chat line with the captured thumbs-up inline and 100 at end.

    Keep this compatibility builder in the client so deploying cc_client.py by
    itself still works when the server has an older cc_protocol.py without the
    mixed-chat helper. C9 and E5 are the byte values captured from the official
    client; they are not Unicode and must be inside the same raw chat string.
    """
    thumbs_up = getattr(P, "CHAT_EMOJI_THUMBS_UP", 0xC9)
    hundred = getattr(P, "CHAT_EMOJI_100", 0xE5)
    mixed_builder = getattr(P, "build_chat_mixed", None)
    if callable(mixed_builder):
        return mixed_builder(before_thumbs_up, thumbs_up,
                             after_thumbs_up, hundred)
    raw = (before_thumbs_up.encode("utf-8") + bytes([thumbs_up]) +
           after_thumbs_up.encode("utf-8") + bytes([hundred]))
    # 0x000c chat type + u32 byte length including the terminating NUL.
    return b"\x0c\x00" + (len(raw) + 1).to_bytes(4, "little") + raw + b"\x00"


def _cur_symbol(cur):
    """Short in-chat tag for a currency. Cubits are the game's default coin and
    are written 'c' in chat; any other coin keeps its own short name."""
    name = (cur or "").strip()
    if not name or name.lower() in ("cubits", "cubit", "c"):
        return "c"
    return name


def _fmt_num(n):
    """Whole number with thousands separators, for chat ('6830' -> '6,830')."""
    try:
        return f"{int(round(n)):,}"
    except (TypeError, ValueError):
        return str(n)


def _chat_clean(s):
    """Tidy an outgoing chat line: write 'Cubits' as the short 'c' tag, remove
    em/en dashes (the game renders those multi-byte chars as garbage — an angry
    face + '##' — so they must never reach chat; the plain ASCII '-' in price
    ranges is fine and kept), collapse whitespace, drop spaces before
    punctuation, and glue a lone 'c' back onto its number ('6,830 c' -> '6,830c').
    Applied to every reply the bot composes."""
    import re
    s = re.sub(r"\bcubits\b", "c", s, flags=re.IGNORECASE)
    s = re.sub(r"\s*[—–]\s*", ", ", s)   # em/en dash -> comma, safe glyph
    # Angle brackets are markup to the in-game chat renderer (it uses <color ...>/
    # <link ...> tags), so a literal "<item>" in a reply is swallowed and the whole
    # line can fail to render. Drop the brackets, keep the word: "<item>" -> "item".
    s = re.sub(r"[<>]", "", s)
    # Parentheses are ALSO control syntax (the whisper/colour tags use c(r,g,b) and
    # "(WHISPER)"). A "(" in a WHISPER corrupts the outgoing message — the server
    # then sees it as too short ("make your whisper longer!") and no picker comes
    # back, so the reply is silently dropped. Strip the brackets, keep the words:
    # "(total 899c)" -> "total 899c".
    s = re.sub(r"[()]", "", s)
    s = re.sub(r"[ \t]+", " ", s).strip()
    s = re.sub(r"\s+([,;:])", r"\1", s)   # tidy ' ,' -> ',' (but keep ' | ')
    s = re.sub(r"(\d)\s+c\b", r"\1c", s)
    return s


# Keep this available at module scope so both the queue boundary and the final
# send boundary can enforce it, and so it can be regression-tested directly.
WHISPER_MAX_BYTES = getattr(P, "WHISPER_TEXT_MAX_BYTES", 90)


def _split_whisper(text, limit=WHISPER_MAX_BYTES):
    """Split whisper text into UTF-8 chunks that fit the server's safe limit.

    Prefer word boundaries, falling back to character boundaries for a single
    long word. The server limit applies to encoded chat bytes, not Python's
    Unicode character count.
    """
    if limit <= 0:
        raise ValueError("whisper byte limit must be positive")
    remaining = text.strip()
    parts = []
    while remaining:
        if len(remaining.encode("utf-8")) <= limit:
            parts.append(remaining)
            break

        used = 0
        cut = 0
        for i, char in enumerate(remaining):
            size = len(char.encode("utf-8"))
            if used + size > limit:
                break
            used += size
            cut = i + 1
        if cut == 0:
            raise ValueError("whisper byte limit cannot fit one character")

        prefix = remaining[:cut]
        word_cut = prefix.rfind(" ")
        if word_cut > 0:
            parts.append(prefix[:word_cut].rstrip())
            remaining = remaining[word_cut + 1:].lstrip()
        else:
            parts.append(prefix)
            remaining = remaining[cut:].lstrip()
    return parts


def _scanned_stats(rows):
    """Group live vending listings by currency into per-currency stat dicts,
    busiest currency first. A listing priced 0 or unknown is not a real sale and
    is skipped. Each dict: {currency, avg, min, min_realm, count}. Returns an
    empty list when nothing usable is present."""
    by_cur = {}
    for row in rows:
        price = row.get("price")
        if price is None or price <= 0:
            continue
        by_cur.setdefault(row.get("currency") or "", []).append(row)
    stats = []
    for cur, listings in sorted(by_cur.items(), key=lambda kv: -len(kv[1])):
        cheapest = min(listings, key=lambda row: row["price"])
        stats.append({
            "currency": cur,
            "avg": round(sum(row["price"] for row in listings) / len(listings)),
            "min": cheapest["price"],
            "min_realm": cheapest.get("realm"),
            "count": len(listings),
        })
    return stats


def _format_scanned(rows):
    """Build the scanned-market half of a price reply from live vending
    listings: 'Average: 6,830c | Min: 1c at 24h Rentals | Listings: 961'. The
    cheapest listing's realm is shown next to Min so buyers know where to go.
    Computed per currency (cubits and any other coin are never mixed); returns
    None when nothing usable was scanned."""
    parts = []
    for s in _scanned_stats(rows):
        sym = _cur_symbol(s["currency"])
        at = f" at {s['min_realm']}" if s.get("min_realm") else ""
        parts.append(f"Average: {_fmt_num(s['avg'])}{sym} | "
                     f"Min: {_fmt_num(s['min'])}{sym}{at} | "
                     f"Listings: {s['count']}")
    return " | ".join(parts) if parts else None


def _hesc(s):
    """Minimal HTML-escape for text dropped into the market page."""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# Self-contained market page: no external assets, works offline, opens in any
# browser. The scanned listings are injected as JSON at __DATA__; the script
# renders a filterable, click-to-sort table with clickable realm links.
_MARKET_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
 :root{color-scheme:light dark}
 body{font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;margin:0;
   background:#0f1115;color:#e6e6e6}
 header{padding:16px 20px;border-bottom:1px solid #2a2f3a;
   position:sticky;top:0;background:#0f1115;z-index:2}
 h1{margin:0 0 4px;font-size:18px}
 .sub{color:#9aa4b2;font-size:12px}
 .bar{margin-top:10px}
 input{width:100%;max-width:420px;padding:8px 10px;border-radius:8px;
   border:1px solid #2a2f3a;background:#171a21;color:#e6e6e6;font-size:14px}
 .count{color:#9aa4b2;font-size:12px;margin-left:8px}
 .wrap{overflow-x:auto}
 table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
 th,td{padding:7px 12px;text-align:left;border-bottom:1px solid #20242e;
   white-space:nowrap}
 th{position:sticky;top:0;cursor:pointer;background:#171a21;user-select:none;
   font-size:12px;color:#b8c1cf}
 th:hover{color:#fff}
 td.price{text-align:right;font-weight:600}
 tr:hover td{background:#161a22}
 a{color:#6ab0ff;text-decoration:none}a:hover{text-decoration:underline}
 .muted{color:#6b7280}
 footer{padding:14px 20px;color:#6b7280;font-size:12px}
</style></head><body>
<header>
 <h1>__TITLE__</h1>
 <div class="sub">__ROWS__ listings across __REALMS__ realms · scanned __WHEN__ ·
   prices are what a machine charges (never bought)</div>
 <div class="bar"><input id="q" placeholder="filter by item, realm or owner…"
   autofocus><span class="count" id="c"></span></div>
</header>
<div class="wrap"><table>
 <thead><tr>
   <th data-k="item">Item</th><th data-k="price">Price</th>
   <th data-k="currency">Cur</th><th data-k="qty">Qty</th>
   <th data-k="realm">Realm</th><th data-k="owner">Owner</th>
   <th data-k="link">Link</th>
 </tr></thead><tbody id="t"></tbody>
</table></div>
<footer>Generated by cc_client — offline market snapshot. Realm links open
 castles.cc.</footer>
<script>
 var DATA = __DATA__;
 var sortK = "price", sortAsc = true;
 function num(v){var n = parseFloat(String(v).replace(/,/g,""));
   return isNaN(n) ? Infinity : n;}
 function esc(s){var d = document.createElement("div");
   d.textContent = (s==null?"":s); return d.innerHTML;}
 function render(){
   var q = document.getElementById("q").value.toLowerCase().trim();
   var rows = DATA.filter(function(r){
     if(!q) return true;
     return ((r.item||"")+" "+(r.realm||"")+" "+(r.owner||"")).toLowerCase()
       .indexOf(q) >= 0;});
   rows.sort(function(a,b){
     var x = a[sortK], y = b[sortK], r;
     if(sortK === "price" || sortK === "qty"){ r = num(x) - num(y); }
     else { r = String(x||"").toLowerCase()
       .localeCompare(String(y||"").toLowerCase()); }
     return sortAsc ? r : -r;});
   var h = "";
   for(var i=0;i<rows.length;i++){var r = rows[i];
     var loc = (r.x!=null)?(" ("+r.x+","+r.y+","+r.z+")"):"";
     var lnk = r.link?('<a href="'+esc(r.link)+'" target="_blank" '
       +'rel="noopener">open ↗</a>'):'<span class="muted">—</span>';
     h += "<tr><td>"+esc(r.item)+"</td><td class=price>"
       +esc(r.price)+"</td><td class=muted>"+esc(r.currency)
       +"</td><td>"+esc(r.qty)+"</td><td>"+esc(r.realm)+"</td>"
       +"<td class=muted>"+esc(r.owner)+"</td><td>"+lnk+"</td></tr>";}
   document.getElementById("t").innerHTML = h;
   document.getElementById("c").textContent = rows.length+" shown";
 }
 document.getElementById("q").addEventListener("input", render);
 var ths = document.querySelectorAll("th");
 for(var j=0;j<ths.length;j++){ ths[j].addEventListener("click", function(){
   var k = this.getAttribute("data-k");
   if(k === sortK){ sortAsc = !sortAsc; } else { sortK = k; sortAsc = true; }
   render();});}
 render();
</script></body></html>"""


# --------------------------------------------------------------------------
# session state
# --------------------------------------------------------------------------

class Session:
    def __init__(self):
        self.key_words = None          # XXTEA key once known
        self.encrypted = False         # flips on after login handshake

    def feed_incoming(self, wire):
        """Decode an inbound frame given current session state."""
        if not self.encrypted or self.key_words is None:
            # pre-encryption: body is the raw frame
            body = wire
            t = P.body_type(body)
            return t, body, False
        _, body, term = P.decrypt_frame(wire, self.key_words)
        return P.body_type(body), body, term

    def try_extract_key(self, body):
        """From a login response (rx 0x0002), find the 16-byte key in the blob.
        Heuristic for offline use; the real offset comes from the blob parser."""
        info = P.parse_login_response(body)
        return info


def describe(t, body):
    name = P.msg_name(t) if t is not None else "??"
    extra = ""
    if t == 0x0019:
        try:
            host, port = P.parse_backend_handoff(body)
            extra = f"  host={host} port={port}"
        except Exception:
            pass
    elif t == 0x0006:
        p = P.parse_move(body) if len(body) == 62 else None
        extra = f"  x={p[0]} y={p[1]} z={p[2]}" if p else ""
    elif t == 0x0101:
        try:
            hb = P.parse_heartbeat(body)
            extra = f"  tick={hb['tick']}"
        except Exception:
            pass
    return f"{name:<18} len={len(body):4d}{extra}"


# --------------------------------------------------------------------------
# replay mode  (offline, safe)
# --------------------------------------------------------------------------

def run_replay(capture_path, key_hex):
    sess = Session()
    # In a real connection the key is learned from the login response; for replay
    # we seed it from the known session key and mark encryption on after the
    # cleartext handshake frames.
    seed_key = P.key_from_hex(key_hex)

    frames = []
    for line in open(capture_path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("type") == "frame":
            frames.append(r)

    print(f"replaying {len(frames)} frames from {capture_path}\n")
    handshake_done = False
    counts = {}
    for i, r in enumerate(frames):
        wire = bytes.fromhex(r["hex"])
        # emulate the handshake: first frames cleartext, then key active
        if not handshake_done:
            t = P.body_type(wire)
            if t == 0x0019:
                # server handoff seen in the clear -> encryption turns on next
                print(f"  {r['dir']}  {describe(t, wire)}   [handshake: backend handoff]")
            elif t == 0x0002:
                print(f"  {r['dir']}  LOGIN/HELLO (cleartext) len={len(wire)}")
            else:
                # first non-handshake decodes: switch on encryption
                sess.key_words = seed_key
                sess.encrypted = True
                handshake_done = True
        if handshake_done:
            t, body, term = sess.feed_incoming(wire)
            if term:
                counts[P.msg_name(t)] = counts.get(P.msg_name(t), 0) + 1
                if i < 40 or (t not in (0x0006, 0x0101, 0x005a)):
                    print(f"  {r['dir']}  {describe(t, body)}")

    print("\nmessage type totals (decoded):")
    for name, c in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {name:<20} {c}")
    print("\nreplay OK — full stack decoded a real session with no network access.")


# --------------------------------------------------------------------------
# live mode  (gated)
# --------------------------------------------------------------------------

# Backend endpoints are stored OBFUSCATED (XOR + base64) instead of as plaintext
# URLs, so the hostnames aren't visible in the source or the built exe.
_VEIL_KEY = b"cc-veil-7f3a"


def _veil(blob):
    import base64
    raw = base64.b64decode(blob)
    return bytes(c ^ _VEIL_KEY[i % len(_VEIL_KEY)]
                 for i, c in enumerate(raw)).decode()


def run_live(args):
    import select, signal, stat, threading, time
    try:
        import msvcrt                    # Windows: read the prompt a key at a time
    except ImportError:
        msvcrt = None

    # Windows consoles default to cp1252, which cannot encode emoji, fancy
    # quotes, or many player/realm names the server sends. A single such char in
    # ANY printed line raised UnicodeEncodeError — and when that fired inside the
    # reader thread it killed the thread and ZOMBIFIED the bot (avatar stays in
    # world, but nothing is read and no command runs). Force best-effort UTF-8 so
    # a print can never crash. errors='replace' shows a '?' instead of dying.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # --- console -------------------------------------------------------------
    # The reader thread prints whenever the server pushes something, which is
    # constantly. input() owns the terminal line, so anything printed while a
    # command is half-typed used to scroll the prompt away and tangle with what
    # was already typed. Everything printed in live mode goes through one lock
    # that erases the prompt, prints, and puts the half-typed text back.
    out_lock = threading.Lock()
    editbuf = []                         # chars typed but not yet entered
    cur = [0]                            # cursor position within editbuf
    hist = []                            # entered commands, for up/down recall
    hidx = [None]                        # where we are while browsing history
    prompt_on = [False]                  # no prompt to preserve until the REPL
    sticky_status = {"text": ""}        # persistent footer (not part of scrollback)
    # erase-to-end-of-line only means something on a terminal; redirected output
    # should be plain text
    tty = sys.stdout.isatty()
    CLR = "\r\033[K" if tty else ""

    def _erase_console_ui():
        """Erase the editable prompt and its optional one-line footer.

        The terminal cursor normally lives on the prompt line, one row above the
        footer. Background output clears both rows before printing, then
        ``_redraw`` puts them back at the bottom of the terminal.
        """
        if not prompt_on[0]:
            return
        sys.stdout.write(CLR)
        if tty and sticky_status["text"]:
            sys.stdout.write("\033[1B\r\033[K\033[1A\r")

    def _redraw():
        if not prompt_on[0]:
            return
        sys.stdout.write(CLR + "> " + "".join(editbuf))
        if tty and sticky_status["text"]:
            # The first draw may scroll once to make room; subsequent draws
            # update these same two rows. Finish back on the prompt at the
            # user's actual edit position, leaving the starred result below it.
            sys.stdout.write("\r\n\033[K\033[7m "
                             + sticky_status["text"]
                             + " \033[0m\033[1A\r")
            col = 2 + cur[0]
            if col:
                sys.stdout.write(f"\033[{col}C")
        else:
            # put the terminal cursor back where it belongs inside the line
            back = len(editbuf) - cur[0]
            if tty and back > 0:
                sys.stdout.write(f"\033[{back}D")
        sys.stdout.flush()

    def set_sticky_status(text=""):
        """Set/clear the persistent bottom-of-terminal status line."""
        with out_lock:
            _erase_console_ui()
            sticky_status["text"] = str(text).strip()
            _redraw()

    # Output verbosity. LOG mode (verbose) shows everything — the play-by-play
    # you see now; REGULAR mode shows only the essentials (status, results,
    # errors, replies to what you typed) and drops the high-volume chatter
    # (chat, block dumps, per-scan progress, per-realm crawl detail). Toggle live
    # with the 'log' command; start regular with --quiet.
    disp = {"verbose": not args.quiet}

    # Rolling log for the web console. Every essential line printed to the
    # terminal is also captured here with a monotonic sequence number so the
    # browser can poll /logs?since=N and stream the tail live.
    log_ring = collections.deque(maxlen=500)   # (seq, text) newest last
    log_seq = {"n": 0}
    log_lock = threading.Lock()

    def _log_capture(text):
        with log_lock:
            log_seq["n"] += 1
            log_ring.append((log_seq["n"], str(text)))

    def show_line(text, verbose=False):
        # a 'verbose' line is play-by-play detail: shown in log mode, hidden in
        # regular mode. Essential lines (default) always show.
        if verbose and not disp["verbose"]:
            return
        _log_capture(text)
        with out_lock:
            _erase_console_ui()
            line = str(text) + "\n"
            try:
                sys.stdout.write(line)
            except UnicodeEncodeError:
                # Last-resort guard: never let an un-encodable character (emoji,
                # exotic name) kill the calling thread — the reader thread dying
                # here is what zombifies the bot. Drop to an encodable rendering.
                enc = getattr(sys.stdout, "encoding", None) or "ascii"
                sys.stdout.write(line.encode(enc, "replace").decode(enc, "replace"))
            sys.stdout.flush()
            _redraw()

    def vlog(text):
        """Play-by-play detail: only printed in log (verbose) mode."""
        show_line(text, verbose=True)

    def print(*parts, **kw):             # shadows the builtin for this function
        show_line(kw.get("sep", " ").join(str(p) for p in parts))

    def _recall(delta):
        """Up/down through command history. delta -1 = older, +1 = newer."""
        if not hist:
            return
        if hidx[0] is None:
            if delta > 0:
                return                   # already at the live line
            hidx[0] = len(hist)
        hidx[0] = max(0, min(len(hist), hidx[0] + delta))
        editbuf[:] = [] if hidx[0] == len(hist) else list(hist[hidx[0]])
        cur[0] = len(editbuf)
        if hidx[0] == len(hist):
            hidx[0] = None
        _redraw()

    fifo_state = {"fh": None, "failed": False}
    # Console commands injected over HTTP (/cmd?line=...). The command loop drains
    # this the same way it drains the FIFO, so the team console can drive the bot
    # reliably over HTTP instead of the FIFO. Thread-safe for append/popleft.
    console_inject = collections.deque()

    def _fifo_command():
        """Block until a line is written to the command FIFO, and return it.

        Returns None if no FIFO is configured or it can't be used (Windows has
        no mkfifo), so the caller falls back to parking.

        Two details that matter. The FIFO is opened O_RDWR rather than O_RDONLY:
        a read-only handle hits EOF the moment the last writer closes, which is
        after every single `echo`, and the loop would spin. Keeping a writer of
        our own open means the pipe never signals EOF. And we select() with a
        timeout rather than blocking in readline() so SIGTERM is noticed
        promptly — a blocked read would sit there until systemd gave up waiting
        and sent SIGKILL."""
        path = getattr(args, "command_fifo", "")
        if not path or fifo_state["failed"] or not hasattr(os, "mkfifo"):
            return None
        if not os.path.isabs(path):
            path = os.path.join(_APP_DIR, path)
        try:
            if fifo_state["fh"] is None:
                if not os.path.exists(path):
                    os.mkfifo(path, 0o600)
                elif not stat.S_ISFIFO(os.stat(path).st_mode):
                    show_line(f"  [cmd] {path} exists and is not a FIFO — "
                              f"command pipe disabled")
                    fifo_state["failed"] = True
                    return None
                fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
                fifo_state["fh"] = os.fdopen(fd, "r", buffering=1)
                show_line(f"  [cmd] command pipe ready — send commands with: "
                          f"echo 'market publish' > {path}")
            fh = fifo_state["fh"]
            while not stop.is_set():
                if console_inject:                 # HTTP-injected command
                    return console_inject.popleft()
                if select.select([fh], [], [], 0.5)[0]:
                    line = fh.readline()
                    if line:
                        line = line.strip()
                        if line:
                            show_line(f"  [cmd] {line}")
                            return line
            return None
        except (OSError, ValueError) as e:
            show_line(f"  [cmd] command pipe unavailable ({e}) — "
                      f"running without it")
            fifo_state["failed"] = True
            try:
                if fifo_state["fh"]:
                    fifo_state["fh"].close()
            except OSError:
                pass
            fifo_state["fh"] = None
            return None

    def _read_posix():
        """POSIX raw-mode line reader: the non-Windows twin of the msvcrt editor
        below. Puts the terminal in cbreak mode and reads a key at a time so the
        half-typed prompt survives anything the reader thread prints mid-typing
        (via _redraw under out_lock), and so arrow keys work: up/down recall
        history, left/right move the cursor, Home/End jump, Delete cuts forward.
        Falls back to a plain cooked input() if the tty can't enter cbreak."""
        try:
            import termios, tty
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
        except Exception:
            return input("> ")

        def do_escape(seq):
            """Act on an escape tail like '[A'/'[3~'. Returns chars consumed."""
            if len(seq) < 2 or seq[0] != "[":
                return 0
            code = seq[1]
            with out_lock:
                if code == "A":                                # Up
                    _recall(-1)
                elif code == "B":                              # Down
                    _recall(+1)
                elif code == "C" and cur[0] < len(editbuf):    # Right
                    cur[0] += 1; _redraw()
                elif code == "D" and cur[0] > 0:               # Left
                    cur[0] -= 1; _redraw()
                elif code == "H" and cur[0] != 0:              # Home
                    cur[0] = 0; _redraw()
                elif code == "F" and cur[0] != len(editbuf):   # End
                    cur[0] = len(editbuf); _redraw()
                elif code == "3":                              # Delete = ESC[3~
                    if cur[0] < len(editbuf):
                        del editbuf[cur[0]]; _redraw()
                    return 3                                   # consumed '[3~'
            return 2                                           # consumed '[X'

        # Read the RAW fd with os.read (NOT sys.stdin, which is buffered — mixing
        # a buffered read with select() is what froze input before).
        buf = ""
        try:
            tty.setcbreak(fd)          # char-at-a-time; keeps OPOST + Ctrl-C
            with out_lock:
                _redraw()
            while True:
                if not buf:
                    if not select.select([fd], [], [], 0.25)[0]:
                        if stop.is_set():
                            return "quit"
                        continue
                    try:
                        chunk = os.read(fd, 256)
                    except OSError:
                        continue
                    if not chunk:
                        if stop.is_set():
                            return "quit"
                        continue
                    buf += chunk.decode("utf-8", "ignore")
                ch = buf[0]; buf = buf[1:]
                if ch == "\x1b":                       # escape sequence
                    # make sure the tail is present (it usually arrived together)
                    if len(buf) < 3 and select.select([fd], [], [], 0.02)[0]:
                        try:
                            buf += os.read(fd, 16).decode("utf-8", "ignore")
                        except OSError:
                            pass
                    consumed = do_escape(buf)
                    buf = buf[consumed:]
                    continue
                if ch == "\x03":                       # Ctrl-C
                    raise KeyboardInterrupt
                if ch in ("\r", "\n"):                 # Enter
                    line = "".join(editbuf)
                    if line.strip() and (not hist or hist[-1] != line):
                        hist.append(line)
                    hidx[0] = None
                    del editbuf[:]; cur[0] = 0
                    with out_lock:
                        _erase_console_ui()
                        sys.stdout.write("> " + line + "\n")
                        sys.stdout.flush()
                    return line
                if ch in ("\x7f", "\b"):               # Backspace
                    if cur[0] > 0:
                        del editbuf[cur[0] - 1]; cur[0] -= 1
                        with out_lock:
                            _redraw()
                    continue
                if ch < " ":                           # other control char
                    continue
                editbuf.insert(cur[0], ch); cur[0] += 1  # insert at cursor
                with out_lock:
                    _redraw()
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            except Exception:
                pass

    def read_command():
        """Read one command line with in-line editing, surviving anything the
        reader thread prints mid-typing.

        With no terminal attached (systemd, nohup, cron) there is nothing to
        read: input() would hit EOF immediately, the command loop would end and
        the bot would shut down seconds after starting.

        So when headless we read from the command FIFO instead (--command-fifo),
        which makes every console command usable while the bot runs as a
        service:  echo 'market publish' > bot.cmd
        Output goes wherever the service's stdout goes — the journal. With no
        FIFO configured we just park and let the scan/crawl threads work.

        Left/right move the cursor, up/down recall history, Home/End jump, and
        Delete/Backspace cut on either side. Windows uses msvcrt; other platforms
        use _read_posix (termios cbreak), so both get the same editing and both
        keep the prompt intact when the reader thread prints mid-typing."""
        if getattr(args, "headless", False):
            interactive = False        # forced headless (GUI-spawned child)
        else:
            try:
                interactive = sys.stdin is not None and sys.stdin.isatty()
            except (ValueError, AttributeError):
                interactive = False    # stdin closed or replaced
        if not interactive:
            line = _fifo_command()
            if line is not None:
                return line
            # no FIFO configured: still honour HTTP-injected commands
            while not stop.is_set():
                if console_inject:
                    return console_inject.popleft()
                stop.wait(0.3)
            return "quit"
        prompt_on[0] = True
        if msvcrt is None:
            return _read_posix()
        with out_lock:
            _redraw()
        while True:
            ch = msvcrt.getwch()
            if ch in ("\x00", "\xe0"):   # extended key: a second wchar follows
                code = msvcrt.getwch()
                with out_lock:
                    if code == "K" and cur[0] > 0:            # left
                        cur[0] -= 1; _redraw()
                    elif code == "M" and cur[0] < len(editbuf):  # right
                        cur[0] += 1; _redraw()
                    elif code == "G" and cur[0] != 0:         # Home
                        cur[0] = 0; _redraw()
                    elif code == "O" and cur[0] != len(editbuf):  # End
                        cur[0] = len(editbuf); _redraw()
                    elif code == "S" and cur[0] < len(editbuf):  # Delete
                        del editbuf[cur[0]]; _redraw()
                    elif code == "H":                         # Up
                        _recall(-1)
                    elif code == "P":                         # Down
                        _recall(+1)
                continue
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch in ("\r", "\n"):
                line = "".join(editbuf)
                if line.strip() and (not hist or hist[-1] != line):
                    hist.append(line)
                hidx[0] = None
                del editbuf[:]; cur[0] = 0
                with out_lock:
                    _erase_console_ui()
                    sys.stdout.write("> " + line + "\n")
                    sys.stdout.flush()
                return line
            if ch in ("\b", "\x7f"):                          # Backspace
                if cur[0] > 0:
                    del editbuf[cur[0] - 1]; cur[0] -= 1
                    with out_lock:
                        _redraw()
                continue
            if ch < " ":
                continue
            editbuf.insert(cur[0], ch); cur[0] += 1           # insert at cursor
            with out_lock:
                _redraw()

    if not args.i_accept_live_risk:
        print("REFUSING to connect.\n")
        print("Live mode connects a third-party client to live.castles.cc using your")
        print("real account login. This can get your account flagged/banned, and the")
        print("server may also reject a non-Steam client outright. If you accept that")
        print("risk, re-run with:  --i-accept-live-risk")
        return 2

    try:
        import websocket  # websocket-client
    except ImportError:
        print("live mode needs websocket-client:  pip install websocket-client")
        return 1

    # the profile lives next to this script, so a bare default works from anywhere
    prof_path = args.login_from
    if not os.path.exists(prof_path):
        prof_path = os.path.join(_APP_DIR,
                                 args.login_from)
    # when frozen into a PyInstaller exe, bundled data lands in sys._MEIPASS
    if not os.path.exists(prof_path):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            bundled = os.path.join(meipass, os.path.basename(args.login_from))
            if os.path.exists(bundled):
                prof_path = bundled
    prof = json.load(open(prof_path, encoding="utf-8"))
    hello_empty = bytes.fromhex(prof["hello_empty"])
    hello_auth = bytes.fromhex(prof["hello_auth"])
    # Display names are public in-game; account ids and replay material are not.
    print(f"login profile: {prof['identity']['display_name']} (account id redacted)")

    # --- ROLE: 'front' (default, full behaviour) vs 'worker' -----------------
    # A 'worker' is a second account meant to run alongside the front bot in the
    # team console (cc_team.py). It does movement, warps, auto-Hollawarp and its
    # half of a prize crack, but stays SILENT: no public chat, no whispers, no
    # announce, no trades/register. Silence is enforced at the outbound choke
    # points (chat_say / pub_say / whisper_say) and at handle_trade_request, so
    # every code path that would talk or trade is covered by this one flag.
    WORKER_SILENT = (getattr(args, "role", "front") == "worker")
    if WORKER_SILENT:
        print("  [role] WORKER — silent: no chat/whisper/announce/trades "
              "(warps, hollas, movement, prize crack still active)")

    # --- DEBUG frame log (set CC_FRAMELOG=<path> to enable) ------------------
    # Records every TX/RX frame type + any server-notice text, plus the login
    # handshake, so a rejected/expired token or a version gate is visible on the
    # wire. No-op when the env var is unset.
    import os as _os
    _flog_path = _os.environ.get("CC_FRAMELOG")
    _flog = open(_flog_path, "a", encoding="utf-8", buffering=1) if _flog_path else None
    def flog(direction, body, note=""):
        if not _flog:
            return
        try:
            bt = P.body_type(body)
            bts = f"0x{bt:04x}" if bt is not None else "----"
            txt = ""
            try:
                nt = P.parse_notice(body) or P.parse_notice_00de(body)
                if nt:
                    txt = f" NOTICE={nt!r}"
            except Exception:
                pass
            _flog.write(f"{time.time():.3f} {direction:2s} {bts} "
                        f"{len(body):5d}B{txt}{note}  {body[:80].hex()}\n")
        except Exception as e:
            try:
                _flog.write(f"{time.time():.3f} {direction} LOGERR {e}\n")
            except Exception:
                pass

    # the realm-registration GUID from the most recent login response; it changes
    # each time we enter a realm and is the candidate for the browser Share
    # link's realm= token
    reg = {"guid": None}

    # The official executable keeps this counter in one process-global u32. It
    # is not reset by a realm handoff; only a fresh client process starts at 0.
    # It must exist before login_on(): the realm-registration ENTER/READY
    # packets are the first three packets sent through the negotiated cipher.
    outer_send = {"counter": 0}

    def encode_session_frame(body, key_words_, outer_key):
        """Build one gameplay wire frame and advance the official send counter.

        POST_LOGIN is deliberately sent without ``outer_key``. Once the server
        replies with its key offer, every later client packet -- beginning with
        the two ENTER packets and READY -- uses this outer layer.
        """
        inner = P.encrypt_frame(body, key_words_)
        if not outer_key:
            return inner
        counter = outer_send["counter"]
        outer_send["counter"] = (counter + 1) & 0xFFFFFFFF
        return SEND_CIPHER.encode(inner, outer_key, counter)

    # A normal browser User-Agent. websocket-client sends NO User-Agent header
    # by default; as of 2026-08-31 the Cloudflare bot-fight Worker in front of
    # prod.castles.cc 400s an empty-UA upgrade from a flagged IP (the deploy box
    # is one), while curl — which sends a UA — is let through from that same box.
    WS_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

    def wsopen(url):
        # Two Cloudflare-driven handshake requirements, both found 2026-08-31:
        #   suppress_origin — websocket-client otherwise stamps
        #     `Origin: http://<host>`; the prod Worker rejects that self-Origin
        #     (the real client's Origin is its game page, not the backend host).
        #   User-Agent      — an empty UA is scored as a bot and 400'd.
        # curl (real UA, no Origin) is accepted on both hops, so we mirror it.
        return websocket.create_connection(url, timeout=15,
                                           enable_multithread=True,
                                           suppress_origin=True,
                                           header=[f"User-Agent: {WS_UA}"])

    def recv_bin(ws):
        d = ws.recv()
        return d.encode("latin1") if isinstance(d, str) else d

    def login_on(ws, send_post):
        """Send the authenticated hello and recover the session key. Only send
        POST_LOGIN when send_post is True (initial login, to get the friends
        list + world data). Teleport re-logins pass False to stay light — the
        big POST_LOGIN world burst interferes with the next teleport's handoff.
        Returns (key_words, own_guid_hex, outer_key), or Nones if rejected."""
        ws.settimeout(15)
        if _flog:
            _flog.write(f"{time.time():.3f} -- LOGIN hello_auth {len(hello_auth)}B "
                        f"{hello_auth[:80].hex()}\n")
        ws.send_binary(hello_auth)
        response = None
        for _ in range(6):
            f = recv_bin(ws)
            if _flog:
                _flog.write(f"{time.time():.3f} RX login-frame "
                            f"type=0x{(P.body_type(f) or 0):04x} {len(f)}B "
                            f"{f[:80].hex()}\n")
            if P.body_type(f) == 0x0002 and len(f) > 60:
                response = f
                break
        if response is None:
            if _flog:
                _flog.write(f"{time.time():.3f} -- LOGIN NO 0x0002 RESPONSE "
                            f"(token likely rejected)\n")
            return None, None, None
        kw = None
        probed = []                # frames read while hunting for the key
        for _ in range(8):
            try:
                nxt = recv_bin(ws)
            except Exception:
                break
            probed.append(nxt)
            rec = P.recover_key_from_response(response, nxt)
            if rec:
                kw = rec[0]
                break
        if kw is None:
            if _flog:
                _flog.write(f"{time.time():.3f} -- LOGIN KEY-RECOVERY FAILED "
                            f"(response {len(response)}B, {len(probed)} probed "
                            f"frames) — session key not issued\n")
            return None, None, None
        if _flog:
            _flog.write(f"{time.time():.3f} -- LOGIN OK: key recovered, "
                        f"response {len(response)}B, {len(probed)} probed frames; "
                        f"decoding them:\n")
            for wire in probed:
                try:
                    _, db, dt = P.decrypt_frame(wire, kw)
                    if dt:
                        flog("RX", db, note="  [post-login]")
                except Exception:
                    pass
        # The realm-identity (rx 0x005f) that names the realm we just entered
        # fires right after login, so it is usually one of the frames we just
        # consumed while recovering the key. The reader never sees those, so
        # capture the realm name/owner here and apply it (once reg["guid"] is
        # set, below) — otherwise a teleport onto a player would leave the
        # current realm stuck on the one we logged in from, so `watch` and the
        # market DB recorded the wrong realm.
        realm_info = None
        outer_key = None
        outer_offer_seen = False
        for wire in probed:
            try:
                _, pbody, pterm = P.decrypt_frame(wire, kw)
            except Exception:
                continue
            if not pterm:
                continue
            if P.body_type(pbody) == 0x005f:
                ri = P.parse_realm_id(pbody)
                if ri and ri.get("realm"):
                    realm_info = ri
            offered = SEND_CIPHER.parse_key_offer(pbody)
            if offered is not None:
                outer_key = offered
                outer_offer_seen = True
        # our own player GUID sits right after the echoed name/account strings
        own = None
        try:
            rr = P.Reader(response); rr.u16(); rr.u16(); rr.s(); rr.s()
            own = response[rr.p:rr.p + 16].hex()
        except Exception:
            pass
        if send_post:
            post = P.build_post_login(response)
            if post:
                # POST_LOGIN is the final ordinary XXTEA-only client packet.
                # The server answers it with the session's send-cipher key.
                ws.send_binary(P.encrypt_frame(post, kw))

            # The official client waits here. Previously we sent ENTER/READY
            # first and only let reader() consume this offer afterward, leaving
            # the account visible in-world but not fully registered; teleport
            # requests were then silently refused.
            deadline = time.time() + 15.0
            while not outer_offer_seen and time.time() < deadline:
                try:
                    wire = recv_bin(ws)
                except websocket.WebSocketTimeoutException:
                    continue
                body = None
                try:
                    _, body, term = P.decrypt_frame(wire, kw)
                except Exception:
                    term = False
                if not term:
                    continue
                flog("RX", body, note="  [awaiting send key]")
                if P.body_type(body) == 0x005f:
                    ri = P.parse_realm_id(body)
                    if ri and ri.get("realm"):
                        realm_info = ri
                offered = SEND_CIPHER.parse_key_offer(body)
                if offered is not None:
                    outer_key = offered
                    outer_offer_seen = True

            if not outer_offer_seen:
                raise RuntimeError("server did not supply the send-cipher key")
            if outer_key:
                show_line("  [transport] official send cipher enabled "
                          f"({len(outer_key)}-byte session key, counter "
                          f"{outer_send['counter']})")
            else:
                show_line("  [transport] server supplied an empty send key; "
                          "outer cipher remains disabled")
        # Realm-registration handshake: normally send 0x000e for our own guid
        # and the realm-registration guid (both from the response), then a
        # 0x0012 ready ping.  In the experimental --no-avatar mode, omit the
        # own-guid ENTER as well as suppressing movement announcements.  The
        # movement-only experiment proved that the server creates the player
        # entity during registration, before the first MOVE.  Keeping the realm
        # ENTER + READY gives the server a chance to deliver the world without
        # explicitly registering the player object.  Some backends may reject
        # or partially initialize this nonstandard sequence.
        try:
            g_own, g_realm = P.guids_from_response(response)
            if g_own and g_realm:
                reg["guid"] = g_realm.hex()
                first_counter = outer_send["counter"]
                registration = []
                if not args.no_avatar:
                    registration.append((P.build_enter(g_own), "own ENTER"))
                registration.extend((
                    (P.build_enter(g_realm), "realm ENTER"),
                    (P.w_u16(0x0012), "READY"),
                ))
                for reg_body, reg_note in registration:
                    flog("TX", reg_body, note=f"  [registration: {reg_note}]")
                    ws.send_binary(encode_session_frame(
                        reg_body, kw, outer_key))
                if args.no_avatar:
                    show_line("  [no-avatar] experimental: skipped own-GUID "
                              "registration and will suppress movement")
                if outer_key:
                    show_line("  [transport] encrypted realm registration sent "
                              f"(counters {first_counter}-"
                              f"{outer_send['counter'] - 1})")
        except Exception:
            pass
        # Stash the realm identity we captured (if any) for the caller to apply
        # once the connection is swapped in — a teleport/join re-login reads it
        # from here (see do_teleport). Applying it directly here isn't safe: the
        # very first login runs before apply_realm_id and the realm state exist.
        # On the initial login the realm 0x005f usually arrives later in the
        # POST_LOGIN burst and the reader handles it as before.
        reg["realm_info"] = realm_info
        ws.settimeout(1.0)
        return kw, own, outer_key

    def enter_backend(host, selector, send_post):
        """Connect to a backend selector and authenticate.
        Returns (ws, key_words, own_guid_hex, outer_key).

        Post the 2026-08-31 game update, the real client does the backend hop on
        the SAME edge host as the load-balancer hop (args.host, live.castles.cc)
        and never connects to the host named in the 0x0019 handoff frame
        (prod.castles.cc). prod is now behind a Cloudflare bot-fight Worker that
        throttles/400s automated handshakes; live.castles.cc has no such Worker.
        So we connect the handed-off SELECTOR on args.host, matching the client
        exactly, and only LOG the handoff host. Verified by
        capture-20260831-150028-cloudflare-login: the client played entirely over
        live.castles.cc/<selector> and the string 'prod.castles.cc' never appears.
        See memory cubic-castles-cloudflare-handshake."""
        connect_host = args.host
        if host and host != connect_host:
            print(f"  (handoff named {host}; connecting {connect_host} like the "
                  f"real client — prod is Cloudflare-gated)")
        url = f"ws://{connect_host}:{args.port}/{selector}"
        print(f"  connecting {url}")
        ws = wsopen(url)
        try:
            kw, own, outer_key = login_on(ws, send_post)
        except Exception:
            ws.close()
            raise
        if kw is None:
            ws.close()
            raise RuntimeError("login rejected on backend")
        return ws, kw, own, outer_key

    def full_connect(send_post):
        """The whole connect handshake from scratch: load-balancer hello ->
        backend handoff -> backend login. Returns
        (ws, key_words, own_guid, outer_key) or raises. Used for the first login
        AND for every auto-reconnect."""
        try:
            lb = wsopen(f"ws://{args.host}:{args.port}{args.path}")
        except Exception as e:
            # Cloudflare can reject the WS UPGRADE outright (HTTP 400/403) before
            # any frame — record that too so the log distinguishes 'blocked at the
            # door' from 'connected but no handoff frame'.
            if _flog:
                _flog.write(f"{time.time():.3f} -- LB UPGRADE FAILED "
                            f"{type(e).__name__}: {e}\n")
            raise
        print(f"  connecting ws://{args.host}:{args.port}{args.path}")
        if _flog:
            _flog.write(f"{time.time():.3f} -- LB CONNECT "
                        f"ws://{args.host}:{args.port}{args.path} "
                        f"hello {len(hello_empty)}B {hello_empty[:80].hex()}\n")
        lb.send_binary(hello_empty)
        handoff = recv_bin(lb)
        # Log the RAW first reply (full hex + printable ASCII). This is the exact
        # payload behind 'no backend handoff' — a Cloudflare throttle/notice or an
        # unexpected frame shows up here so we can see what the server actually
        # sent instead of the expected 0x0019 backend-handoff.
        if _flog:
            bt = P.body_type(handoff)
            ascii_view = "".join(chr(b) if 32 <= b < 127 else "." for b in
                                 handoff[:512])
            _flog.write(f"{time.time():.3f} RX LB-first-reply "
                        f"type=0x{(bt or 0):04x} {len(handoff)}B\n"
                        f"    hex   : {handoff[:512].hex()}\n"
                        f"    ascii : {ascii_view}\n")
        if P.body_type(handoff) != 0x0019:
            lb.close()
            raise RuntimeError("unexpected first reply (no backend handoff)")
        host, selector = P.parse_backend_handoff(handoff)
        print(f"  backend handoff -> {host} path /{selector}")
        lb.close()
        return enter_backend(host, selector, send_post=send_post)

    # --- initial connect ---
    try:
        ws, key_words, own_guid, outer_key = full_connect(send_post=True)
    except Exception as e:
        print(f"  connect failed: {e}"); return 1
    print("  login accepted; in world.")

    # shared connection state (swapped on teleport), guarded by lock
    conn = {"ws": ws, "key": key_words, "own": own_guid,
            "outer_key": outer_key}
    lock = threading.Lock()
    stop = threading.Event()

    def encode_outbound(body, key_words_, outer_key):
        """Build one wire frame, including the negotiated official outer layer.

        Callers hold ``lock``, which makes the global counter increment atomic
        with respect to the socket send.
        """
        return encode_session_frame(body, key_words_, outer_key)

    # Under systemd, `systemctl stop|restart` sends SIGTERM. Python's default is
    # to die on the spot, which can land in the middle of writing vends.json or
    # a DB transaction. Setting `stop` instead releases the command loop so the
    # normal shutdown path runs: socket closed, DB closed, files intact.
    # SIGINT is deliberately left alone — the interactive session relies on
    # Ctrl-C raising KeyboardInterrupt, and handling it here would swallow that.
    def _on_sigterm(signum, _frame):
        stop.set()

    try:
        signal.signal(signal.SIGTERM, _on_sigterm)
    except (ValueError, OSError, AttributeError):
        pass                           # not the main thread, or no SIGTERM

    switching = threading.Event()
    reconnecting = threading.Event()   # a kick-recovery is rebuilding the socket
    # Deliberate log-off (web/console 'disable'): take THIS account offline and
    # KEEP it off (auto-reconnect suppressed) until 'enable'. The process stays
    # alive on the command loop so it can be brought back. reader_holder keeps
    # the supervised-reader thread handle so go_online can restart it (the reader
    # ends when the socket is closed with auto-reconnect off).
    manual_offline = {"on": False, "prev_reconnect": True}
    reader_holder = {"t": None}
    # last time ANY frame arrived — the watchdog uses this to catch a SILENT kick
    # (server stops talking but never closes the socket, so recv just times out
    # forever). Bumped on every successful read and after each (re)connect.
    net = {"last_rx": time.time()}
    pending = {"guid": None, "autoscan": False, "watch_if_vends": False}
    # Installed after world/query/movement helpers are defined.  Keeping the
    # holder here lets queueing and realm-change guards see a build without a
    # circular dependency on the later adapter setup.
    build_runtime = {"controller": None}
    # Realm identity changes and verified placement sends share this lock.  A
    # placement is therefore either completed in the old confirmed realm or sees
    # the new identity and refuses; it cannot race across the boundary.
    build_action_lock = threading.RLock()
    # Bulk realm crawl: join realm-by-realm (0x00d3, no player), let the autoscan
    # scan each, move on. 'arrived' fires on entry, 'event' when that realm's
    # scan cycle is done — the driver waits on both. GUID-join means we never
    # need anyone to be in the realm.
    crawl = {"active": False, "stop": False, "pending_targets": None,
             "resolve_each": False,
             "arrived": threading.Event(), "event": threading.Event()}
    scanning = threading.Event()
    # True through the autoscan settle-wait AND its scan, so a queued move can't
    # yank us out of a realm before the auto-scan that entry armed has finished.
    autoscan_active = threading.Event()
    # Set while a synthetic walk (walk_to) is actively stepping the avatar, so the
    # 1-Hz keepalive doesn't inject a zero-velocity "stopped" frame mid-stride
    # (which would stutter the walk animation on other clients).
    walking = threading.Event()
    # --- movement command queue -------------------------------------------
    # tp / guid / joinrealm / summon / web-console moves are QUEUED here instead
    # of firing the instant they arrive. A command that lands while the bot is
    # mid-scan, mid-crawl, or mid-Hollawarp waits its turn (FIFO) and runs once
    # the bot is free, instead of pulling it out of the realm it's working — and
    # a second command no longer overwrites the first. Internal driver moves
    # (crawl's next realm, Hollawarp's next warp, park) keep setting pending[...]
    # directly: they ARE the busy work and sequence themselves.
    cmdq = collections.deque()        # items: kind/value/label + scan options
    cmdq_lock = threading.Lock()

    def bot_busy():
        """True while the bot is doing something a stray move would wreck: a
        scan, an armed auto-scan, a crawl, the Hollawarp driver, or an in-flight
        realm switch. Queued commands wait until this goes False."""
        builder = build_runtime.get("controller")
        return (scanning.is_set() or autoscan_active.is_set()
                or crawl["active"] or hollow["driver"] or scanbot["active"]
                or switching.is_set() or bool(builder and builder.active))

    def queue_move(kind, value, label, autoscan=False, watch_if_vends=False):
        """Queue a user movement request. kind 'guid' = teleport to a player,
        'join' = join a realm by GUID. Runs when the bot is next free; if it's
        busy it lines up behind whatever's ahead of it. Scan options are copied
        to pending when the move starts. Returns the queue depth (1 = it's next)."""
        with cmdq_lock:
            cmdq.append({"kind": kind, "value": value, "label": label,
                         "autoscan": autoscan,
                         "watch_if_vends": watch_if_vends})
            depth = len(cmdq)
        if bot_busy():
            show_line(f"  queued: {label}  (bot busy — #{depth} in line, runs "
                      f"when free)")
        return depth

    friends = {}
    requests = {}        # outstanding friend requests from rx 0x0027 (name -> guid)
    known = {}           # name.lower() -> guid, resolved by the `guid` command
    lookup = {"name": None, "guid": None, "match_name": None,
              "event": threading.Event()}

    def _alnum(s):
        """Name reduced to lowercase letters+digits only — so a name typed with
        plain quotes/spaces matches the server's version with fancy quotes,
        odd spacing, or other decoration ('\"Draco\"' == '“Draco”' == 'draco')."""
        return "".join(ch for ch in s.lower() if ch.isalnum())

    # Passive registry of players seen this session: their live GUID keyed from
    # 0x0005 player-state (which carries display name + GUID together). This
    # resolves names the FRIEND system rejects — decorated names with quotes or
    # symbols — because it never sends a request, it just reads who's present.
    players = {}          # guid_hex -> display name (session-wide)
    realm_players = set()  # guids confirmed in the CURRENT realm (cleared on hop)
    # Mannequins render as ENTITIES (rx 0x0005 with an EMPTY name — real players
    # have names), broadcast as you walk past. We can't cleanly parse the outfit
    # out of 0x0005 (it's tangled with position/appearance), but its coords give
    # the mannequin's block, which we then read reliably via 0x0014 -> 0x000e.
    mannequin_seen = {}   # (bx,by,bz) -> entity guid; cleared on realm hop
    # Facing has no standalone field (SCHEMA 0x0006 — it's the direction of the
    # velocity vector), so we learn which way a player is facing by watching their
    # position move between 0x0005 updates. `player_heading` keeps each player's
    # last real step direction as a (vx,vy) at WALK_SPEED, so a follow-teleport
    # can turn to face the same way on arrival.
    player_pos = {}       # guid -> (x,y) last seen (for computing heading)
    player_heading = {}   # guid -> (vx,vy) their last movement direction
    player_block = {}     # guid -> (bx,by,bz) last block they stood on

    def track_player_heading(guid, x, y, z=None):
        if z is not None:
            player_block[guid] = (x // P.COORD_BASE, y // P.COORD_BASE,
                                  z // P.COORD_BASE)
        prev = player_pos.get(guid)
        player_pos[guid] = (x, y)
        if prev is None:
            return
        import math
        dx, dy = x - prev[0], y - prev[1]
        dist = math.hypot(dx, dy)
        if dist >= (P.WALK_TICK or 1) * 0.3:   # a real step, not idle jitter
            player_heading[guid] = (int(dx / dist * P.WALK_SPEED),
                                    int(dy / dist * P.WALK_SPEED))

    def find_player_by_name(name):
        """GUID of a player seen in-world by (display) name: exact first, then
        the forgiving alphanumeric match. None if we haven't seen them."""
        for g, nm in players.items():
            if nm.lower() == name.lower():
                return g
        key = _alnum(name)
        if key:
            for g, nm in players.items():
                if _alnum(nm) == key:
                    return g
        return None
    # Realm-browser search (tx 0x00c8 -> rx 0x00e1 markup). Realm GUIDs are NOT
    # stable — a realm gets a fresh GUID each time it's hosted — so we resolve
    # the current one by NAME at join time instead of trusting a saved GUID.
    realm_search = {"want": None, "guid": None, "match_name": None,
                    "results": [], "then_join": False, "then_scan": False,
                    "event": threading.Event(), "browser_open": False}
    # Auto-Hollawarp: join every Hollawarp broadcast, scan it, watchlist it if it
    # has vends, then park. Dedup by GUID via `seen`; first few detections dumped
    # raw (dumps) as a sanity check on the parser.
    # `seen` maps realm GUID -> last time we joined it. Re-warping to the same
    # realm every time it hollers is an obvious bot tell, so a realm that hollers
    # again inside `cooldown` seconds is ignored; after the window it's eligible
    # again (which also refreshes its prices). `hwarp cooldown <sec>` tunes it.
    hollow = {"auto": args.auto_hollowarp, "q": [], "seen": {},
              "driver": False, "dumps": 0, "cooldown": 600.0}
    # Price chatbot (OFF by default): when on, answer in-game chat that addresses
    # the bot by name asking "price of <item>", looking the item up in the
    # community price list and replying with its current price string.
    # delay   : seconds to wait before replying (feels less bot-like)
    # cooldown: minimum gap between ANY two replies (global anti-spam)
    # per_user: minimum gap between replies to the SAME player (anti-spam)
    # seen    : sender guid -> last time we answered them
    pricebot = {"on": False, "map": {}, "fetched": 0.0, "last_reply": 0.0,
                "delay": 1.5, "cooldown": 3.0, "per_user": 15.0, "seen": {},
                "url": _veil("CxdZBhZTQwJUBR0TDAxZBRYMHltSFEBPAAxAWQEIGEwYBVwMDhZDHxEQM11FD1AEEE1HBQoH")}
    # QUIZ auto-answer bot (OFF by default; Stage 18). A trivia HOST asks
    # questions in public chat; the bot computes the answer INSTANTLY from its
    # offline brain (cc_quiz — math is computed, facts are looked up, and every
    # answer the host reveals is learned forever), then plays the game's
    # turn-taking etiquette: it "raises its hand" by typing `raise_word`
    # ("question") and HOLDS the answer until the host says a go-ahead phrase
    # ("you're allowed to talk"), at which point it drops the ready answer with
    # no delay. Only reacts to the one designated `host`.
    #   host      : lowercased display name of the question-giver (None = unset,
    #               bot stays silent until you set one)
    #   gate      : True = obey turn-taking (raise hand, wait for go-ahead);
    #               False = answer the instant the host asks
    #   min_conf  : lowest answer confidence the bot will speak (math/exact/
    #               learned are 1.0; fuzzy matches must clear this)
    #   pending   : {q, a, raised} an answer held awaiting the go-ahead
    #   last_q    : last question seen from the host, so a later "the answer is
    #               X" reveal can be learned against it
    quizbot = {
        "on": False, "host": None, "gate": True, "min_conf": 0.9,
        # raise_hand: type "question" when a question is detected (hand-raising
        # etiquette). OFF for this game — the host just mutes/unmutes, so the bot
        # simply HOLDS the answer and speaks it on unmute, nothing else.
        "auto_learn": True, "raise_hand": False, "raise_word": "question",
        "timeout": 120.0,
        "go_phrases": ["you're allowed to talk", "youre allowed to talk",
                       "you are allowed to talk", "allowed to talk",
                       "you can talk", "you may talk", "go ahead", "your turn",
                       "you're up", "youre up"],
        "pending": None, "last_q": None, "answered": 0, "learned": 0,
        # CROWD LEARNING: in this game the crowd shouts answers right after the
        # realm unmutes. `round` captures the current question and, between unmute
        # and the next mute, every player answer; when the round closes the most-
        # agreed answer is LEARNED. So the bot teaches itself from watching, even
        # when nobody says "the answer is X". min_agree = how many players must
        # give the same answer before the crowd is trusted; min_margin = how far
        # the top answer must BEAT the runner-up (so a near-tie like usa=5 /
        # south-africa=4 / russia=4 is REJECTED rather than learned wrong — in a
        # guessing game the plurality is often not the correct answer).
        "round": None, "min_agree": 3, "min_margin": 2,
        "brain": None,
    }
    if cc_quiz is not None:
        _quiz_learned = os.path.join(_APP_DIR,
                                     getattr(args, "quiz_learned_file",
                                             "quiz_learned.json"))
        try:
            quizbot["brain"] = cc_quiz.QuizBrain(learned_path=_quiz_learned)
        except Exception as _e:
            quizbot["brain"] = None

    # Idle wander (ON): while a scan runs the avatar would otherwise stand dead
    # still — an obvious bot tell. When on, it strolls one walk tick at a time
    # within `radius` ticks of the spawn spot, then returns there. Radius is kept
    # small so machine queries/opens don't drift out of range. `wander off` /
    # `wander <radius>` tune it at runtime.
    # `on` now gates the OFF-MAP hide (below), not the old walk-the-aisles wander
    # which is gone. On any scan-join the avatar is relocated to a FIXED ABSOLUTE
    # spot — `offmap_x/y/z` in BLOCKS (× COORD_BASE), default (0,0,0) — so it's out
    # of sight while it lingers in a stranger's realm. `radius` is kept only for
    # the idle-glance behavior. `offmap <x> <y> <z>` tunes it at runtime.
    wander = {"on": not getattr(args, "no_wander", False),
              "active": False, "radius": 2,
              "offmap_x": args.offmap_x, "offmap_y": args.offmap_y,
              "offmap_z": args.offmap_z}
    # Hard movement freeze (OFF by default): when frozen, NOTHING moves the avatar
    # — no wander, no idle turns, no jumps, no walk_to. `freeze`/`unfreeze` (and a
    # console button) toggle it; the prize crack sets it for its whole run.
    movelock = {"frozen": False}
    # Summon (OFF by default): let players in the bot's realm type 'summon <name>'
    # in chat to make the bot teleport to them. Guarded to same-realm only.
    summon = {"on": False}
    # Scan-on-command (OFF by default): when on, a player in the bot's realm can
    # type 'scan realm <exact name>' (addressing the bot by name) to make it
    # search that realm by name, join it, and scan its vending machines into the
    # market DB. Same-realm requester guard + rate limit, like summon.
    scanbot = {"on": False, "last": 0.0, "active": False}
    world = {}           # guid -> world object (blocks / goods on display)
    # Diagnostic for the "blocks reads flaky/partial" bug: parse_world_objects
    # drops an ENTIRE 0x000f/0x0021 frame when its payload isn't an exact multiple
    # of the record size, so a burst of build blocks can vanish silently. Tally
    # every frame we RECEIVE vs. what parsed, and remember the odd remainders so a
    # live reading tells us the real record layout instead of us guessing.
    #   frames/objs = clean frames and objects kept
    #   dropped     = frames discarded whole (payload % record_size != 0)
    #   remainders  = {(src, leftover_bytes): count} — the smoking gun
    world_diag = {"frames": 0, "objs": 0, "dropped": 0,
                  "remainders": collections.Counter()}
    world_rx = {"last": 0.0}
    offers = {}          # machine guid -> {"block", "machine", "text", "offer"}
    # Monotonic "a realm scan finished" counter. Bumped on EVERY scan completion
    # (typed, remote, auto-Hollawarp, or the auto-scan a `guid` teleport triggers)
    # so a remote caller can start a scan, note the value, and poll until it
    # advances = the whole realm has been scanned. See /scanstatus.
    remote_scan = {"seq": 0}
    qwait = {"block": None, "reply": None, "event": threading.Event(),
             "batch": False}
    # The ordered inventory array is security-critical for placement: tx 0x000b
    # selects by the array's CURRENT zero-based slot, not by catalogue item id.
    # Keep only snapshots addressed to our own player GUID; object inventories
    # share the same rx type and must never be mistaken for ours.
    player_inventory = {"snapshot": None, "seq": 0,
                        "event": threading.Event(),
                        "lock": threading.Lock()}
    # mannequin/object-contents wait: reader latches an rx 0x000e whose guid
    # matches the object we queried with tx 0x000e (build_query_object).
    mwait = {"guid": None, "inv": None, "event": threading.Event()}
    qcache = {}          # block -> last 0x0014 reply, filled by the reader
    dwait = {"active": False, "dialog": None, "event": threading.Event()}
    # register-open probe: openreg sets active, then the 0x00a8 reader latches the
    # trade request the server sends back when we open a register (tx 0x00a4).
    regwait = {"active": False, "req": None, "event": threading.Event()}
    # filled by the reader when an "Enter Sign Text" prompt (rx 0x00c8) arrives
    # after placing a sign — carries the new sign's guid so placesign can write.
    sign_wait = {"active": False, "guid": None, "event": threading.Event()}
    # --- buy orders (owner-only; console-driven, never a chat command) -------
    # A standing order buys an item off the ALREADY-SCANNED list whenever a known
    # machine offers it at or below a price. The whole purchase protocol is decoded
    # in memory/cubic-castles-purchase-flow: open 0x010f -> dialog 0x00ca -> confirm
    # 0x00ca+01 (spends) -> success 0x0037 INVENTORY_CHANGED / failure 0x00de
    # "Not enough Cubits!". The live wallet balance rides in 0x0011 (offset 4,
    # u32le). There is no arm/dry-run gate: an order buys immediately when it
    # matches. The guards (price ceiling, optional budget/qty, per-machine dedup,
    # wallet pre-check) are the safety.
    wallet = {"cubits": None}
    buy_orders = []      # [{item, max_price, qty, budget, spent, bought, active, dedup}]
    # reader latches the outcome of a confirm we just sent (0x0037 vs 0x00de)
    buywait = {"active": False, "result": None, "text": None,
               "event": threading.Event()}
    # AUTO-SNIPE (Stage 17, ON by default). A standing "buy any giveaway" rule
    # that needs NO per-item order: whenever a scanned listing is priced at or
    # below `steal_max` cubits (default 1c — a mis-listing / typo) AND that item
    # is genuinely valuable — its community-price average (community_prices.json)
    # is at least `min_avg` cubits (default 2,000) — buy it on the spot. Both
    # gates must hold, so a cheap item listed cheap is never touched (a 600c
    # Santa Nightcap, avg ~1,500, is skipped; a 1c Wuvva Shirt, avg ~2,500, is
    # sniped). The value gate is enforced in open_and_buy once the REAL item name
    # is read off the purchase dialog, and if the community price for that item is
    # unknown the buy is refused — we never spend on an item we can't value.
    # It reuses the whole buy engine (open 0x010f -> dialog 0x00ca -> confirm)
    # and every wallet guard. `snipe` (console) toggles/tunes it. The synthetic
    # order below is what matching_order/open_and_buy act on; its dedup set stops
    # the same machine being reopened twice, exactly like a real buy order.
    autosnipe = {"on": True, "min_avg": 2000.0, "steal_max": 1,
                 "order": {"item": "steal", "autosnipe": True, "max_price": 1,
                           "qty": None, "budget": None, "spent": 0, "bought": 0,
                           "active": True, "dedup": set()}}
    # PRIZE MACHINE / PASSWORD SENTRY (Stage 12, PRIZE.md). The `prize` command
    # fires one tx 0x0040 guess at a time and blocks on this. The reader latches
    # rx 0x0036 as authoritative "wrong". An in-phase 0x0014 is only a tentative
    # accept because delayed arm replies look identical; the loop waits out an
    # extended rejection window before reporting it. It never claims the prize.
    prizewait = {"active": False, "result": None, "text": None,
                 "dispenser_guid": None, "block": None,
                 "phase": None, "arm_kind": None, "saw_accept": False,
                 "arm_event": threading.Event(), "event": threading.Event()}
    # 'prize test <code>': fire ONE guess and record every rx frame for a few
    # seconds so we can see exactly what the server replies. Read by the reader
    # thread, so it MUST be defined here (early), not down by the console loop.
    prize_probe = {"active": False, "frames": []}
    # PLAYER buy orders (cc_orders ledger, odb) reuse the SAME purchase engine as
    # the owner buy_orders above, but each order belongs to a player and spends
    # that player's deposited balance. The bot's ONE physical wallet holds the
    # pooled deposits; a purchase debits the physical wallet (real buy) AND the
    # player's ledger (record_purchase), keeping wallet == sum(balances). This set
    # stops one (order, machine) pair from being bought twice in a session.
    player_dedup = set()          # {(order_id, machine_guid)}

    # AUTO-TRADE (Stage 10): accept a player's trade, read the cubits they stake,
    # confirm, and credit their escrow balance — hands-off deposits. SAFETY: the
    # bot only ever auto-confirms a trade where ITS OWN side is empty (our_cubits
    # == 0), so an auto-trade can only ADD to the bot, never give anything away.
    # Trade wire format decoded in TRADE.md. An incoming request already opens
    # the trade on this client; sending the speculative OPEN phase at that point
    # was observed live to reset the trade. We therefore send only the two real
    # buttons: ACCEPT after Cubits settle, then the final confirmation YES.
    autotrade = {"on": True}
    trades = {}   # trade_guid_hex -> {name, their_guid, staked, our_cubits,
                  #                    confirmed, credited, wallet_before}
    # The most recent trade window someone opened with us, tracked independently
    # of the escrow autotrade logic so the web console's manual Accept/Confirm/
    # Decline buttons work even when autotrade is off or no order DB is loaded.
    last_trade = {"guid": None, "name": None, "at": 0.0,
                  "staked": 0, "our": 0, "open": False}
    # Live WASD drive: the web console holds down direction keys; drive_loop
    # steps the avatar each tick and broadcasts a walking motion frame so other
    # players see it walk. keys is the set of currently-held keys (w/a/s/d),
    # z is a one-shot vertical nudge (+1 up / -1 down) applied next tick.
    drive = {"keys": set(), "z": 0, "active": False, "moving": False}
    # Client-side physics for driving (the server doesn't enforce collision, so
    # without this the avatar walks through walls and floats). `down` is which z
    # direction gravity pulls (+1 = larger z is lower, proven by the prize work);
    # auto-calibrated from the spawn floor. `foot`-model: the bot's body cell is
    # air and the floor block sits at bz+down. `step_up` climbs 1-block ledges;
    # `max_fall` caps a drop; solid = any grid-aligned world object unless a
    # `solid_kinds` allow-set is given (None = everything is solid).
    physics = {"on": True, "down": 1, "step_up": 1, "max_fall": 96,
               "solid_kinds": None, "calibrated": False,
               # The realm's base ground level (deepest rest z we've stood on).
               # When the bot walks off a block into a column with NO geometry in
               # `world` (the realm ground often isn't all sent as objects), it
               # falls back to THIS instead of floating. Reset per realm.
               "ground_bz": None, "dbg": ""}
    _solidc = {"len": -1, "set": set(), "cols": set()}
    pending_trade_credits = {}  # committed trades waiting for wallet 0x0011
    # The reader thread starts before later helper definitions execute. Keep a
    # safe indirection so an early wallet frame cannot race that initialization.
    trade_credit_retry = {"fn": lambda: None}
    # TRADE-STATE PROBE (Stage 10): `probe.on` cycles state profiles from
    # trade_accept_candidates across successive
    # trades and records `probe.winner` only when rx 0x0036 proves the final
    # confirmation worked. The earlier rx 0x00ca proves only OPEN + ACCEPT.
    # Once winner is known, deposits use it automatically even with probe off.
    probe = {"on": False, "idx": 0, "last": None, "winner": None}
    ACCEPT_SETTLE_SECS = 1.0    # wait this long after the deposit stops changing
                                # before sending the accept (debounced per trade)
    REACCEPT_DELAY_SECS = 0.75  # let the game's "deciding..." animation clear
    TRADE_COMMIT_DELAY_SECS = 0.35  # official capture: YES follow-up was ~0.38s
    # When on, dumps EVERY rx frame in the trade type-range (0x30..0x40, 0xa0..0xb0)
    # with hex + decoded fields, so we can see exactly what the server sends back
    # after each candidate accept. Turn on with `tradedebug on`.
    tradedebug = {"on": False}
    _TRADE_DBG_TYPES = set(range(0x30, 0x41)) | set(range(0xa0, 0xb1)) | {0x11}
    trade_accept_path = os.path.join(
        _APP_DIR, "trade_accept.json")

    def save_trade_accept():
        try:
            with open(trade_accept_path, "w") as f:
                json.dump({"winner": probe["winner"]}, f)
        except Exception:
            pass

    def load_trade_accept():
        try:
            with open(trade_accept_path) as f:
                probe["winner"] = json.load(f).get("winner")
        except Exception:
            pass

    load_trade_accept()
    # The accept/confirm shapes are now PROVEN (plaintext capture 2026-08-15): the
    # single valid profile is 'proven_aa'. Force it and keep probing OFF, ignoring
    # any stale winner a self-calibrating run may have saved to trade_accept.json.
    probe["winner"] = "proven_aa"
    probe["on"] = False
    # Orders persist to a file so they survive restarts and keep buying across
    # sessions of scanning. dedup is a set (not JSON), so it round-trips as a
    # list. Progress (spent/bought/active) is saved too, so a filled or capped
    # order stays filled after a restart.
    _BUY_KEYS = ("item", "max_price", "qty", "budget", "spent", "bought",
                 "active")
    buy_orders_path = os.path.join(_APP_DIR,
                                   "buy_orders.json")

    def save_buy_orders():
        try:
            data = [{**{k: o.get(k) for k in _BUY_KEYS},
                     "dedup": sorted(o.get("dedup", set()))}
                    for o in buy_orders]
            tmp = buy_orders_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=1, ensure_ascii=False)
            os.replace(tmp, buy_orders_path)
        except OSError as e:
            show_line(f"  (couldn't save buy_orders.json: {e})")

    def load_buy_orders():
        try:
            data = json.load(open(buy_orders_path, encoding="utf-8"))
        except (OSError, ValueError):
            return
        for o in (data if isinstance(data, list) else []):
            if not isinstance(o, dict) or not o.get("item"):
                continue
            buy_orders.append({"item": o["item"],
                               "max_price": o.get("max_price"),
                               "qty": o.get("qty"), "budget": o.get("budget"),
                               "spent": o.get("spent", 0),
                               "bought": o.get("bought", 0),
                               "active": o.get("active", True),
                               "dedup": set(o.get("dedup", []))})
        if buy_orders:
            show_line(f"  {len(buy_orders)} buy order(s) restored from "
                      f"buy_orders.json.")

    load_buy_orders()
    def realm_ref(s):
        """A realm GUID (wire hex) out of: a Share link (castles.cc?realm=<32
        hex>), a bare 32-hex wire GUID, or a registry-format GUID
        ({13980BD1-4310-...}, as the game shows them). None if it's none of those
        (then it's treated as a player name)."""
        if not s:
            return None
        s = s.strip()
        i = s.find("realm=")
        cand = (s[i + 6:i + 38] if i >= 0 else s).lower()
        try:
            if len(cand) == 32:
                bytes.fromhex(cand)
                return cand
        except ValueError:
            pass
        # registry / braced form -> convert to wire order (bytes_le)
        braced = s.strip().strip("{}")
        if len(braced) == 36 and braced.count("-") == 4:
            try:
                return P.realm_guid_to_wire(braced).hex()
            except (ValueError, AttributeError):
                pass
        return None

    # Parking target after a guid-triggered scan: EITHER a realm we enter by its
    # GUID (from a Share link, via the 0x000e check-in) OR a player whose realm we
    # teleport into. Persisted in park.json so it's set once and survives
    # restarts; --after-scan overrides the saved value for this run.
    park_path = os.path.join(_APP_DIR,
                             args.park_file)

    def load_park():
        try:
            d = json.load(open(park_path, encoding="utf-8"))
            return d.get("after"), d.get("after_guid"), d.get("after_realm")
        except Exception:
            return None, None, None

    if args.after_scan is not None:
        _ag = realm_ref(args.after_scan)
        _after, _after_guid, _after_realm = (
            (None, _ag, None) if _ag else (args.after_scan, None, None))
    else:
        _after, _after_guid, _after_realm = load_park()

    state = {"follow_guid": None, "follow_heading": None,
             "after": _after, "after_guid": _after_guid,
             "after_realm": _after_realm,
             "realm": None, "realm_owner": None, "entry_logged": False}

    def save_park():
        try:
            with open(park_path, "w", encoding="utf-8") as fh:
                json.dump({"after": state["after"],
                           "after_guid": state["after_guid"],
                           "after_realm": state["after_realm"]},
                          fh, indent=1, ensure_ascii=False)
        except OSError as e:
            show_line(f"  (couldn't save {args.park_file}: {e})")
    # Every frame we don't surface, tallied by type so 'stats' can show what was
    # hidden without any of it hitting the console.
    supp = collections.Counter()
    # World churn — movement, heartbeats, entity updates, typing toggles. Loud
    # and meaningless here, so never shown.
    SPAM = {0x0006, 0x0007, 0x0008, 0x0101, 0x005a, 0x000b, 0x000f,
            0x0044, 0x0072, 0x0073, 0x0011, 0x00e8, 0x0076, 0x007a,
            0x011a,          # another player moving — one frame per tick, each
            0x0031}          # chat typing toggle — fires on every keystroke

    # A realm's Share link is just https://castles.cc?realm=<its GUID>, confirmed
    # by comparing to the browser. That GUID is the realm-registration GUID we
    # already pull from every login (reg["guid"]), so the link needs no browser
    # and no pasting — the client builds it. realm_guids remembers each realm's
    # GUID as we enter it; realm_links holds the rare hand-typed override.
    realm_guids = {}                      # realm name -> its GUID (from reg)
    realm_links = {}                      # realm name -> manual override URL
    links_path = os.path.join(_APP_DIR,
                              args.links_file)
    try:
        realm_links.update(json.load(open(links_path, encoding="utf-8")))
    except Exception:
        pass

    # Persistent catalogue of every realm we've ever entered: name -> its GUID,
    # built link, owner. Grows across sessions so you accumulate a list of realm
    # links just by walking/teleporting through them.
    realms_path = os.path.join(_APP_DIR,
                               args.realms_file)
    try:
        realms_log = json.load(open(realms_path, encoding="utf-8"))
    except Exception:
        realms_log = {}

    # Rescan watchlist: realms you flag with `watch` so you can re-run the scan
    # over all of them later with a single `rescan`. Keyed by realm GUID (dedups
    # automatically), persisted to watchlist.json so it survives across sessions.
    watchlist_path = os.path.join(_APP_DIR,
                                  "watchlist.json")
    try:
        watchlist = json.load(open(watchlist_path, encoding="utf-8"))
    except Exception:
        watchlist = {}

    def save_watchlist():
        try:
            with open(watchlist_path, "w", encoding="utf-8") as fh:
                json.dump(watchlist, fh, indent=1, ensure_ascii=False)
            return True
        except OSError as e:
            show_line(f"  (couldn't save watchlist.json: {e})")
            return False

    # ------------------------------------------------------------------ #
    # Discord webhook alerts (optional). When a webhook URL is configured the
    # bot pings a Discord channel on two events: a prize password cracked, and
    # an auto-snipe steal bought. OFF by default — no URL means no calls are
    # ever made. The URL is read once here from the CUBICBOT_DISCORD_WEBHOOK
    # env var, else webhook.json in the app dir; change it live with the
    # `webhook` console command (so the exe's command box can set it too).
    webhook_path = os.path.join(_APP_DIR, "webhook.json")

    def _load_webhook():
        # Defaults: URL empty (feature off), both alert types ON once a URL is
        # set. The env var, when present, wins for the URL only.
        wh = {"url": "", "prize": True, "snipe": True}
        try:
            d = json.load(open(webhook_path, encoding="utf-8"))
            wh["url"] = (d.get("url") or "").strip()
            wh["prize"] = bool(d.get("prize", True))
            wh["snipe"] = bool(d.get("snipe", True))
        except Exception:
            pass
        env = (os.environ.get("CUBICBOT_DISCORD_WEBHOOK") or "").strip()
        if env:
            wh["url"] = env
        return wh

    webhook = _load_webhook()

    def save_webhook():
        try:
            with open(webhook_path, "w", encoding="utf-8") as fh:
                json.dump({"url": webhook["url"], "prize": webhook["prize"],
                           "snipe": webhook["snipe"]}, fh, indent=1)
        except OSError as e:
            show_line(f"  (couldn't save webhook.json: {e})")

    def _webhook_looks_valid(u):
        u = (u or "").lower()
        return (u.startswith("https://") and "discord" in u
                and "/webhooks/" in u)

    def discord_notify(title, message, event=None, color=None, fields=None):
        """Fire-and-forget Discord alert, sent as a clean rich embed. No-op when
        no webhook is set, or when this `event` type ('prize'/'snipe') has been
        toggled off. Runs the POST in a daemon thread and swallows every error —
        a bad URL or a dead network must never stall or crash the bot.
        event=None (e.g. the test ping) always sends as long as a URL is set.

        `fields` is an optional list of (name, value, inline_bool) tuples shown
        as the embed's labelled rows; `color` overrides the left accent bar."""
        url = (webhook.get("url") or "").strip()
        if not url:
            return
        if event and not webhook.get(event, True):
            return                         # this alert type is muted
        import datetime
        embed = {"title": (title or "CubicBot")[:256],
                 "color": color if color is not None else 0x4F8CFF,
                 "footer": {"text": "CubicBot"},
                 "timestamp": datetime.datetime.now(
                     datetime.timezone.utc).isoformat()}
        if message:
            embed["description"] = str(message)[:4000]
        if fields:
            embed["fields"] = [{"name": str(n)[:256], "value": str(v)[:1024],
                                "inline": bool(inl)} for (n, v, inl) in fields]
        payload = json.dumps({"username": "CubicBot",
                              "embeds": [embed]}).encode("utf-8")

        def _post():
            try:
                import urllib.request
                req = urllib.request.Request(
                    url, data=payload,
                    headers={"Content-Type": "application/json",
                             "User-Agent": "CubicBot/1.0"})
                urllib.request.urlopen(req, timeout=10).read()
            except Exception:
                pass                       # alerts are best-effort, never fatal

        threading.Thread(target=_post, daemon=True).start()

    # --- Live chat translator (Stage 27) -------------------------------------
    # Auto-detects non-English chat, translates it to English and re-posts it as
    #   "[Player] said in <Language>: <English>"
    # either in PUBLIC chat or WHISPERED to one chosen player. OFF by default.
    # Modular backends live in cc_translate (builtin/libre/deepl/google); the
    # provider is chosen in config and any API KEY is read from the environment
    # by that module — never stored here. All settings persist to translate.json
    # so they survive a restart. Loop/dedup/rate-limit live in a TranslateThrottle.
    translate_path = os.path.join(_APP_DIR, "translate.json")

    # Load persisted settings (defaults + env overrides for provider/URL only;
    # API KEYS live in the environment and are read inside cc_translate).
    translatebot = (cc_translate.load_settings(translate_path)
                    if cc_translate is not None
                    else {"on": False, "mode": "public", "whisper_to": "",
                          "provider": "auto", "libre_url": "",
                          "argos_auto_download": True, "argos_models_dir": ""})
    # CLI flags win over the file at startup (documented one-shot overrides).
    if getattr(args, "no_translate", False):
        translatebot["on"] = False
    if getattr(args, "translate", False):
        translatebot["on"] = True
    if getattr(args, "translate_mode", None):
        translatebot["mode"] = args.translate_mode
    if getattr(args, "translate_to", None):
        translatebot["whisper_to"] = args.translate_to.strip()
    if getattr(args, "translate_provider", None):
        translatebot["provider"] = args.translate_provider.strip().lower()
    translatebot["throttle"] = (cc_translate.TranslateThrottle()
                                if cc_translate is not None else None)
    translatebot["engine"] = None
    translatebot["engine_provider"] = None

    def _build_translator():
        """(Re)build the translation engine for the current provider. Stores it on
        translatebot['engine']; on failure records None and returns the error."""
        if cc_translate is None:
            translatebot["engine"] = None
            return "cc_translate module not available"
        try:
            translatebot["engine"] = cc_translate.make_translator(
                {"provider": translatebot["provider"],
                 "libre_url": translatebot["libre_url"],
                 "argos_auto_download": translatebot.get("argos_auto_download",
                                                         True),
                 "argos_models_dir": translatebot.get("argos_models_dir", "")})
            # Record the RESOLVED provider ('auto' -> the real local backend).
            prov = translatebot["provider"]
            if prov == "auto":
                prov = cc_translate.default_provider()
            translatebot["engine_provider"] = prov
            return None
        except Exception as e:
            translatebot["engine"] = None
            return f"{type(e).__name__}: {e}"

    if cc_translate is not None:
        _terr = _build_translator()
        if _terr:
            show_line(f"  (translator provider '{translatebot['provider']}' "
                      f"unavailable: {_terr})")

    def save_translate_cfg():
        if cc_translate is None:
            return
        try:
            cc_translate.save_settings(translate_path, translatebot)
        except OSError as e:
            show_line(f"  (couldn't save translate.json: {e})")

    def add_watch(guid, name=None, owner=None):
        """Add or refresh a realm on the rescan watchlist (keyed by GUID)."""
        if not guid:
            return False
        # Never list the same realm twice: if this name is already on the list
        # under a different GUID (e.g. the realm was re-hosted), drop the stale
        # one so the name appears exactly once.
        if name:
            for gg in [k for k, v in watchlist.items()
                       if k != guid
                       and (v.get("name") or "").lower() == name.lower()]:
                del watchlist[gg]
        prev = watchlist.get(guid, {})
        watchlist[guid] = {
            "guid": guid,
            "name": name or prev.get("name") or guid[:8],
            "owner": owner if owner is not None else prev.get("owner"),
            "link": link_for(name, guid) if name else
                    (prev.get("link") or link_for(None, guid)),
            "added": prev.get("added") or time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return save_watchlist()

    # Approved-user allowlist for privileged in-game chat commands. Public
    # commands (price checks, help, realm info) stay open to EVERYONE; anything
    # that moves the bot or touches admin features (summon, scan realm) is gated
    # to the names on this list. Stored lowercased in a set and persisted to
    # approved_users.json so it survives restarts and can be edited by hand, with
    # the 'approve'/'unapprove' console commands, or from the web console.
    approved_path = os.path.join(_APP_DIR,
                                 args.approved_file)
    approved = set()
    try:
        _al = json.load(open(approved_path, encoding="utf-8"))
        _names = _al.get("approved", []) if isinstance(_al, dict) else _al
        for _n in (_names or []):
            if isinstance(_n, str) and _n.strip():
                approved.add(_n.strip().lower())
    except Exception:
        pass

    def save_approved():
        try:
            with open(approved_path, "w", encoding="utf-8") as fh:
                json.dump({"approved": sorted(approved)}, fh,
                          indent=1, ensure_ascii=False)
            return True
        except OSError as e:
            show_line(f"  (couldn't save {args.approved_file}: {e})")
            return False

    def is_approved(sender_guid):
        """True if the chat sender's resolved display name is on the allowlist.
        A sender whose name we haven't learned yet is never approved."""
        name = (players.get(sender_guid) or "").strip().lower()
        return bool(name) and name in approved

    # Persistent vending catalogue: what each realm sells and for how much.
    # Keyed by realm NAME so a realm can never appear twice; (re)scanning a
    # realm REPLACES that realm's whole entry and leaves every other realm
    # alone. Survives restarts (vends.json).
    vends_path = os.path.join(_APP_DIR,
                              "vends.json")
    try:
        vends = json.load(open(vends_path, encoding="utf-8"))
    except Exception:
        vends = {}

    def save_vends():
        # Write-then-rename: this is the bot's primary state file and it is ~5 MB,
        # so a plain open('w') leaves it truncated for the whole dump. Under
        # systemd a stop/restart lands SIGTERM at an arbitrary moment, which made
        # that window a real way to lose the catalogue. os.replace is atomic.
        tmp = vends_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(vends, fh, indent=1, ensure_ascii=False, default=str)
            os.replace(tmp, vends_path)
        except OSError as e:
            show_line(f"  (couldn't save vends.json: {e})")
            try:
                os.remove(tmp)
            except OSError:
                pass

    # SQLite market-history database. This is now the primary store: it keeps
    # the same *current* catalogue (a completed rescan replaces a realm's
    # listings) but ALSO retains every observation, price/item change, and
    # removal so history is queryable. vends.json is still written for
    # compatibility during the transition. Optional and defensive — if it can't
    # open, the client falls back to JSON-only and nothing else breaks.
    mdb = None
    if args.use_market_db and cc_storage is not None:
        try:
            db_path = args.market_db if os.path.isabs(args.market_db) else \
                os.path.join(_APP_DIR,
                             args.market_db)
            mdb = cc_storage.MarketDB(db_path)
            show_line(f"  market history DB: {db_path}")
        except Exception as e:
            show_line(f"  (market history DB unavailable — JSON only: {e})")
            mdb = None

    # Buy-order escrow ledger (Stage 10, experimental). Per-player balances +
    # buy orders in a private SQLite DB players cannot reach. Pure local
    # bookkeeping — it never moves cubits itself; the deposit/collection TRADE is
    # a separate (still-unmapped) step. Optional and defensive, like the market DB.
    odb = None
    if args.use_orders_db and cc_orders is not None:
        try:
            odb_path = args.orders_db if os.path.isabs(args.orders_db) else \
                os.path.join(_APP_DIR,
                             args.orders_db)
            odb = cc_orders.OrderStore(odb_path)
            show_line(f"  buy-order ledger: {odb_path}")
        except Exception as e:
            show_line(f"  (buy-order ledger unavailable: {e})")
            odb = None

    # item id -> name table, extracted from the game's memory by cc_items.py.
    # Optional: if absent, the inventory command just shows numeric ids.
    names_path = os.path.join(_APP_DIR, "names.json")
    if not os.path.exists(names_path):
        # Source checkouts keep names.json at the repository root.  Frozen builds
        # may bundle it under _MEIPASS, while writable state still lives in
        # %APPDATA%\CubicBot.
        source_names = os.path.join(os.path.dirname(_APP_DIR), "names.json")
        bundled_names = os.path.join(getattr(sys, "_MEIPASS", ""), "names.json")
        if os.path.exists(source_names):
            names_path = source_names
        elif os.path.exists(bundled_names):
            names_path = bundled_names
    try:
        item_names = {int(k): v for k, v in
                      json.load(open(names_path, encoding="utf-8")).items()}
    except Exception:
        item_names = {}

    # Seed the DB's id->name table from names.json (only if it's empty), so new
    # items can be matched to a protocol item id on an exact name match.
    if mdb is not None:
        try:
            mdb.ensure_names(names_path)
        except Exception:
            pass

    def item_label(tid):
        nm = item_names.get(tid)
        return f"{nm} (id {tid})" if nm else f"id {tid}"

    # Which world-object type_ids count as "fossils". Two sources, unioned:
    #   1. any item whose catalogue name contains "fossil" (needs names.json)
    #   2. ids the user has tagged live with `fossils learn <id>`, persisted
    #      here so a mine only has to be identified once.
    # The tagged set is the reliable source: fossil blocks are the same
    # catalogue id in every realm, so learning it in one mine finds it in all.
    fossils_path = os.path.join(_APP_DIR,
                                "fossils.json")
    try:
        fossil_ids = set(int(i) for i in
                         json.load(open(fossils_path, encoding="utf-8")))
    except Exception:
        fossil_ids = set()

    def save_fossil_ids():
        try:
            tmp = fossils_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(sorted(fossil_ids), fh)
            os.replace(tmp, fossils_path)
        except OSError as e:
            show_line(f"  (couldn't save fossils.json: {e})")

    def is_fossil(tid):
        if tid in fossil_ids:
            return True
        nm = item_names.get(tid)
        return bool(nm) and "fossil" in nm.lower()

    # A spatial fossil zone: two opposite corners of a box, drawn live with
    # `fossils region`. EVERY placed block inside it counts as a fossil, whatever
    # its type — for a mine where the fossils are clustered in one square. A box
    # only means something in the realm it was drawn in, so it's tagged with that
    # realm and ignored anywhere else (no cross-realm bleed, no persistence).
    fossil_region = {"box": None, "realm": None}  # box = (x1,y1,z1,x2,y2,z2|None)

    def region_active():
        # A box applies until it's cleared or the bot changes realm (the three
        # world.clear() sites also clear the box). Not gated on the realm NAME,
        # which is often None in a mine before the name is echoed.
        return fossil_region["box"] is not None

    def in_region(o):
        if not region_active():
            return False
        x1, y1, z1, x2, y2, z2 = fossil_region["box"]
        if not (x1 <= o["bx"] <= x2 and y1 <= o["by"] <= y2):
            return False
        return z1 is None or (z1 <= o["bz"] <= z2)

    def region_hist():
        """{type_id: count} of every placed block inside the active box."""
        from collections import Counter
        return Counter(o.get("type_id") for o in world.values() if in_region(o))

    def region_dominant():
        """The most common type_id inside the box — the wall/dirt the fossils
        are embedded in. Returns None if the box is empty or a single type."""
        h = region_hist()
        if len(h) < 2:
            return None
        return h.most_common(1)[0][0]

    def save_links():
        try:
            with open(links_path, "w", encoding="utf-8") as fh:
                json.dump(realm_links, fh, indent=1, ensure_ascii=False)
        except OSError as e:
            show_line(f"  (couldn't save {args.links_file}: {e})")

    def link_for(realm, guid=None):
        """The Share link for a realm: a hand-typed override if one exists, else
        built from the realm's GUID."""
        if realm in realm_links:
            return realm_links[realm]
        guid = guid or realm_guids.get(realm)
        return args.share_url.format(guid=guid) if guid else ""

    def note_realm_guid():
        """Remember the current realm's GUID, and log it to the persistent
        catalogue with its built link — so every realm entered becomes a saved
        base link automatically."""
        realm = state["realm"]
        if not (realm and reg["guid"]):
            return
        realm_guids[realm] = reg["guid"]
        prev = realms_log.get(realm)
        rec = {"guid": reg["guid"], "link": link_for(realm),
               "owner": state["realm_owner"],
               "seen": time.strftime("%Y-%m-%d %H:%M:%S")}
        realms_log[realm] = rec
        if not prev or prev.get("guid") != reg["guid"]:
            try:
                with open(realms_path, "w", encoding="utf-8") as fh:
                    json.dump(realms_log, fh, indent=1, ensure_ascii=False)
            except OSError:
                pass
            if not prev:
                show_line(f"       logged realm link: {rec['link']}")

    def apply_realm_id(info):
        """Adopt a realm-identity (rx 0x005f) reading: set the current realm
        name/owner, drop the old realm's world/query caches on a change, log the
        link, and surface it. Shared by the reader AND the login path — a
        teleport/join re-login recovers the session key by reading the first few
        frames, and the 0x005f announcing the destination realm is usually among
        them, so login_on captures it and calls this. Without that, a teleport
        onto a player left the current realm stuck on the one we logged in from
        (so `watch` bookmarked the wrong realm)."""
        if not info or not info.get("realm"):
            return
        with build_action_lock:
            if info["realm"] != state["realm"]:
                old_realm = state["realm"]
                builder = build_runtime.get("controller")
                if builder and builder.active:
                    builder.cancel()
                    show_line(f"[build] realm changed from {old_realm!r} to "
                              f"{info['realm']!r}; cancellation requested")
                # World objects and block-query replies describe ONE realm.
                # Carrying them across a hop left the next scan probing
                # coordinates from the realm we just left.
                world.clear()
                fossil_region["box"] = None   # coord boxes are realm-specific
                qcache.clear()
                realm_players.clear()          # different realm, different crowd
                mannequin_seen.clear()
                player_pos.clear()             # positions are per-realm
                player_heading.clear()
                player_block.clear()
                world_diag.update(frames=0, objs=0, dropped=0)
                world_diag["remainders"].clear()
                world_rx["last"] = 0.0
            state["realm"] = info["realm"]
            state["realm_owner"] = info["owner"]
            state["entry_logged"] = False   # next placement = this realm's spawn
            note_realm_guid()
            show_line(f"[realm] {info['realm']} (owner {info['owner']})")

    def send(body):
        if switching.is_set():
            flog("TX", body, note="  [SUPPRESSED: switching]")
            return False
        flog("TX", body)
        with lock:
            wire = encode_outbound(body, conn["key"], conn["outer_key"])
            conn["ws"].send_binary(wire)
        return True

    def send_public_chat(chat_frame):
        """Send a PUBLIC 0x000c chat frame the way the real client does: bracketed
        by the typing toggle (0x0031 ON before the text, OFF after). The server only
        broadcasts a chat line to the channel when it is preceded by the ON toggle —
        a bare 0x000c is accepted but shown to nobody (proven live + in capture
        20260807-154729). Whispers do NOT use this: '/whisper' is a command."""
        send(P.build_chat_toggle(True))
        send(chat_frame)
        send(P.build_chat_toggle(False))

    # Single outbound path for the bot's AUTOMATIC chat replies (price checks,
    # keyword commands, summon/scan acknowledgements). It enforces a minimum gap
    # between any two bot messages and a small pre-delay before each one, so a
    # burst — or several handlers answering the same line at once — goes out
    # spaced apart instead of machine-gunning the channel. Manual 'say' bypasses
    # this on purpose. Tunable with --chat-delay / --chat-gap.
    chat_gate = {"lock": threading.Lock(), "next": 0.0}

    # When a command is being answered because it arrived as a WHISPER, this holds
    # the whisperer's GUID so chat_say/_reply route the answer back privately
    # instead of into public chat. Set (and cleared) around the whisper dispatch;
    # the reader thread is the only setter, so no lock is needed. Only the
    # SYNCHRONOUS replies a handler makes while dispatching are captured — a handler
    # that answers later from its own worker thread (e.g. scanbot's realm-lookup)
    # will have this cleared again and falls back to public chat.
    reply_ctx = {"whisper_to": None}

    def chat_say(text):
        if not text or stop.is_set():
            return
        if WORKER_SILENT:                     # worker role never talks
            return
        target = reply_ctx.get("whisper_to")
        if target is not None:                # answering a whisper -> whisper back
            whisper_say(target, text)
            return
        body = _chat_clean(text)
        delay = max(0.0, args.chat_delay)
        gap = max(0.0, args.chat_gap)
        with chat_gate["lock"]:
            now = time.time()
            when = max(now + delay, chat_gate["next"])
            chat_gate["next"] = when + gap

        def _fire():
            if not stop.is_set():
                try:
                    send_public_chat(P.build_chat(body))
                except Exception as e:
                    show_line(f"  [chat] send failed: {type(e).__name__}: {e}")

        wait = when - time.time()
        if wait <= 0.01:
            _fire()
        else:
            threading.Timer(wait, _fire).start()

    # --- PUBLIC chat sent FROM the reader thread -----------------------------
    # A send_public_chat() call made inline on the reader thread (the WebSocket
    # receive loop) is accepted by the server but broadcast to NOBODY — proven
    # live: public 'botname help' produced nothing in-game. Every send that DOES
    # render runs on some OTHER thread: the console 'say' (main thread) and the
    # whisper worker (its own thread). So public replies triggered from the
    # reader (handle_public_help) are queued here and this dedicated worker does
    # the actual send, exactly like whisper_worker does for whispers.
    pub_q = collections.deque()
    pub_wake = threading.Event()

    def pub_worker():
        """Serialise outbound PUBLIC chat lines and send them off the reader
        thread (where send_public_chat doesn't render), paced by --chat-gap."""
        while not stop.is_set():
            if not pub_q:
                pub_wake.wait(1.0)
                pub_wake.clear()
                continue
            try:
                text = pub_q.popleft()
            except IndexError:
                continue
            try:
                send_public_chat(P.build_chat(_chat_clean(text)))
                show_line(f"  [pub] sent: {text}")
            except Exception as e:
                show_line(f"  [pub] send failed: {type(e).__name__}: {e}")
            gap = max(0.0, args.chat_gap)
            if gap:
                stop.wait(gap)

    def pub_say(text):
        """Queue a PUBLIC chat line for the dedicated pub_worker thread. Use this
        for any public reply composed on the reader thread — a direct
        send_public_chat there is silently dropped by the server."""
        if not text or stop.is_set():
            return
        if WORKER_SILENT:                     # worker role never talks
            return
        pub_q.append(text)
        pub_wake.set()

    # --- WHISPER (private message) bot ---------------------------------------
    # A whisper rides the ordinary 0x000c chat type but is server-tagged (see
    # P.parse_whisper). SENDING one is a two-step server menu: build_whisper_open
    # ("/whisper <msg>") -> the server pops a rx 0x00ba "Whisper to Who?" picker ->
    # build_whisper_select(menu_id, index) clicks the recipient's row. There is NO
    # direct "/whisper <name> <msg>" form (confirmed by capture). Because the reply
    # depends on a menu the READER thread must deliver, replies can't be sent inline
    # from the reader (it would block on itself) — they are queued and a dedicated
    # worker runs one menu dance at a time.
    whisperbot = {"on": not getattr(args, "no_whisperbot", False),
                  "public": bool(getattr(args, "answer_public", False))}
    whisper_q = collections.deque()
    whisper_wake = threading.Event()
    # The reader latches the picker here for the worker that is mid-handshake.
    whisper_menu = {"awaiting": False, "menu": None, "event": threading.Event()}

    def _whisper_name(guid):
        """Resolve a sender GUID to the display name the picker lists it under. An
        inbound whisper carries only the GUID; the picker matches by name, so we map
        it via the players registry (seen in-realm) or the friends list."""
        nm = players.get(guid)
        if nm:
            return nm
        for name, g in friends.items():
            if g == guid:
                return name
        return None

    def whisper_say(target_guid, text):
        """Queue a private reply to `target_guid`. Non-blocking: the worker does the
        menu handshake so the reader thread is never blocked on its own reply. Long
        replies are split so the game never rejects them for length."""
        if not text or stop.is_set():
            return
        if WORKER_SILENT:                     # worker role never whispers
            return
        for part in _split_whisper(_chat_clean(text)):
            whisper_q.append((target_guid, part))
        whisper_wake.set()

    def _do_one_whisper(target_guid, text):
        # Enforce the limit again at the last possible moment. This protects the
        # wire even if a future caller appends directly to whisper_q or restores
        # an oversized queued message. Put any extra chunks at the front so the
        # recipient sees this reply in order before later queued replies.
        parts = _split_whisper(_chat_clean(text))
        if not parts:
            return
        for remainder in reversed(parts[1:]):
            whisper_q.appendleft((target_guid, remainder))
        text = parts[0]

        name = _whisper_name(target_guid)
        who = name or (target_guid[:8] + "…")
        if not name:
            show_line(f"  [whisper] can't reply to {who}: name unknown "
                      "(not seen in-realm and not a friend)")
            return
        menu = None
        for attempt in (1, 2):
            whisper_menu["menu"] = None
            whisper_menu["event"].clear()
            whisper_menu["awaiting"] = True
            try:
                send(P.build_whisper_open(text))      # "/whisper <text>"
            except Exception as e:
                whisper_menu["awaiting"] = False
                show_line(f"  [whisper] send failed: {type(e).__name__}: {e}")
                return
            got = whisper_menu["event"].wait(5.0)     # reader latches the picker
            whisper_menu["awaiting"] = False
            menu = whisper_menu["menu"]
            if got and menu:
                break
            if attempt == 1:
                show_line(f"  [whisper] no picker for {who} "
                          f"(len={len(text)}) — retrying once")
                stop.wait(1.0)
            else:
                show_line(f"  [whisper] no picker came back for {who}; reply "
                          f"dropped (len={len(text)}): {text!r}")
                return
        want = _alnum(name)
        idx = None
        for i, nm in menu["names"]:
            if nm == name or (want and _alnum(nm) == want):
                idx = i
                break
        if idx is None:
            show_line(f"  [whisper] {who} isn't in the picker "
                      f"({len(menu['names'])} online) — can't whisper them back")
            return
        try:
            send(P.build_whisper_select(menu["menu_id"], idx))
            log_whisper("out", target_guid, text)   # prints the "-> who: text" line
        except Exception as e:
            show_line(f"  [whisper] pick failed: {type(e).__name__}: {e}")

    def whisper_worker():
        """Serialise outbound whispers: one "/whisper" + picker + click at a time,
        paced like public chat so the bot never machine-guns private messages."""
        while not stop.is_set():
            if not whisper_q:
                whisper_wake.wait(1.0)
                whisper_wake.clear()
                continue
            try:
                target_guid, text = whisper_q.popleft()
            except IndexError:
                continue
            _do_one_whisper(target_guid, text)
            gap = max(0.0, args.chat_gap)
            if gap:
                stop.wait(gap)

    # presence: announce position so the avatar renders, keep it fresh.
    #
    # We do NOT pick our own spawn. After the 0x000e realm check-in the server
    # places us at the realm's entry portal and reports it back as an rx 0x0005
    # carrying our own GUID — the real client just echoes that in its first MOVE
    # (capture 212753: rx 0x0005 (48009,85739) at t=21.99, tx MOVE with the same
    # numbers at t=22.03). So stay silent until we're placed, then adopt it.
    # --x/--y only exist as a manual override / last-resort fallback.
    #
    # After a teleport we FREEZE (stop forcing our own position) so the server's
    # placement next to the friend sticks instead of being overwritten.
    pos = {"x": args.x or 0, "y": args.y or 0, "z": args.z, "seq": 1,
           "frozen": False, "placed": False, "home": None, "warned": False,
           "provisional": False, "heading": 0}

    def announce(force=False):
        # Experimental no-avatar mode also omits the own-GUID registration in
        # login_on(). Never publish a 0x0006 movement packet here either. Check
        # this before `force` so placement and console movement cannot announce
        # it. This must be enabled before entering the realm and does not despawn
        # an avatar that was already announced.
        if args.no_avatar:
            return
        if not pos["placed"] and not force:
            return
        if pos["frozen"] and not force:
            return
        pos["seq"] = (pos["seq"] + 1) & 0xFF
        # carry the current facing even while standing still, so the avatar keeps
        # pointing the way it last faced instead of snapping to a default
        send(P.build_move(pos["x"], pos["y"], pos["z"], pos["seq"],
                          heading=pos.get("heading", 0)))

    def place_at(p, why, home=False, provisional=False):
        """Adopt a position the server gave us and broadcast it. The FIRST
        placement after entering a realm is the server's spawn decision, so
        that one gets logged whatever form it took.

        `provisional` marks a (0,0) placement: that IS a real spawn in some
        realms (Free Mines reports 0,0 and the real client echoes it), but it's
        also what an incomplete placement looks like — so we take it, and let a
        later non-zero report replace it."""
        pos["x"], pos["y"], pos["z"] = p
        pos["placed"] = True
        pos["frozen"] = False
        pos["provisional"] = provisional
        # If this placement is the arrival of a follow-teleport, face the target's
        # heading right away (captured at teleport start) instead of waiting for
        # the settle — that's what made the angle-copy feel slow.
        fh = state.get("follow_heading")
        if fh and not provisional:
            pos["heading"] = P.heading_deg(fh[0], fh[1])
            state["follow_heading"] = None
        if crawl["active"]:
            crawl["arrived"].set()       # we're in the next realm — driver waits on this
        if home:
            pos["home"] = p
        if not state["entry_logged"]:
            state["entry_logged"] = not provisional
            log_spawn(p, why)
        # Scan-join (a holla / guid / joinname-scan / crawl): jump off-map on the
        # VERY FIRST placement, BEFORE we broadcast the spawn spot — so the first
        # (and only) position anyone ever sees us at is off-map. Instant: no spawn
        # frame is sent, so there's no "stand at spawn, then pop away" lag.
        # go_offmap() does its own announce; otherwise announce normally.
        if (pending.get("autoscan") and wander["on"] and pos["placed"]
                and not movelock["frozen"] and not args.no_avatar):
            go_offmap()
        else:
            announce(force=True)
        show_line(f"  {why} ({p[0]},{p[1]}).")
        if not provisional:
            maybe_autoscan()

    import math as _math

    def walk_to(tx, ty, keep_going=None, stop_dist=None, curve=0.0):
        """Walk the avatar from where it is to (tx, ty) the way the real client
        does: the motion block carries the velocity vector (so receivers face it
        the right way and animate a walk), then a zero-velocity frame to stop.

        Smoothness: it advances a fraction of a WALK_TICK on a short (~130ms) tick
        and re-aims the heading toward the next path point every frame, so both the
        motion and the turning read smoothly instead of in big snaps.

        `curve` bows the path sideways (0 = dead straight; ~0.25 = a gentle arc)
        via a quadratic bezier, so it doesn't always beeline. `stop_dist` stops the
        walk once within that many units of the target instead of landing on it —
        pass ~one block to stand BESIDE a machine (it then turns to face it).
        `keep_going` aborts the walk early once it returns False."""
        if args.no_avatar or not pos["placed"] or movelock["frozen"]:
            return
        sx, sy = pos["x"], pos["y"]
        total = _math.hypot(tx - sx, ty - sy)
        tick = P.WALK_TICK or 1
        near = stop_dist if stop_dist is not None else tick * 0.5
        short = near > tick * 0.5             # stopping beside the target, not on it
        if total < 1:
            if short:
                pos["heading"] = P.heading_deg(tx - sx, ty - sy)
                pos["frozen"] = False
                announce(force=True)
            return
        # quadratic-bezier control point: midpoint pushed sideways by `curve`
        px, py = -(ty - sy) / total, (tx - sx) / total          # left-normal
        cx = (sx + tx) / 2 + px * curve * total
        cy = (sy + ty) / 2 + py * curve * total

        def bez(u):
            a, b, c = (1 - u) ** 2, 2 * (1 - u) * u, u * u
            return a * sx + b * cx + c * tx, a * sy + b * cy + c * ty

        seg = tick * 0.55                     # advance per frame (smaller = smoother)
        dt = seg / (tick / 0.26)              # keep real walk SPEED (~0.13s/frame)
        u = 0.0
        walking.set()
        try:
            while not stop.is_set():
                if keep_going is not None and not keep_going():
                    return
                if _math.hypot(tx - pos["x"], ty - pos["y"]) < near:
                    break
                u = min(1.0, u + seg / total)
                nx, ny = bez(u)
                dx, dy = nx - pos["x"], ny - pos["y"]
                d = _math.hypot(dx, dy) or 1.0
                pos["x"], pos["y"] = int(round(nx)), int(round(ny))
                pos["frozen"] = False
                vx, vy = int(dx / d * P.WALK_SPEED), int(dy / d * P.WALK_SPEED)
                pos["heading"] = P.heading_deg(vx, vy)   # smooth turn along the path
                pos["seq"] = (pos["seq"] + 1) & 0xFF
                try:
                    send(P.build_move(pos["x"], pos["y"], pos["z"], pos["seq"],
                                      vx=vx, vy=vy, moving=True))
                except Exception:
                    return
                if u >= 1.0:
                    break
                if stop.wait(dt):
                    return
        finally:
            walking.clear()
        if short:
            # stopped beside the target — turn to face it and hold position
            pos["heading"] = P.heading_deg(tx - pos["x"], ty - pos["y"])
        else:
            pos["x"], pos["y"] = int(tx), int(ty)    # land exactly on it
        pos["frozen"] = False
        announce(force=True)

    def face_like(guid):
        """After teleporting onto a player, turn to face the same way they are —
        their last-observed heading. Facing is just the +24 angle field now, so we
        turn IN PLACE (no walking): set our heading and re-announce. No-op if we
        never saw them move."""
        # heading captured at teleport start (before the realm hop cleared the
        # per-realm tables); fall back to a live value for a same-realm case
        h = state.get("follow_heading")
        state["follow_heading"] = None
        if not h and guid:
            h = player_heading.get(guid if isinstance(guid, str) else guid.hex())
        if not h or args.no_avatar or not pos["placed"]:
            return
        vx, vy = h
        pos["heading"] = P.heading_deg(vx, vy)
        pos["frozen"] = False
        announce(force=True)

    def do_jump():
        """Fire a single 0x0008 jump event at the current spot — a little hop.
        The client plays the arc; our normal move stream reports the landing."""
        if args.no_avatar or not pos["placed"] or movelock["frozen"]:
            return
        pos["seq"] = (pos["seq"] + 1) & 0xFF
        try:
            send(P.build_jump(pos["x"], pos["y"], pos["z"], pos["seq"]))
        except Exception:
            pass

    def go_offmap():
        """Hide the avatar off the map — up and off to one side of wherever it
        stands — so it's out of sight while it lingers in a stranger's realm.
        Called from place_at on the FIRST placement of a scan-join, so the first
        position anyone ever sees us at is off-map (no spawn frame is sent first).

        Sends the jump as a **moving** frame (moving=True, with a velocity), NOT a
        standing announce(): a standing frame that leaps a long way reads as a
        teleport and the server drops it, whereas a moving/walk frame is accepted
        (that's how walk_to moves us). Fires a short burst so a dropped frame
        doesn't leave us at spawn. No-op with --no-avatar, before placement, or
        while frozen / off (wander['on']). If the avatar still doesn't move live,
        the offset is past the realm's accepted bounds — lower it with
        'offmap <high> <side>' until it takes."""
        if (args.no_avatar or not pos["placed"] or movelock["frozen"]
                or not wander["on"]):
            return
        sx, sy, sz = pos["x"], pos["y"], pos["z"]
        # Jump to a FIXED ABSOLUTE spot (default 0,0,0 — the map origin, off the
        # playable area) rather than a spawn offset. 'offmap <x> <y> <z>' tunes it.
        pos["x"] = wander["offmap_x"] * P.COORD_BASE
        pos["y"] = wander["offmap_y"] * P.COORD_BASE
        pos["z"] = wander["offmap_z"] * P.COORD_BASE
        pos["frozen"] = False
        # Adopt the off-map spot DIRECTLY and broadcast a plain standing frame —
        # the exact mechanism apply_move uses for u/d (vertical) and idle turns,
        # which the server accepts. (The earlier moving-frame burst was treated as
        # a walk and clamped.) 'offmap <x> <y> <z>' tunes it; if the server snaps
        # him back, the coords are outside the realm's bounds.
        pos["seq"] = (pos["seq"] + 1) & 0xFF
        try:
            announce(force=True)
        except Exception:
            pass
        show_line(f"  [offmap] warped off-map: block ({sx // P.COORD_BASE},"
                  f"{sy // P.COORD_BASE},{sz // P.COORD_BASE}) -> "
                  f"({pos['x'] // P.COORD_BASE},{pos['y'] // P.COORD_BASE},"
                  f"{pos['z'] // P.COORD_BASE})  (raw {pos['x']},{pos['y']},"
                  f"{pos['z']})")

    def maybe_autoscan():
        """`guid <name>` arms this; it fires once we are actually placed in the
        realm we teleported into.

        The scan waits on replies that the reader thread delivers, and this runs
        inside that thread — so it has to hand off to a worker or it would sit
        waiting for a reader that is blocked on it."""
        if not pending["autoscan"] or stop.is_set():
            return
        pending["autoscan"] = False
        watch_if_vends = pending.get("watch_if_vends", False)
        pending["watch_if_vends"] = False

        def worker():
            # Held busy for the whole settle+scan so a queued tp/guid can't fire
            # mid-way and teleport us out before this realm is scanned.
            autoscan_active.set()
            # (The off-map hide already happened in place_at, on the very first
            # placement — before any spawn frame was broadcast — so nothing to
            # move here. It covers every scan-join: holla, guid, joinname-scan,
            # crawl. Trade-off: opening a machine is proximity-gated, so scanning
            # from off-map misses vends that need a dialog open; query-priced
            # ones still land. `wander off` disables the hide.)
            try:
                # the realm's 0x000f object lists arrive in bursts after entry;
                # start once the count has stopped growing. The quiet window
                # (4 * 0.3s = 1.2s of nothing new) is unchanged from before, but
                # the CEILING is capped at ~8s instead of 30s: an empty realm
                # (n stays 0, so `stable` never advances) used to burn the whole
                # 30s before being skipped — across a 150-realm rescan that tail
                # was most of the wasted hours.
                # Poll faster (0.15s) and declare "settled" after a shorter quiet
                # window so we start reading the realm sooner. `--settle-quiet`
                # (nothing-new seconds) and `--settle-max` (ceiling) tune the
                # speed/completeness trade; a realm whose objects arrive in a slow
                # trickle may want them raised.
                poll = 0.15
                need = max(1, int(round(args.settle_quiet / poll)))   # quiet window
                ceil = max(need + 1, int(round(args.settle_max / poll)))
                last, stable = -1, 0
                for _ in range(ceil):
                    if stop.is_set():
                        return
                    n = len(world)
                    stable = stable + 1 if n and n == last else 0
                    last = n
                    if stable >= need:
                        break
                    time.sleep(poll)
                if stop.is_set():
                    return
                if not world:
                    show_line("  autoscan: no world objects arrived — skipping")
                    if crawl["active"]:
                        crawl["event"].set()
                    return
                vlog(f"  autoscan: {state['realm']} settled at {len(world)} "
                     f"object(s), scanning ...")
                try:
                    scan_machines()
                except Exception as e:
                    show_line(f"  autoscan failed: {e}")
                # scanning's done — stop strolling and park on spawn before any
                # realm switch (go_to_waiting) so we can't emit a stray move
                # mid-teleport. The finally below is just a safety net.
                wander["active"] = False
                # scan-on-command realms join the rescan watchlist if they
                # actually have vends (mirrors the auto-Hollawarp rule).
                if watch_if_vends:
                    realm, rg = state["realm"], reg["guid"]
                    mine = [r for r in offers.values()
                            if r.get("realm_guid") == rg]
                    if rg and mine:
                        add_watch(rg, realm, state["realm_owner"])
                        show_line(f"  [scanbot] {realm or rg[:8]}: {len(mine)} "
                                  f"vend(s) — watchlisted ({len(watchlist)} on "
                                  f"list)")
                    else:
                        show_line(f"  [scanbot] {realm or (rg or '?')[:8]}: no "
                                  f"vends found — not watchlisted")
                if crawl["active"]:
                    crawl["event"].set()     # let the crawl driver take next realm
                    return
                go_to_waiting()
            finally:
                wander["active"] = False     # stop the fidget; it parks at spawn
                autoscan_active.clear()

        threading.Thread(target=worker, daemon=True).start()

    # Realm entry by GUID is done with tx 0x00d3 (build_join_realm), routed
    # through pending["join"] -> do_teleport(..., follow=False). The old 0x000e
    # "check-in" experiment (try_enter_realm) is gone: it was proven not to work
    # (0x000e is backend-local). See capture 162327 for the real realm-browser
    # join flow.

    def go_to_waiting(lead="scan done — "):
        """Park at the configured waiting realm, so the client isn't left
        standing in a stranger's realm. Called automatically once a scan
        finishes, and on demand by the `park` command (which passes lead="").

        Three ways to name it, in priority order:
          after_realm — a realm NAME: search it (0x00c8), take the current GUID
                        from the results, then join (0x00d3). Robust to the realm
                        being re-hosted with a new GUID — the recommended park.
          after_guid  — a fixed realm GUID / Share link: join it directly.
          after       — a player whose realm we teleport into (0x0089).
        Set with `parkrealm <name>`, `after <link|guid>`, or --after-scan."""
        if stop.is_set():
            return
        pending["autoscan"] = False        # never chain another scan from this
        if state.get("after_realm"):
            nm = state["after_realm"]
            show_line(f"  {lead}searching for realm '{nm}' to park ...")
            search_realm(nm, then_join=True)
            return
        if state.get("after_guid"):
            show_line(f"  {lead}joining the waiting realm to park ...")
            pending["join"] = state["after_guid"]
            return
        if state.get("after"):
            who = state["after"]
            guid = find_guid(who)
            if not guid:
                show_line(f"  waiting realm: no known GUID for '{who}' — run "
                          f"'find {who}' once, or 'after off' to stop trying")
                return
            show_line(f"  {lead}heading to {who}'s realm to park ...")
            pending["guid"] = guid

    def crawl_run(targets, delay, out_file):
        """Bulk-scan driver. For each (guid, name): join the realm by GUID (no
        player needed), wait for entry, let the autoscan settle + scan it, then
        move on. Realms we can't enter (private / gone / rate-limited) are
        skipped after --crawl-arrival-timeout. Runs in its own thread; the
        autoscan worker signals each realm done via crawl['event']. Machines
        accumulate in `offers` (realm-tagged) and are appended to out_file after
        every realm so a crash/stop never loses the run."""
        crawl["active"] = True
        crawl["stop"] = False
        total = len(targets)
        scanned = 0
        # Progress bookkeeping so 'crawl status' can give a live ETA. `total`/`i`
        # are this batch; `done` counts realms fully handled (scanned, skipped or
        # overran) so elapsed/done is a real average-per-realm. run_started is
        # this batch's clock; batched rescans reset it each batch.
        crawl["run_started"] = time.monotonic()
        crawl["total"] = total
        crawl["i"] = 0
        crawl["done"] = 0
        # Pace by the interval BETWEEN reconnects, not by a fixed sleep bolted on
        # after each scan. `delay` is the minimum time one join (reconnect) must
        # be from the last — but the arrival+settle+scan we just did already
        # counts toward it, so a realm that took longer than `delay` to scan
        # waits 0, and only genuinely fast realms get paced. Same reconnect
        # frequency the server sees (same ban exposure), far less idle time.
        last_join = None

        def pace_reconnect():
            if not delay or last_join is None:
                return
            gap = delay - (time.monotonic() - last_join)
            while gap > 0 and not (stop.is_set() or crawl["stop"]):
                time.sleep(min(0.5, gap))
                gap = delay - (time.monotonic() - last_join)

        try:
            for i, (guid, name) in enumerate(targets, 1):
                if stop.is_set() or crawl["stop"]:
                    break
                # When we start realm i, exactly i-1 are fully handled — this is
                # what 'crawl status' reads for its ETA (covers the skip path too,
                # since the next iteration updates it regardless of how this one
                # ended).
                crawl["i"], crawl["done"] = i, i - 1
                # Just-in-time name resolution (rescan fast): a realm gets a fresh
                # GUID every re-host, so the GUID staged here may be stale. Rather
                # than resolve the whole list up front, resolve THIS realm's name
                # to its current GUID right before joining it — the same joinname
                # path the Hollawarp driver uses. Falls back to the staged GUID if
                # the name can't be resolved (hidden, renamed, or rate-limited).
                if crawl.get("resolve_each") and name:
                    pace_reconnect()             # the search shares the socket
                    if stop.is_set() or crawl["stop"]:
                        break
                    fresh = resolve_realm_name(name)
                    if fresh and fresh != guid:
                        show_line(f"  crawl {i}/{total}: '{name}' -> current "
                                  f"GUID {fresh[:8]}… (was {guid[:8]}…)")
                        guid = fresh
                    elif not fresh:
                        show_line(f"  crawl {i}/{total}: '{name}' — not found in "
                                  f"browser (offline/renamed), trying saved GUID "
                                  f"{guid[:8]}…")
                crawl["arrived"].clear()
                crawl["event"].clear()
                pending["autoscan"] = True
                if reg["guid"] and guid == reg["guid"]:
                    # Already standing in this realm — the server won't hand us
                    # off into a realm we're already in, so skip the (pointless,
                    # ban-risky) rejoin and scan the objects we already have.
                    # No reconnect happens here, so it needs no pacing.
                    show_line(f"  crawl {i}/{total}: already in '{name}' "
                              f"({guid[:8]}…) — scanning in place ...")
                    maybe_autoscan()
                else:
                    pace_reconnect()             # hold the min gap since last join
                    if stop.is_set() or crawl["stop"]:
                        break
                    show_line(f"  crawl {i}/{total}: joining '{name}' "
                              f"({guid[:8]}…) — {len(offers)} machines so far ...")
                    last_join = time.monotonic()
                    pending["join"] = guid
                    if not crawl["arrived"].wait(args.crawl_arrival_timeout):
                        show_line(f"  crawl {i}/{total}: '{name}' — couldn't enter "
                                  f"(private / gone / rate-limited), skipping")
                        continue
                if not crawl["event"].wait(args.crawl_scan_timeout):
                    show_line(f"  crawl {i}/{total}: '{name}' scan overran "
                              f"{args.crawl_scan_timeout:.0f}s — moving on")
                else:
                    scanned += 1
                    # Same rule as the auto-Hollawarp harvester: a realm that
                    # sells anything goes on the rescan watchlist so 'rescan'
                    # can revisit it later. Keyed by GUID, so re-crawling just
                    # refreshes the entry.
                    rg = reg["guid"]
                    mine = [r for r in offers.values()
                            if r.get("realm_guid") == rg]
                    if mine:
                        add_watch(rg, state["realm"], state["realm_owner"])
                        show_line(f"  crawl {i}/{total}: '{name}' — {len(mine)} "
                                  f"vend(s), watchlisted ({len(watchlist)} on "
                                  f"list)")
                if out_file:
                    try:
                        dump_machines(out_file)
                    except Exception as e:
                        show_line(f"  crawl: couldn't write {out_file}: {e}")
                # No trailing sleep here — pacing is applied at the next join via
                # pace_reconnect(), which already counts this realm's scan time.
        finally:
            crawl["done"] = crawl["i"] = total
            crawl["active"] = False
            pending["autoscan"] = False
            show_line(f"  crawl finished: {scanned}/{total} realm(s) scanned, "
                      f"{len(offers)} machine(s) collected."
                      + (f" Saved to {out_file}." if out_file
                         else " 'dump <file>' to save."))

    def resolve_realm_name(name):
        """Look a realm NAME up in the realm browser and return the wire-hex GUID
        of the exact-name match, or None. This is the 'joinname' resolution the
        Hollawarp driver uses to re-enter a hollered realm by name instead of by
        its broadcast link. Waits for the browser reply (do_search); None means
        no reply or no exact match, and the caller falls back to the holla GUID."""
        res = do_search(name)
        if res is None:
            return None
        return realm_search["guid"]        # exact-name match guid, or None

    def warp_driver():
        """Auto-Hollawarp worker: drain the queue, joining each broadcast realm,
        scanning it, watchlisting it if it sells anything, then PARK (leave for
        the configured home realm) once the queue is empty so the bot never sits
        idle in a stranger's realm. One realm at a time; reuses the crawl
        join/scan signalling (crawl['arrived']/['event']). Runs in its own thread
        so the reader stays free to execute the join. publish_realm (end of
        scan_machines) writes each scanned realm to vends.json."""
        hollow["driver"] = True
        did_any = False
        try:
            while hollow["auto"] and hollow["q"] and not stop.is_set():
                # A manual crawl (active) or a crawlfile name-resolution pass
                # (resolving) owns the socket — the holla stays queued and we
                # wait until both are done before joining anything.
                if crawl["active"] or crawl.get("resolving"):
                    time.sleep(1.0)
                    continue
                item = hollow["q"].pop(0)
                g = item["guid"]
                nm = item.get("name")
                if g == reg["guid"]:           # already standing in it
                    continue
                # Join by NAME, not by the raw holla link: resolve the realm's
                # CURRENT guid through the realm browser (the joinname path a
                # player uses) and enter that. Fall back to the broadcast GUID if
                # the name can't be resolved — hidden from search, odd spelling,
                # or the browser is rate-limited — so a realm is never missed.
                join_guid, via = g, "GUID"
                if nm:
                    resolved = resolve_realm_name(nm)
                    if resolved:
                        join_guid, via = resolved, f"name '{nm}'"
                    else:
                        show_line(f"  [hollowarp] name '{nm}' not found in realm "
                                  f"browser — falling back to GUID join")
                show_line(f"  [hollowarp] joining {g[:8]}… via {via} "
                          f"({len(hollow['q'])} more queued) ...")
                crawl["active"] = True
                crawl["arrived"].clear()
                crawl["event"].clear()
                pending["autoscan"] = True
                pending["join"] = join_guid
                # (the autoscan worker hides off-map on arrival for every
                # scan-join now, gated by wander["on"] — see maybe_autoscan)
                if not crawl["arrived"].wait(args.crawl_arrival_timeout):
                    show_line(f"  [hollowarp] {g[:8]}… — couldn't join, skipping")
                    crawl["active"] = False
                    pending["autoscan"] = False
                    continue
                crawl["event"].wait(args.crawl_scan_timeout)
                crawl["active"] = False
                did_any = True
                realm, rg = state["realm"], reg["guid"]
                mine = [r for r in offers.values()
                        if r.get("realm_guid") == rg]
                if mine:
                    add_watch(rg, realm, state["realm_owner"])
                    show_line(f"  [hollowarp] {realm}: {len(mine)} vend(s) — "
                              f"watchlisted ({len(watchlist)} on list)")
                else:
                    show_line(f"  [hollowarp] {realm}: no vends — not watchlisted")
                # (already hidden off-map since arrival — nothing to move here)
                time.sleep(args.warp_delay)
        finally:
            hollow["driver"] = False
            # Queue drained — park (leave for home) so we don't linger in the
            # last warped-into realm. No-op if no park target is configured.
            if did_any and hollow["auto"] and not stop.is_set() \
                    and not crawl["active"]:
                if state.get("after_realm") or state.get("after_guid") \
                        or state.get("after"):
                    show_line("  [hollowarp] queue empty — parking ...")
                    go_to_waiting()

    def hollowarp_detected(t, body):
        """A frame mentioning a Hollowarp arrived. Dump the first few raw (to
        verify/repair the parser, since we've never captured one), and if auto is
        on, extract the realm GUID + display NAME and queue both. Dedup by GUID
        via `seen`; the driver joins by name (GUID as fallback)."""
        g = P.parse_hollowarp(body) if hollow["auto"] else None
        nm = P.parse_hollowarp_name(body) if hollow["auto"] else None
        # show raw bytes in sniff-only mode, when we can't parse a GUID, or for
        # the first few auto detections — but not for every one in a busy session
        if (not hollow["auto"]) or (g is None) or hollow["dumps"] < 3:
            hollow["dumps"] += 1
            txt = "".join(chr(c) if 32 <= c < 127 else "." for c in body)
            vlog(f"  [hollowarp] type=0x{t:04x} len={len(body)}")
            vlog(f"             text: {txt}")
            vlog(f"             hex:  {body.hex()}")
        if not hollow["auto"] or not g:
            if hollow["auto"] and not g:
                show_line("             (no realm GUID found — parser needs the "
                          "real layout; the dump above has it)")
            return
        if g == reg["guid"]:
            return
        # Cooldown/dedup KEY: the realm NAME when the holla carries one, else the
        # GUID. Keying on the name means the same realm can't be re-joined inside
        # the 10-min window (hollow["cooldown"] = 600s) even if it re-hollers with
        # a DIFFERENT guid (re-hosted realms get a new guid), which a guid-only
        # key would miss.
        key = nm.lower() if nm else g
        now = time.time()
        last = hollow["seen"].get(key)
        if last is not None and now - last < hollow["cooldown"]:
            # same realm hollered again inside the cooldown — skip it so we don't
            # visibly re-warp to the same shop over and over (a clear bot tell).
            secs = int(hollow["cooldown"] - (now - last))
            vlog(f"  [hollowarp] {(nm or g[:8]+'…')} hollered again — on cooldown "
                 f"({secs}s left), skipping")
            return
        if any((it.get("name") or "").lower() == key or it["guid"] == g
               for it in hollow["q"]):                    # already queued
            return
        hollow["seen"][key] = now
        hollow["q"].append({"guid": g, "name": nm})
        label = f"'{nm}' ({g[:8]}…)" if nm else f"{g[:8]}…"
        show_line(f"  [hollowarp] queued realm {label} (queue {len(hollow['q'])})")
        if not hollow["driver"]:
            threading.Thread(target=warp_driver, daemon=True).start()

    def _price_norm(s):
        """Lowercase, strip punctuation, collapse spaces — so 'Cupid's Halo',
        'cupids halo', 'CUPIDS  HALO' all match the same key."""
        import re
        return re.sub(r"\s+", " ",
                      re.sub(r"[^a-z0-9 ]", " ", s.lower())).strip()

    def load_prices():
        """Fetch the community price list and index it by normalised item name.
        Runs in a background thread (network I/O). Each entry's words[0] is
        'Name: min - max' — the name is before the colon, the whole string is the
        answer we hand back in chat."""
        import urllib.request
        try:
            req = urllib.request.Request(
                pricebot["url"], headers={"User-Agent": "Mozilla/5.0"})
            data = json.loads(urllib.request.urlopen(req, timeout=20)
                              .read().decode("utf-8"))
        except Exception as e:
            show_line(f"  [pricebot] couldn't fetch prices: {e}")
            return
        m = {}
        for e in data:
            w = (e.get("words") or [""])[0]
            if ":" in w:
                key = _price_norm(w.split(":", 1)[0])
                if key:
                    m[key] = w
        pricebot["map"] = m
        pricebot["fetched"] = time.time()
        show_line(f"  [pricebot] loaded {len(m)} item prices.")

    def _price_lookup(query):
        """Find the best community-price string for a queried item. EXACT and
        verbatim matches are tried BEFORE any fuzzy guess, in order:
          1. exact normalised match;
          2. the query appears verbatim inside a longer catalogue name (shortest
             wins: 'angel wing' -> 'Angel Wings', not 'Violet Angel Wings');
          3. a full catalogue name appears verbatim inside a wordier query
             (longest wins), ignoring trivial one-word fragments so a multi-word
             query never decays into a catch-all 'shirt'/'hat' entry;
          4. otherwise guess the single MOST SIMILAR catalogue item, so a typo
             still resolves ('dark traveler shirt' -> 'Dark Traveller Shirt') and
             an item with no exact entry still gets its closest match ('farmer
             shirt' -> 'Farmer's Hat'). Only genuine gibberish (nothing even
             roughly similar) returns nothing."""
        import difflib
        key = _price_norm(query)
        m = pricebot["map"]
        if not key or not m:
            return None
        if key in m:
            return m[key]
        containing = [k for k in m if key in k]
        if containing:
            return m[min(containing, key=len)]
        contained = [k for k in m if k in key and (" " in k or len(k) >= 6)]
        if contained:
            return m[max(contained, key=len)]
        close = difflib.get_close_matches(key, list(m), n=1, cutoff=0.5)
        return m[close[0]] if close else None

    def _ensure_prices():
        """Make sure the community price map is loaded and fresh. Fetched in the
        background (never blocks a scan); returns True only when a usable map is
        already in hand THIS instant. Auto-snipe treats 'not yet loaded' as
        'unknown value' and refuses to buy, so a slow/failed fetch can never
        cause a blind purchase."""
        stale = time.time() - pricebot.get("fetched", 0.0) > 3600
        if not pricebot["map"] or stale:
            if not pricebot.get("_loading"):
                pricebot["_loading"] = True
                def _bg():
                    try:
                        load_prices()
                    finally:
                        pricebot["_loading"] = False
                threading.Thread(target=_bg, daemon=True).start()
        return bool(pricebot["map"])

    def community_avg(item):
        """Midpoint of an item's community-price range (community_prices.json),
        as a number in cubits, or None when the item isn't listed. Uses the same
        fuzzy lookup the price bot uses, then averages the first and last numbers
        in the 'min - max' string (a lone number averages with itself). This is
        the value the auto-snipe gate compares against min_avg."""
        import re
        s = _price_lookup(item)
        if not s or ":" not in s:
            return None
        nums = [int(n.replace(",", ""))
                for n in re.findall(r"[\d,]+", s.split(":", 1)[1])]
        nums = [n for n in nums if n > 0]
        if not nums:
            return None
        return (nums[0] + nums[-1]) / 2.0

    def snipe_reject(item, price, currency):
        """Why auto-snipe must NOT buy this offer, or None if it's a clear steal.
        Called from open_and_buy with the REAL item name + price off the dialog.
        Returns an outcome slug: 'snipe_wrong_currency' (not priced in cubits),
        'snipe_low_value' (community avg unknown OR below min_avg). A None return
        means both gates pass: price <= steal_max (already checked upstream) and
        community avg >= min_avg."""
        if (currency or "").lower()[:5] != "cubit":
            return "snipe_wrong_currency"
        _ensure_prices()
        avg = community_avg(item)
        if avg is None or avg < autosnipe["min_avg"]:
            return "snipe_low_value"
        return None

    # Warm the community price list at startup so auto-snipe can value items on
    # the very first realm instead of missing them while the first fetch lands.
    if autosnipe["on"]:
        _ensure_prices()

    def _scanned_avg(term):
        """Average price of an item across the realms we've actually scanned,
        computed from the CURRENT market catalogue (the live listings the market
        DB holds after scans). Per-currency — cubits and other currencies are
        never mixed. Returns a short
        'Average: N c | Min: M c | Listings: K' string, or None if the DB is
        closed or nothing scanned matches the item.
        Listings priced at 0 are excluded — an idle slot isn't a real sale."""
        if mdb is None or not term:
            return None
        try:
            rows = mdb.current_for_item(term)
        except Exception:
            return None
        return _format_scanned(rows)

    # Phrasings the price bot recognises, tried in order, each capturing the
    # item name. Covers 'price of X', 'how much is X', "what's the value of X",
    # 'price check X' / 'pricecheck X', and the trader shorthand 'pc X'.
    PRICE_PATTERNS = [
        r"\bprice\s*check\b\s*[:\-]?\s*(.+)",
        r"\bpc\b\s*[:\-]?\s*(.+)",
        r"what(?:'?s| is| are)?\s*(?:the\s+)?(?:price|cost|value|worth)"
        r"\s*(?:of|for|on)?\s*[:\-]?\s*(.+)",
        r"how much\s*(?:is|are|for|does|do|would|to buy)?\s*"
        r"(?:a|an|the)?\s*(.+)",
        r"(?:price|cost|worth|value)\s*(?:of|for|on|is|are|it)?"
        r"\s*[:\-]?\s*(.+)",
    ]

    def handle_price_query(sender_guid, text):
        """If the price bot is on and a chat line addresses the bot by name and
        asks for an item's price (in any of several phrasings), reply in-game
        with the community price AND the average across scanned realms. Never
        answers the bot's own messages. Anti-spam: a global cooldown between any
        two replies, a longer per-player cooldown, and a small delay before the
        reply actually goes out (so it doesn't fire instantly like a bot)."""
        if not pricebot["on"]:
            return
        if conn.get("own") and sender_guid == conn.get("own"):
            return
        import re
        low = text.lower()
        own = (prof["identity"]["display_name"] or "").lower()
        if own and own not in low:            # only when addressed by name
            return
        item = None
        for pat in PRICE_PATTERNS:
            m = re.search(pat, low)
            if m:
                item = m.group(1)
                break
        if not item:
            return
        # Strip the bot's own name if it trailed the query ('pc halo botname'),
        # drop trailing filler/politeness, and tidy punctuation/whitespace.
        if own:
            item = re.sub(re.escape(own), "", item)
        item = re.sub(r"\b(cost|worth|please|pls|plz|thanks|thx|thank you|"
                      r"sell|go for|now)\b", " ", item)
        item = re.sub(r"\s+", " ", item).strip(" ?!.,'\"\t")
        if not item:
            return
        now = time.time()
        # anti-spam gates: global rate limit, then per-player rate limit
        if now - pricebot["last_reply"] < pricebot["cooldown"]:
            return
        seen = pricebot["seen"]
        if now - seen.get(sender_guid, 0.0) < pricebot["per_user"]:
            return
        # keep the seen-map from growing without bound
        if len(seen) > 512:
            cut = now - pricebot["per_user"] * 4
            for g in [g for g, t in seen.items() if t < cut]:
                del seen[g]
        seen[sender_guid] = now            # throttle this player either way
        disp = _price_lookup(item)
        # Look the item up in the scanned market by the community-catalogue name
        # when we matched one (the part before the colon), else by what was
        # asked — that gives the DB its best shot at matching.
        db_term = disp.split(":", 1)[0].strip() if disp else item
        scanned = _scanned_avg(db_term)
        if not disp and not scanned:
            return
        # Community range first (or a tidy Title Case of what was asked when the
        # catalogue has no entry for it), then the live scanned-market stats.
        reply = disp or item.title()
        if scanned:
            reply = f"{reply} | {scanned}"
        reply = _chat_clean(reply)
        # Reserve the global slot NOW so a burst of messages in the delay window
        # can't stack up several queued replies; the shared chat gate then spaces
        # the actual send from any other bot message.
        pricebot["last_reply"] = now
        show_line(f"  [pricebot] -> {reply}")
        chat_say(reply)

    def handle_summon(sender_guid, text):
        """If summon is on and a player types 'summon <bot name>' in chat,
        teleport to them — but ONLY if they're in the bot's current realm.
        Regular chat (0x000c) is realm-local, so a chat sender is already here;
        we also require them in realm_players as an explicit same-realm guard,
        which keeps the bot from ever being pulled across realms."""
        if not summon["on"]:
            return
        own_guid = conn.get("own")
        if own_guid and sender_guid == own_guid:
            return
        own = _alnum(prof["identity"]["display_name"] or "")
        # 'summon botname' (any casing/decoration) -> normalised 'summonbotname'
        if not own or ("summon" + own) not in _alnum(text):
            return
        # summon MOVES the bot, so it's an approved-only command.
        if not is_approved(sender_guid):
            who = players.get(sender_guid, sender_guid[:8] + "…")
            show_line(f"  [summon] ignored — {who} is not on the approved list.")
            chat_say("Sorry, summon is for approved users only.")
            return
        if sender_guid not in realm_players:
            # they're not confirmed in our realm — refuse rather than travel
            chat_say("You have to be in my realm to summon me.")
            return
        who = players.get(sender_guid, sender_guid[:8] + "…")
        show_line(f"  [summon] {who} summoned me — queued.")
        queue_move("guid", sender_guid, f"summon from {who}", autoscan=False)

    def handle_scan_query(sender_guid, text):
        """If scan-on-command is on and a player in the bot's realm addresses the
        bot by name and says 'scan realm <exact name>', search that realm by
        name, join it, and scan its vending machines into the market DB. Same
        same-realm requester guard as summon, plus a 30s rate limit so it can't
        be used to fling the bot around endlessly."""
        if not scanbot["on"]:
            return
        own_guid = conn.get("own")
        if own_guid and sender_guid == own_guid:
            return
        import re
        own = prof["identity"]["display_name"] or ""
        low = text.lower()
        if own and own.lower() not in low:        # only when addressed by name
            return
        m = re.search(r"scan\s*realm\s*[:\-]?\s*(.+)", text, re.IGNORECASE)
        if not m:
            return
        realm = m.group(1)
        # Drop the bot's own name if it trailed the command
        # ("scan realm My Shop botname") and tidy stray quotes/punctuation, but
        # otherwise keep the realm name EXACTLY as typed — the browser match is
        # case-insensitive but wants the real spelling.
        if own:
            realm = re.sub(re.escape(own), "", realm, flags=re.IGNORECASE)
        realm = realm.strip(" \t?!.,'\"")
        if not realm:
            return
        # scanning MOVES the bot across realms, so it's an approved-only command.
        if not is_approved(sender_guid):
            who = players.get(sender_guid, sender_guid[:8] + "…")
            show_line(f"  [scanbot] ignored — {who} is not on the approved list.")
            chat_say("Sorry, scan realm is for approved users only.")
            return
        if sender_guid not in realm_players:
            chat_say("You have to be in my realm to send me scanning.")
            return
        if mdb is None:
            chat_say("My market DB is off, so I can't store a scan now.")
            return
        if scanbot["active"]:
            chat_say("I'm already finding a realm to scan. Try again "
                     "after this one starts.")
            return
        now = time.time()
        if now - scanbot["last"] < 30.0:
            return
        scanbot["last"] = now
        who = players.get(sender_guid, sender_guid[:8] + "…")
        show_line(f"  [scanbot] {who} asked me to scan realm '{realm}' "
                  f"— searching.")
        # Both captured emojis belong inside this one message: C9 immediately
        # after "On it", and E5 at the end. Never use a Unicode em dash here:
        # the game renders its three UTF-8 bytes as a red face followed by ##.
        try:
            send_public_chat(_build_scanbot_chat(
                "On it ", f" searching for '{realm}' to scan. "))
        except Exception as e:
            # A failed send must not prevent the lookup/scan from proceeding.
            show_line(f"  [scanbot] chat acknowledgement failed "
                      f"({type(e).__name__}: {e})")
        # A direct then_scan search is fire-and-forget. When the server-side realm
        # browser session has lapsed, the server silently drops that search and
        # scanbot used to remain at "searching" forever. Resolve in a worker via
        # find_realm_by_name/do_search instead: that path waits for the reply,
        # reopens a lapsed browser, retries, and can report a definite failure.
        # The worker also leaves the reader free to receive the 0x00e1 reply.
        scanbot["active"] = True

        def resolve_and_queue_scan():
            try:
                match, reason = find_realm_by_name(realm)
                if stop.is_set():
                    return
                if not match:
                    if reason == "noreply":
                        detail = "the realm browser did not answer after retrying"
                    else:
                        detail = "no exact realm-name match was returned"
                    show_line(f"  [scanbot] couldn't find '{realm}': {detail}.")
                    chat_say(f"I couldn't find '{realm}' ({detail}).")
                    return
                matched_name, guid = match
                show_line(f"  [scanbot] found '{matched_name}' ({guid[:8]}...) — "
                          f"queued to join + scan.")
                queue_move("join", guid, f"scanbot realm {matched_name}",
                           autoscan=True, watch_if_vends=True)
            except Exception as e:
                show_line(f"  [scanbot] realm lookup failed for '{realm}': "
                          f"{type(e).__name__}: {e}")
                chat_say(f"I couldn't start the scan for '{realm}'.")
            finally:
                scanbot["active"] = False

        threading.Thread(target=resolve_and_queue_scan, daemon=True).start()

    # ---- QUIZ auto-answer bot (Stage 18) ---------------------------------
    # Reads every PUBLIC chat line (called before the whisper-mode gate, so it
    # works even when the whisper bot has taken over public chat). Reacts ONLY
    # to the designated host. Three things it watches for, in order:
    #   1. a go-ahead phrase while an answer is held -> release the answer NOW
    #   2. a "the answer is X" reveal -> learn X against the last question
    #   3. a fresh question -> compute the answer instantly and raise its hand
    # All sends go through pub_say (the reader-thread-safe public queue).
    def _quiz_reveal(text):
        """If the host is REVEALING the correct answer, pull it out; else None.
        Conservative: requires the word 'answer' so ordinary chatter isn't
        mistaken for a reveal."""
        m = re.search(r"(?:correct\s+answer|the\s+answer|answer)\s*"
                      r"(?:is|was|=|:)\s*[:\-]?\s*(.+)$", text, re.I)
        if not m:
            return None
        ans = m.group(1).strip().strip("\"'.!").strip()
        # Drop a trailing "!" celebration or "everyone"/"guys" address noise.
        ans = re.sub(r"\s+(everyone|guys|folks|all)\W*$", "", ans, flags=re.I)
        return ans or None

    def _quiz_go_ahead(low, own):
        """True if `low` (lowercased host line) is a go-ahead to speak, and it is
        not addressed to a DIFFERENT named player. A go-ahead that names us, or
        names nobody, counts; one that clearly names someone else does not (best
        effort — we only know it's not us if OUR name is absent and another
        known player's name is present)."""
        if not any(p in low for p in quizbot["go_phrases"]):
            return False
        if own and own.lower() in low:
            return True
        # Someone else called on by name? If a known player's name (not ours)
        # appears right before the go-ahead, assume it's not our turn.
        for nm in players.values():
            nml = (nm or "").lower()
            if nml and nml != (own or "").lower() and len(nml) >= 3 \
                    and nml in low:
                return False
        return True

    def _quiz_release(reason):
        """Drop the held answer NOW (the go-ahead arrived). No-op if nothing is
        held. Shared by the host go-ahead phrase and the realm-unmute trigger."""
        qb = quizbot
        if not qb["pending"]:
            return False
        ans = qb["pending"]["a"]
        qb["pending"] = None
        qb["answered"] += 1
        show_line(f"  [quiz] release ({reason}) -> {ans}")
        pub_say(ans)
        return True

    def handle_quiz(sender_guid, text):
        qb = quizbot
        if not qb["on"] or qb["brain"] is None or not text:
            return
        own_guid = conn.get("own")
        if own_guid and sender_guid == own_guid:      # never react to ourselves
            return
        host = qb["host"]
        if not host:                                  # no host set -> stay silent
            return
        name = (players.get(sender_guid) or "").strip().lower()
        if name != host:                              # only the question-giver
            return
        own = (prof["identity"]["display_name"] or "").strip()
        low = text.lower()

        # 1) Holding an answer? A host go-ahead phrase releases it instantly.
        # (The primary release for this game is the realm-UNMUTE system notice,
        # handled frame-type-agnostically in the reader loop; this phrase path is
        # a spoken-go-ahead fallback.)
        if qb["pending"] is not None:
            if _quiz_go_ahead(low, own):
                _quiz_release("host go-ahead")
                return
            if time.time() - qb["pending"]["raised"] > qb["timeout"]:
                show_line("  [quiz] pending answer expired (no go-ahead)")
                qb["pending"] = None

        # 2) Host revealing the correct answer? Learn it for next time.
        if qb["auto_learn"] and qb["last_q"]:
            revealed = _quiz_reveal(text)
            if revealed:
                if qb["brain"].learn(qb["last_q"], revealed):
                    qb["learned"] += 1
                    show_line(f"  [quiz] learned: {qb['last_q']!r} -> "
                              f"{revealed!r}")
                qb["last_q"] = None                   # don't re-learn on echoes
                return

        # 3) A fresh question -> compute instantly, then act. Treat the line as a
        # question if it LOOKS like one (has a "?" or a question word) OR the brain
        # can confidently answer it — so a BARE expression the host types, like
        # "5x5" or "1+1" (no "whats", no "?"), is answered too.
        r = qb["brain"].answer(text)
        is_question = (cc_quiz.looks_like_question(text)
                       or r["source"] in ("math", "exact", "learned"))
        if not is_question:
            return
        qb["last_q"] = text
        # Open a fresh round for crowd-learning (the guesses come in after the
        # realm unmutes). Set BEFORE the confidence check so we still learn from
        # the crowd even when we had no answer of our own.
        qb["round"] = {"q": text, "answers": [], "collecting": False}
        if not r["source"] or r["confidence"] < qb["min_conf"]:
            show_line(f"  [quiz] no answer yet for: {text} "
                      f"(will learn it from the crowd)")
            return
        ans = r["answer"]
        show_line(f"  [quiz] {r['source']} (conf {r['confidence']:.2f}) "
                  f"ready: {ans}")
        if qb["gate"]:
            # HOLD the answer until the realm unmutes (the go-ahead). Only type
            # "question" first if hand-raising is explicitly enabled.
            qb["pending"] = {"q": text, "a": ans, "raised": time.time()}
            if qb["raise_hand"]:
                pub_say(qb["raise_word"])
        else:
            qb["answered"] += 1
            pub_say(ans)

    def _quiz_collect(sender_guid, text):
        """While a round is collecting (realm unmuted), record each player's
        answer line. Called for EVERY public chat line, so it filters out our own
        messages, questions, and obvious spam before keeping a guess."""
        qb = quizbot
        rnd = qb["round"]
        if not qb["on"] or not qb["auto_learn"] or not rnd \
                or not rnd.get("collecting"):
            return
        own_guid = conn.get("own")
        if own_guid and sender_guid == own_guid:      # not our own answer
            return
        t = (text or "").strip()
        # A real answer is short; skip long spam (the "@@@@@..." line), empties,
        # and anything that is itself a question.
        if not t or len(t) > 40 or cc_quiz.looks_like_question(t):
            return
        rnd["answers"].append(t)

    def _quiz_round_start():
        """Realm just unmuted — begin gathering the crowd's answers for the
        question that was asked, so the round can be learned when it closes."""
        qb = quizbot
        rnd = qb["round"]
        if qb["auto_learn"] and rnd and rnd.get("q") and not rnd.get("collecting"):
            rnd["collecting"] = True
            rnd["answers"] = []
            show_line(f"  [quiz] collecting crowd answers for: {rnd['q']}")

    def _quiz_round_close(reason):
        """Realm re-muted (or round otherwise ends) — learn the answer the crowd
        agreed on most, if enough players agreed. Groups answers by their
        normalised form and keeps the first original spelling as the answer."""
        qb = quizbot
        rnd = qb["round"]
        if not rnd or not rnd.get("collecting"):
            return
        rnd["collecting"] = False
        q = rnd.get("q")
        answers = rnd.get("answers") or []
        if not (qb["auto_learn"] and q and answers):
            qb["round"] = None
            return
        counts, rep = {}, {}
        for a in answers:
            k = cc_quiz.normalize(a)
            if not k:
                continue
            counts[k] = counts.get(k, 0) + 1
            rep.setdefault(k, a)                      # first original spelling
        qb["round"] = None
        if not counts:
            return
        ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
        best_k, best_n = ranked[0]
        runner = ranked[1][1] if len(ranked) > 1 else 0
        # Need BOTH enough agreement AND a clear win over the runner-up. A guessing
        # crowd produces near-ties (usa 5 / south-africa 4); those are NOT trusted.
        if best_n < qb["min_agree"] or (best_n - runner) < qb["min_margin"]:
            show_line(f"  [quiz] round closed ({reason}); crowd unsure "
                      f"(top '{rep[best_k]}'={best_n} vs runner-up={runner}) — "
                      f"NOT learning (needs >={qb['min_agree']} and a "
                      f">={qb['min_margin']} lead)")
            return
        ans = rep[best_k]
        if qb["brain"].learn(q, ans):
            qb["learned"] += 1
            show_line(f"  [quiz] LEARNED from crowd ({best_n} agreed): "
                      f"{q!r} -> {ans!r}")
        else:
            show_line(f"  [quiz] crowd confirmed known answer: {q!r} -> {ans!r}")

    # ---- keyword chat commands -------------------------------------------
    # Everything the bot answers in chat by an explicit keyword lives in the
    # registry below, so adding a command later is a one-liner: append an entry
    # with its trigger word(s), a short help label, whether it needs an approved
    # user, and a handler fn(sender_guid, arg) -> reply string (or None to stay
    # quiet). The price bot / summon / scan keep their own phrase-matching
    # handlers; this covers the plain keyword commands (help, realm, greeting).
    cmdbot = {"on": True, "last": 0.0, "seen": {}, "cooldown": 1.5,
              "per_user": 4.0}
    # Separate anti-spam timer for the PUBLIC 'help' reply so a whisper command
    # from the same player (which trips cmdbot) can't suppress the public answer.
    pubhelp_gate = {"last": 0.0, "seen": {}, "cooldown": 1.5, "per_user": 4.0}

    def _reply(text):
        """Send one composed reply through the shared outbound gate (normalised,
        and spaced from other bot messages by --chat-gap)."""
        chat_say(text)

    def cmd_help(sender_guid, arg):
        """Explain HOW to use each command, not just its name. One chat line:
        the bot's name, then each command's syntax. Approved users also see the
        privileged ones. Built from the registry's 'usage' fields so a new
        command's help appears automatically."""
        own = prof["identity"]["display_name"] or "me"
        # Keep help SHORT and free of markup brackets (the in-game chat renderer
        # eats "<...>" and very long lines may not show up at all). Over a whisper
        # they are already doing it right, so list the commands. In public chat,
        # just point them at whisper — that is how the bot is meant to be used.
        if reply_ctx.get("whisper_to") is not None:
            msg = ("Try: price of ITEM, pc ITEM, realm, help. Buy orders: "
                   "buy QTY ITEM @ PRICE, balance, orders, cancel N, withdraw.")
            if is_approved(sender_guid):
                msg += " Approved: summon, scan realm NAME."
            return msg
        # No literal slash-command here: a public message containing "/whisper" is
        # swallowed by the server's command parser and never renders. Describe the
        # Whisper action by name instead.
        return (f"Whisper me to use me! In chat, choose Whisper and pick {own}, "
                f"then send your question.")

    def _machine_count(realm_ref_str):
        """How many vending machines a realm has, from the market DB: the count
        of its current offers (current_offers is keyed one row per machine).
        Accepts a realm name or GUID. None if the DB is off or the query errors."""
        if mdb is None or not realm_ref_str:
            return None
        try:
            rows = mdb.current_in_realm(realm_ref_str)
        except Exception:
            return None
        return len({r["machine_guid"] for r in rows})

    def _find_realm_in_db(name):
        """Resolve a realm the asker NAMED to (canonical_name, owner,
        machine_count) from the market DB, forgiving small spelling differences
        so '24hr rentals' still finds '24h Rentals'. Exact (case-insensitive)
        name wins, then a substring match, then a difflib close match; ties go to
        the busiest realm. Re-hosts that share a name are merged. None if the DB
        is off or nothing matches. (Reads the DB directly, via the same _q the
        library uses, to keep all of this in one file.)"""
        if mdb is None or not name:
            return None
        try:
            rows = mdb._q(
                "SELECT r.name AS name, MAX(r.owner) AS owner, "
                "COUNT(c.machine_guid) AS machines "
                "FROM realms r "
                "JOIN machines m ON m.realm_guid = r.guid "
                "JOIN current_offers c ON c.machine_guid = m.guid "
                "GROUP BY LOWER(r.name)")
        except Exception:
            return None
        if not rows:
            return None
        key = name.strip().lower()
        exact = [r for r in rows if (r["name"] or "").lower() == key]
        subs = [r for r in rows if key in (r["name"] or "").lower()
                or (r["name"] or "").lower() in key]
        pick = None
        if exact:
            pick = max(exact, key=lambda r: r["machines"])
        elif subs:
            pick = max(subs, key=lambda r: r["machines"])
        else:
            import difflib
            names = [r["name"] or "" for r in rows]
            close = difflib.get_close_matches(name, names, n=1, cutoff=0.7)
            if close:
                pick = next(r for r in rows if r["name"] == close[0])
        if not pick:
            return None
        return pick["name"], pick["owner"], pick["machines"]

    def cmd_realm(sender_guid, arg):
        """Realm info + vending machine count. 'realm' = the realm the bot is
        standing in; 'realm <name>' = any realm the bot has scanned, looked up by
        name and forgiving of small typos (e.g. 'realm 24hr rentals' finds '24h
        Rentals'). No Share link and no live player count (the client can't tell
        who has LEFT, so a count would be a running total, not who is here now).
        Counts come from the market DB by NAME, which is stable when a realm is
        re-hosted under a new GUID."""
        name = arg.strip()
        if name:                              # a named realm the bot has scanned
            if mdb is None:
                return f"My market DB is off, so I can't look up '{name}'."
            found = _find_realm_in_db(name)
            if not found:
                return f"I have not scanned a realm called '{name}'."
            rname, owner, n = found
            bits = [f"Realm: {rname}"]
            if owner:
                bits.append(f"Owner: {owner}")
            bits.append(f"Vending machines: {n}")
            return " | ".join(bits)
        realm = state.get("realm")
        if not realm:
            return "I'm not in a realm right now."
        bits = [f"Realm: {realm}", f"Owner: {state.get('realm_owner') or '?'}"]
        n = _machine_count(realm)
        if n is not None:
            bits.append(f"Vending machines: {n}")
        return " | ".join(bits)

    def cmd_hi(sender_guid, arg):
        """Friendly reply when someone just says the bot's name."""
        return "Hi!"

    # ---- buy-order commands (Stage 10) -----------------------------------
    # These manage a player's private balance and buy orders in the escrow
    # ledger (odb). Everything money-related is WHISPER-ONLY: a public
    # 'botname balance' just points the player at whisper, so one player can
    # never read another's balance or orders out of public chat. Accounts are
    # keyed by the player's display NAME, the sole identity. We pass the chat
    # GUID too, but the ledger stores it only as last-seen audit metadata — chat
    # GUIDs are per-session and change between logins, so they never gate money.
    # NB: local `import re` — a block-level `import re` elsewhere in run_live makes
    # `re` a function-local, so it must be bound before this first body-level use.
    import re
    _BUY_RE = re.compile(
        r"^(?:(\d+)\s+)?(.+?)\s*(?:@|at|for)\s*(\d+)\s*"
        r"(?:each|ea|per|cubits?|c)?\s*$", re.IGNORECASE)

    def _order_name(sender_guid):
        """The account key + friendly name for a command sender, or None if we
        can't read their name yet (never seen in-realm and not a friend). Keying
        money to an unknown name is unsafe, so callers must handle None."""
        return players.get(sender_guid) or _whisper_name(sender_guid)

    def _whisper_only():
        """True when the current command arrived over a whisper. Money commands
        require this so balances/orders never surface in public chat."""
        return reply_ctx.get("whisper_to") is not None

    # Buy orders wait for a yes/no confirmation before any cubits are reserved, so
    # a mistyped item or price is caught first. Keyed by normalised account name.
    pending_buys = {}   # name -> {"item", "qty", "price"}
    # WITHDRAWALS: a player says 'withdraw [N]' then opens a trade; the bot stakes
    # exactly that amount and confirms ONLY if the server echoes the same figure.
    # Keyed by normalised account name -> amount of cubits.
    pending_withdrawals = {}
    pending_withdraw_debits = {}   # trade_guid -> tr, awaiting the wallet to drop

    def _lowest_listing(item):
        """(min_price, realm_or_None, count) for `item`, read from the SAME
        vends.json catalogue the buy engine actually buys from (market_rows), with
        the same forgiving _alnum matching — so the quote and the buy agree. Cubits
        only. None if nothing in the catalogue matches. (market_rows is defined
        later in this scope but resolved at call time.)"""
        if not item:
            return None
        try:
            rows = market_rows(item)
        except Exception:
            return None
        priced = []
        for r in rows:
            p = _price_num(r.get("price"))
            cur = (r.get("currency") or "").strip().lower()
            if p == float("inf") or p <= 0:
                continue
            if cur in ("", "c", "cubit", "cubits"):   # cubit listings only
                priced.append((int(p), r.get("realm")))
        if not priced:
            return None
        priced.sort(key=lambda x: x[0])
        return (priced[0][0], priced[0][1], len(priced))

    def cmd_balance(sender_guid, arg):
        """Report the sender's own balance: total held, available, reserved."""
        if odb is None:
            return "The buy-order system is off right now."
        if not _whisper_only():
            own = prof["identity"]["display_name"] or "me"
            return f"Whisper me (choose Whisper, pick {own}) to see your balance."
        name = _order_name(sender_guid)
        if not name:
            return "I can't read your name yet — say something in public chat first."
        s = odb.account_summary(name)
        if not s or s["balance"] == 0:
            return ("You have 0 cubits with me. Trade me cubits at the register to "
                    "deposit, then 'buy ITEM @ PRICE' or 'withdraw' any time.")
        extra = ""
        if s["reserved"]:
            extra = (f" — {s['available']} available, {s['reserved']} reserved "
                     f"on {s['open_orders']} open order(s)")
        return (f"Balance: {s['balance']} cubits{extra}. Say 'withdraw' to take it "
                f"back at the register.")

    def cmd_buy(sender_guid, arg):
        """Start a buy order: 'buy QTY ITEM @ PRICE' (QTY optional, default 1).

        Doesn't place anything yet — it quotes the lowest price I currently see,
        repeats the item + price back, and waits for the player to reply 'yes'
        (place it) or 'no' (drop it). Nothing is reserved until they confirm."""
        if odb is None:
            return "The buy-order system is off right now."
        if not _whisper_only():
            own = prof["identity"]["display_name"] or "me"
            return f"Whisper me (choose Whisper, pick {own}) to place a buy order."
        name = _order_name(sender_guid)
        if not name:
            return "I can't read your name yet — say something in public chat first."
        m = _BUY_RE.match(arg.strip())
        if not m:
            return "Say: buy QTY ITEM @ PRICE — e.g. buy 2 Cupids Halo @ 1200."
        qty = int(m.group(1)) if m.group(1) else 1
        item = m.group(2).strip(" ,.'\"")
        price = int(m.group(3))
        if not item:
            return "Which item? e.g. buy 2 Cupids Halo @ 1200."
        if qty <= 0 or price <= 0:
            return "Quantity and price must both be above zero."
        pending_buys[cc_orders.normalize_name(name)] = {
            "item": item, "qty": qty, "price": price}
        low = _lowest_listing(item)
        if low:
            mn, realm, count = low
            where = f" at {realm}" if realm else ""
            quote = f"Lowest now {mn}c{where}, {count} listed."
            if mn > price:
                quote += f" Over your {price}c cap, may wait."
        else:
            quote = "No recent price scanned."
        return (f"Buy {qty}x {item} at up to {price}c, total {qty * price}c? "
                f"{quote} Reply yes or no.")

    def cmd_confirm(sender_guid, arg):
        """'yes' — place the buy order the sender just set up with 'buy'."""
        if odb is None or not _whisper_only():
            return None
        name = _order_name(sender_guid)
        if not name:
            return None
        key = cc_orders.normalize_name(name)
        pend = pending_buys.get(key)
        if not pend:
            return ("Nothing to confirm. Send a buy order first: "
                    "buy QTY ITEM @ PRICE.")
        need = pend["qty"] * pend["price"]
        avail = odb.available(name)
        if avail < need:
            return (f"That order needs {need}c but you have {avail}c available. "
                    f"Trade me the cubits at the register first, then say 'yes' "
                    f"again.")
        try:
            oid = odb.place_order(name, pend["item"], pend["qty"], pend["price"],
                                  guid=sender_guid)
        except cc_orders.OrderError as e:
            return str(e)
        pending_buys.pop(key, None)
        return (f"Order #{oid} placed: buy {pend['qty']} x {pend['item']} at up to "
                f"{pend['price']}c each. I'll buy when I find it at or below that.")

    def cmd_decline(sender_guid, arg):
        """'no' — drop the buy order the sender was about to confirm."""
        if not _whisper_only():
            return None
        name = _order_name(sender_guid)
        if not name:
            return None
        if pending_buys.pop(cc_orders.normalize_name(name), None):
            return "Okay, I won't place that order."
        return None

    def cmd_withdraw(sender_guid, arg):
        """'withdraw' (all available) or 'withdraw N' — take cubits back at the
        register. Sets a pending withdrawal; the player then opens a trade with me
        and I stake exactly that amount. I only confirm if the server echoes the
        same figure and it's within your available balance, so nothing over-pays."""
        if odb is None:
            return "The buy-order system is off right now."
        if not _whisper_only():
            own = prof["identity"]["display_name"] or "me"
            return f"Whisper me (choose Whisper, pick {own}) to withdraw."
        name = _order_name(sender_guid)
        if not name:
            return "I can't read your name yet — say something in public chat first."
        avail = odb.available(name)
        if avail <= 0:
            return "You have no available cubits to withdraw."
        m = re.search(r"\d[\d,]*", arg)
        amt = int(m.group(0).replace(",", "")) if m else avail
        if amt <= 0:
            return "How much? e.g. withdraw 500 (or just 'withdraw' for all)."
        if amt > avail:
            return (f"You have {avail}c available to withdraw (the rest is reserved "
                    f"on open orders). Try 'withdraw {avail}'.")
        pending_withdrawals[cc_orders.normalize_name(name)] = amt
        return (f"To withdraw {amt}c, trade me. I'll stake it, you accept + confirm. "
                f"Say 'cancel withdraw' to stop.")

    def cmd_cancel_withdraw(sender_guid, arg):
        """'cancel withdraw' — drop a pending withdrawal before trading."""
        if not _whisper_only():
            return None
        name = _order_name(sender_guid)
        if not name:
            return None
        if pending_withdrawals.pop(cc_orders.normalize_name(name), None) is not None:
            return "Withdrawal cancelled."
        return None

    def cmd_orders(sender_guid, arg):
        """List the sender's own orders (open first)."""
        if odb is None:
            return "The buy-order system is off right now."
        if not _whisper_only():
            own = prof["identity"]["display_name"] or "me"
            return f"Whisper me (choose Whisper, pick {own}) to see your orders."
        name = _order_name(sender_guid)
        if not name:
            return "I can't read your name yet — say something in public chat first."
        rows = odb.orders_for(name)
        if not rows:
            return "You have no orders with me yet."
        rows.sort(key=lambda o: (o["status"] != cc_orders.S_OPEN, o["id"]))
        bits = []
        for o in rows[:6]:
            bits.append(f"#{o['id']} {o['qty_bought']}/{o['qty_requested']} "
                        f"{o['item_query']} @<={o['max_unit_price']} [{o['status']}]")
        more = f" (+{len(rows) - 6} more)" if len(rows) > 6 else ""
        return " | ".join(bits) + more

    def cmd_cancel(sender_guid, arg):
        """Cancel one of the sender's own OPEN orders: 'cancel N'."""
        if odb is None:
            return "The buy-order system is off right now."
        if not _whisper_only():
            own = prof["identity"]["display_name"] or "me"
            return f"Whisper me (choose Whisper, pick {own}) to cancel an order."
        name = _order_name(sender_guid)
        if not name:
            return "I can't read your name yet — say something in public chat first."
        m = re.search(r"\d+", arg)
        if not m:
            return "Which order? e.g. cancel 3 (see 'orders' for the numbers)."
        oid = int(m.group(0))
        o = odb.get_order(oid)
        # Verify ownership by NAME before touching it — never cancel someone
        # else's order, and never confirm an order exists that isn't theirs.
        if not o or o["account"] != cc_orders.normalize_name(name):
            return f"You have no order #{oid}."
        try:
            odb.cancel_order(oid, reason="cancelled by player")
        except cc_orders.OrderError as e:
            return str(e)
        return f"Order #{oid} cancelled. Any cubits it reserved are freed up."

    def _resolve_player_guid(name):
        """Best-effort GUID for a player NAME (seen in-realm or a friend). Used to
        pick the whisper-translation recipient. None if not known yet."""
        if not name:
            return None
        want = _alnum(name)
        g = friends.get(name)
        if not g:
            g = next((gg for gg, nm in players.items()
                      if _alnum(nm) == want), None)
        if not g:
            g = next((gg for nm, gg in friends.items()
                      if _alnum(nm) == want), None)
        return g

    def _translate_status_line():
        tb = translatebot
        state_s = "ON" if tb["on"] else "OFF"
        if tb["mode"] == "whisper":
            who = tb["whisper_to"] or "(nobody selected)"
            mode_s = f"whisper to {who}"
        else:
            mode_s = "public chat"
        prov = tb.get("engine_provider") or tb["provider"]
        ready = "ready" if tb.get("engine") is not None else "NOT ready"
        return (f"Translator {state_s} | mode: {mode_s} | provider: {prov} "
                f"({ready})")

    TRANSLATE_HELP = (
        "translator: on | off | public | whisper | to NAME | provider NAME | "
        "status | help")

    def translate_control(sub, arg):
        """Shared control logic for BOTH the console 'translate ...' command and
        the in-game 'translate ...' chat command (approved users only). Returns a
        short human reply string. Persists every change."""
        sub = (sub or "").strip().lower()
        arg = (arg or "").strip()
        if cc_translate is None:
            return ("Translator module isn't installed on this bot "
                    "(cc_translate.py missing).")
        if sub in ("", "status"):
            return _translate_status_line()
        if sub in ("help", "commands", "?"):
            return TRANSLATE_HELP
        if sub == "on":
            translatebot["on"] = True
            if translatebot.get("engine") is None:
                err = _build_translator()
                if err:
                    translatebot["on"] = False
                    save_translate_cfg()
                    return (f"Can't turn on — provider "
                            f"'{translatebot['provider']}' failed: {err}")
            save_translate_cfg()
            return "Live translation ON. " + _translate_status_line()
        if sub == "off":
            translatebot["on"] = False
            save_translate_cfg()
            return "Live translation OFF."
        if sub in ("public", "public mode"):
            translatebot["mode"] = "public"
            save_translate_cfg()
            return "Mode: PUBLIC — translations go to public chat."
        if sub in ("whisper", "whisper mode", "private"):
            translatebot["mode"] = "whisper"
            save_translate_cfg()
            who = translatebot["whisper_to"] or "(nobody yet — 'translate to NAME')"
            return f"Mode: WHISPER — translations whispered to {who}."
        if sub == "to":
            if not arg:
                translatebot["whisper_to"] = ""
                save_translate_cfg()
                return "Cleared the whisper-translation recipient."
            translatebot["whisper_to"] = arg
            save_translate_cfg()
            known = "" if _resolve_player_guid(arg) else \
                " (not seen in-realm yet — I'll whisper once I can pick them)"
            return f"Whisper translations will go to {arg}.{known}"
        if sub == "provider":
            if not arg:
                return ("Providers: "
                        + ", ".join(cc_translate.available_providers())
                        + f". Current: {translatebot['provider']}.")
            new = arg.strip().lower()
            if new not in cc_translate.available_providers():
                return ("Unknown provider. Choose: "
                        + ", ".join(cc_translate.available_providers()))
            old = translatebot["provider"]
            translatebot["provider"] = new
            err = _build_translator()
            if err:
                translatebot["provider"] = old
                _build_translator()
                return f"Provider '{new}' failed to init: {err}"
            save_translate_cfg()
            return (f"Translation provider set to '{new}'. "
                    "Keys/URLs come from the environment — see the docs.")
        return "Usage — " + TRANSLATE_HELP

    def cmd_translate(sender_guid, arg):
        """In-game control of the live translator. Approved-user only (admin=True
        in the registry). 'translate' alone shows status."""
        parts = (arg or "").strip().split(None, 1)
        sub = parts[0] if parts else ""
        rest = parts[1] if len(parts) > 1 else ""
        return translate_control(sub, rest)

    # The registry. Longer/more-specific triggers must precede the shorter ones
    # they contain ('realm info' before 'realm'). Set admin=True to gate a
    # command to the approved-user allowlist. 'usage' is the how-to-use string
    # the help command shows; use "" to hide a command from help.
    CHAT_COMMANDS = [
        {"names": ["translator", "translate"], "admin": True,
         "usage": "translate on|off|public|whisper|to NAME|status", "fn": cmd_translate},
        {"names": ["help", "commands"], "admin": False,
         "usage": "help", "fn": cmd_help},
        {"names": ["realm info", "realminfo", "realm"], "admin": False,
         "usage": "realm [name]", "fn": cmd_realm},
        {"names": ["buy", "order"], "admin": False,
         "usage": "buy QTY ITEM @ PRICE", "fn": cmd_buy},
        {"names": ["yes", "confirm"], "admin": False,
         "usage": "", "fn": cmd_confirm},        # contextual: after a 'buy'
        {"names": ["no", "decline"], "admin": False,
         "usage": "", "fn": cmd_decline},        # contextual: after a 'buy'
        {"names": ["balance", "bal"], "admin": False,
         "usage": "balance", "fn": cmd_balance},
        {"names": ["withdraw", "cash out", "cashout"], "admin": False,
         "usage": "withdraw [amount]", "fn": cmd_withdraw},
        {"names": ["cancel withdraw", "cancel withdrawal"], "admin": False,
         "usage": "", "fn": cmd_cancel_withdraw},
        {"names": ["my orders", "orders"], "admin": False,
         "usage": "orders", "fn": cmd_orders},
        {"names": ["cancel order", "cancel"], "admin": False,
         "usage": "cancel N", "fn": cmd_cancel},
    ]

    # Mention log: whenever a chat line names the bot, record WHO said it and
    # WHAT they said — to the console (so it lands in the systemd journal) and
    # appended to a file for later review. Only mentions are logged; unrelated
    # realm chatter is never captured. On by default, so the launch command
    # needs no new flags; set --mentions-file "" to skip the file (the console
    # line still prints).
    mentions_path = os.path.join(_APP_DIR,
                                 args.mentions_file) if args.mentions_file else ""

    def log_mention(sender_guid, text):
        own = (prof["identity"]["display_name"] or "").strip()
        if not own or own.lower() not in (text or "").lower():
            return
        who = players.get(sender_guid) or (sender_guid[:8] + "…")
        realm = state.get("realm") or "?"
        show_line(f"  [mention] {who}: {text}")
        if not mentions_path:
            return
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(mentions_path, "a", encoding="utf-8") as fh:
                fh.write(f"{stamp} | {realm} | {who}: {text}\n")
        except OSError as e:
            show_line(f"  (couldn't write {args.mentions_file}: {e})")

    # Whisper log: every private message the bot receives AND every private reply
    # it sends, so the whole conversation is on record. On by default; set
    # --whispers-file "" to skip the file (the console line still prints).
    whispers_path = os.path.join(_APP_DIR,
                                 args.whispers_file) if args.whispers_file else ""

    def log_whisper(direction, other_guid, text):
        """direction is 'in' (received) or 'out' (replied). Records who + message +
        timestamp to whispers.log (and always prints a console line)."""
        who = players.get(other_guid) or _whisper_name(other_guid) \
            or (other_guid[:8] + "…")
        arrow = "<-" if direction == "in" else "->"
        show_line(f"  [whisper] {arrow} {who}: {text}")
        if not whispers_path:
            return
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(whispers_path, "a", encoding="utf-8") as fh:
                fh.write(f"{stamp} | {direction} | {who}: {text}\n")
        except OSError as e:
            show_line(f"  (couldn't write {args.whispers_file}: {e})")

    def handle_whisper(sender_guid, message):
        """Answer a whisper as if it were an addressed public command, but route
        the reply back privately. A whisper is already a direct message to the bot,
        so the user need not name it — we synthesise that addressing (the existing
        handlers all require the bot's name) by appending the bot name, then set
        reply_ctx so every synchronous chat_say/_reply the handlers make goes back
        as a whisper to this sender."""
        log_whisper("in", sender_guid, message)
        own = (prof["identity"]["display_name"] or "").strip()
        addressed = message
        if own and own.lower() not in message.lower():
            addressed = f"{message} {own}".strip()
        reply_ctx["whisper_to"] = sender_guid
        try:
            handle_chat_command(sender_guid, addressed)
            handle_price_query(sender_guid, addressed)
            handle_summon(sender_guid, addressed)
            handle_scan_query(sender_guid, addressed)
        finally:
            reply_ctx["whisper_to"] = None

    def handle_public_help(sender_guid, text):
        """The ONE thing answered from PUBLIC chat when the bot is in whisper-only
        mode: 'botname help'. It replies IN PUBLIC with the command list and a note
        that the commands must be whispered. Only 'help'/'commands' triggers it;
        every other public line is ignored (they must whisper). Same light anti-spam
        as the keyword commands. NB: the reply must stay free of any slash-command
        substring — a public message containing e.g. '/whisper' is eaten by the
        server's command parser and never renders."""
        if not cmdbot["on"]:
            return
        own_guid = conn.get("own")
        if own_guid and sender_guid == own_guid:
            return
        own = (prof["identity"]["display_name"] or "").strip()
        if not own or own.lower() not in text.lower():
            return                                # must address the bot by name
        import re
        body = re.sub(re.escape(own.lower()), " ", text.lower())
        body = re.sub(r"\s+", " ", body).strip(" ,.!?:@'\"")
        if body not in ("help", "commands"):      # ONLY help works in public
            return
        # INDEPENDENT cooldown (pubhelp_gate), NOT the shared cmdbot gate: a whisper
        # 'help' from the same person runs through handle_chat_command and sets
        # cmdbot's per-user timer, which would otherwise suppress a near-simultaneous
        # public 'botname help' from that same person (exactly what happened live —
        # the whisper answered and the public line stayed silent). Keeping a separate
        # timer here lets public help always answer on its own.
        now = time.time()
        if now - pubhelp_gate["last"] < pubhelp_gate["cooldown"]:
            return
        seen = pubhelp_gate["seen"]
        if now - seen.get(sender_guid, 0.0) < pubhelp_gate["per_user"]:
            return
        pubhelp_gate["last"] = now
        seen[sender_guid] = now
        # The real command list, IN PUBLIC. Everything but 'help' still runs over
        # whisper in whisper-only mode, so the line names the commands and points
        # people at the Whisper action. Keep it free of any '/command' substring
        # (the server's parser eats those) and of <> brackets (chat markup).
        msg = (f"Commands: price of ITEM, pc ITEM, realm, help. "
               f"Whisper me (choose Whisper, pick {own}) to use them.")
        who = players.get(sender_guid, sender_guid[:8] + "…")
        show_line(f"  [public-help] {who} -> {msg}")
        # Queue for pub_worker: a send_public_chat() done inline here (on the
        # reader thread) is silently dropped by the server. The worker sends it
        # from its own thread, like the console 'say'.
        pub_say(msg)

    def handle_translate(sender_guid, text):
        """Live translator (Stage 27). Detect a non-English public chat line,
        translate it to English and re-post it as
            [Player] said in <Language>: <English>
        in public chat OR whispered to the selected player. Runs on public chat
        INDEPENDENTLY of whisper mode (like the quiz bot), guarded by
        translatebot['on']. Every failure mode is contained here: it never posts
        a broken public line, never translates the bot's own messages, guards
        against loops/duplicates, and rate-limits itself."""
        tb = translatebot
        if not tb["on"] or cc_translate is None:
            return
        engine = tb.get("engine")
        throttle = tb.get("throttle")
        if engine is None or throttle is None:
            return
        who = players.get(sender_guid) or (sender_guid[:8] + "…")
        # The whole decision (own-message + loop + dedup + rate-limit + English
        # gate + translate) lives in cc_translate.plan_translation so it is
        # unit-tested; here we only do the game I/O it can't.
        plan = cc_translate.plan_translation(
            sender_guid, text, engine, throttle, own_guid=conn.get("own"))
        action = plan["action"]
        if action == cc_translate.SKIP:
            return
        if action == cc_translate.ERROR:
            # FAILURE PATH: log it, never post a broken public line, and
            # optionally whisper a short error to the selected user.
            show_line(f"  [translate] failed for {who}: {plan['detail']}")
            tgt_name = tb["whisper_to"]
            if tgt_name:
                g = _resolve_player_guid(tgt_name)
                if g:
                    whisper_say(g, f"(couldn't translate {who}'s message)")
            return
        res = plan["result"]
        out = cc_translate.format_translation(who, res)
        show_line(f"  [translate] {who} ({res.lang_code}): "
                  f"{res.source_text} -> {res.text}")
        # Record our own output so an echo of it is treated as a duplicate.
        throttle.note_output(out)
        if tb["mode"] == "whisper":
            tgt_name = tb["whisper_to"]
            if not tgt_name:
                show_line("  [translate] whisper mode but no recipient set "
                          "('translate to NAME') — not sending.")
                return
            g = _resolve_player_guid(tgt_name)
            if not g:
                show_line(f"  [translate] can't whisper {tgt_name} yet "
                          "(not seen in-realm / not a friend).")
                return
            whisper_say(g, out)
        else:
            pub_say(out)

    def handle_chat_command(sender_guid, text):
        """Answer the keyword chat commands. A message must address the bot by
        name ('botname help', 'botname realm info'); a bare 'botname' gets a
        greeting. Admin commands are refused unless the sender is approved. Light
        anti-spam (global + per-player cooldown) keeps it from flooding chat.
        Runs alongside the price/summon/scan handlers; their triggers don't
        overlap these keywords, so nothing answers twice."""
        if not cmdbot["on"]:
            return
        own_guid = conn.get("own")
        if own_guid and sender_guid == own_guid:
            return
        import re
        own = (prof["identity"]["display_name"] or "").strip()
        if not own:
            return
        low = text.lower()
        if own.lower() not in low:            # only when addressed by name
            return
        # strip the bot's name (wherever it sits) — the rest is the command text
        body = re.sub(re.escape(own.lower()), " ", low)
        body = re.sub(r"\s+", " ", body).strip(" ,.!?:@'\"")
        entry = fn = arg = None
        if not body:                          # bare name -> greeting
            fn, arg = cmd_hi, ""
        else:
            for c in CHAT_COMMANDS:
                for nm in c["names"]:
                    if body == nm or body.startswith(nm + " "):
                        entry, fn, arg = c, c["fn"], body[len(nm):].strip()
                        break
                if fn:
                    break
        if not fn:
            return
        now = time.time()
        if now - cmdbot["last"] < cmdbot["cooldown"]:
            return
        seen = cmdbot["seen"]
        if now - seen.get(sender_guid, 0.0) < cmdbot["per_user"]:
            return
        if entry and entry.get("admin") and not is_approved(sender_guid):
            cmdbot["last"] = now
            seen[sender_guid] = now
            _reply("Sorry, that command is for approved users only.")
            return
        reply = fn(sender_guid, arg)
        if not reply:
            return
        cmdbot["last"] = now
        seen[sender_guid] = now
        if len(seen) > 512:                   # keep the seen-map bounded
            cut = now - cmdbot["per_user"] * 8
            for g in [g for g, t in seen.items() if t < cut]:
                del seen[g]
        who = players.get(sender_guid, sender_guid[:8] + "…")
        show_line(f"  [cmd] {who} -> {reply}")
        _reply(reply)

    def crawl_prepare(targets, source, auto_start=False, resolve_each=False):
        """Stage a crawl: store the target list and show the review + the
        ban/rate-limit risk. Ordinary crawls wait for 'crawl go'; a rescan can
        explicitly request an immediate start after its name resolution.

        `resolve_each` arms just-in-time name resolution in crawl_run: each
        realm's name is resolved to its CURRENT GUID right before it's joined,
        instead of the whole list up front. Set here (the single staging funnel)
        so it defaults off and never leaks from one crawl into the next."""
        crawl["resolve_each"] = resolve_each
        crawl["pending_targets"] = targets
        print(f"  crawl ready: {len(targets)} realm(s) from {source}:")
        for g, nm in targets[:8]:
            print(f"    {nm[:36]:<36} {g[:8]}…")
        if len(targets) > 8:
            print(f"    … and {len(targets) - 8} more")
        mins = len(targets) * args.crawl_delay / 60
        print(f"  Each is a FULL reconnect+relogin, paced {args.crawl_delay:.0f}s "
              f"apart (>= ~{mins:.0f} min + scan time).")
        print("  ⚠ BAN / RATE-LIMIT RISK: rapid reconnects are exactly what "
              "the live server throttles and flags for abuse. You own the account "
              "and accept the exposure.")
        if auto_start:
            print("  Rescan resolution complete — starting the crawl automatically. "
                  "Type 'crawl stop' to stop it.")
        else:
            print("  Type 'crawl go' to start, 'crawl stop' to cancel.")

    def start_staged_crawl(n=None):
        """Start all or the first `n` staged targets. Shared by the interactive
        'crawl go' command and rescan's automatic post-resolution start."""
        targets = crawl.get("pending_targets")
        if crawl["active"]:
            print("  a crawl is already running — 'crawl stop' first")
            return False
        if crawl.get("resolving"):
            print("  still resolving realm names — wait for the "
                  "'crawl ready: N realm(s)' line")
            return False
        if not targets:
            print("  nothing queued — run 'crawl <term>' or 'crawlfile <path>' "
                  "first")
            return False
        if n is not None and n <= 0:
            print("  crawl batch size must be greater than zero")
            return False

        if n is not None and n < len(targets):
            batch, leftover = targets[:n], targets[n:]
        else:
            batch, leftover = targets, None
        crawl["pending_targets"] = leftover
        print(f"  crawl: starting on {len(batch)} realm(s)"
              + (f" — {len(leftover)} still staged ('crawl go' for more)"
                 if leftover else "") + " ...")
        # Flip active synchronously (crawl_run sets it again first thing) so a
        # caller that waits on crawl["active"] right after this returns never
        # races the new thread's scheduling and mistakes 'not yet started' for
        # 'already finished' — the batched rescan driver depends on this.
        crawl["active"] = True
        threading.Thread(
            target=crawl_run,
            args=(batch, args.crawl_delay, args.crawl_file),
            daemon=True).start()
        return True

    def run_batched_rescan(batch):
        """Drive a staged rescan in batches: crawl `batch` realm(s), then let the
        auto-Hollowarp queue drain (join/scan whatever hollered while the batch
        ran), then the next batch, until the staged list is exhausted. One pass —
        no auto-repeat. Runs in its own thread; the caller stages the targets and
        only reaches here when batching is on and there's more than one batch.

        'crawl stop' clears crawl['pending_targets'] (and sets crawl['stop']), so
        the current batch's crawl_run breaks and this loop finds nothing left to
        stage — one stop ends the whole rescan, not just the batch it lands in."""
        passno = 0
        while crawl.get("pending_targets") and not (stop.is_set()
                                                    or crawl["stop"]):
            passno += 1
            remaining = len(crawl["pending_targets"])
            show_line(f"  rescan batch {passno}: crawling "
                      f"{min(batch, remaining)} of {remaining} staged "
                      f"realm(s) ...")
            if not start_staged_crawl(batch):
                break
            # Wait out this batch's crawl AND the Hollowarp queue that piled up
            # while it ran. warp_driver auto-starts on each queued holla but holds
            # while crawl['active'], then drains once the batch is idle; both share
            # crawl['active'], so we simply wait until nothing is running and the
            # queue is empty before staging the next batch.
            announced = False
            while not (stop.is_set() or crawl["stop"]):
                draining = hollow["driver"] or (hollow["auto"] and hollow["q"])
                if crawl["active"] or draining:
                    if draining and not crawl["active"] and not announced:
                        announced = True
                        show_line(f"  rescan: draining {len(hollow['q'])} queued "
                                  f"Hollowarp realm(s) before the next batch ...")
                    # A non-empty queue normally already has a live warp_driver
                    # (started when the holla was appended); kick one if not, so
                    # the wait can never hang on an undrained queue.
                    if hollow["auto"] and hollow["q"] and not hollow["driver"] \
                            and not crawl["active"]:
                        threading.Thread(target=warp_driver, daemon=True).start()
                    time.sleep(0.5)
                    continue
                break
        if stop.is_set() or crawl["stop"]:
            show_line("  rescan: stopped.")
        else:
            show_line(f"  rescan: all {passno} batch(es) complete.")

    # Built-in seed terms for auto-discovery: shop-ish words first (realms that
    # actually have vending machines), then vowels/common letters for breadth.
    # Each search returns up to ~80 realms; the union across seeds is the pool.
    DISCOVERY_SEEDS = ["shop", "market", "store", "mall", "sell", "vend",
                       "prices", "cheap", "collection", "rentals", "spawn",
                       "hangout", "world", "free", "a", "e", "i", "o", "u",
                       "s", "r", "n", "t", "m", "c", "b", "p"]

    def discover_and_stage(cap, seeds):
        """Find realms with NO input from the user: run each seed term through the
        realm browser, union the results into a pool, shuffle it, and stage a
        random `cap` of them for review. Discovery is cheap — plain search
        queries on the live connection, NO reconnects — so only the crawl itself
        (staged behind 'crawl go') carries the reconnect/ban risk."""
        show_line(f"  discovering realms on its own via {len(seeds)} searches "
                  f"(no GUIDs/links needed) ...")
        pool = {}
        for term in seeds:
            if stop.is_set() or crawl["active"]:
                return
            if search_realm(term, then_join=False) and \
                    realm_search["event"].wait(4.0):
                for nm, g in realm_search["results"]:
                    pool.setdefault(g, nm)
            if len(pool) >= cap * 5:        # plenty to pick from — stop early
                break
            time.sleep(args.crawl_discover_gap)
        if not pool:
            show_line("  discovery found nothing — the browser returned no "
                      "realms (try 'crawl <term>' with a word instead)")
            return
        items = list(pool.items())          # [(guid, name), ...]
        random.shuffle(items)
        targets = items[:cap]
        crawl_prepare(targets, f"auto-discovery — {len(pool)} realms found, "
                               f"{len(targets)} picked at random")

    # Words too generic to search on: the realm browser matches PER WORD and
    # caps the reply, so searching "shop" floods the page and the realm you want
    # may not be in it. Pick a distinctive word instead.
    GENERIC_WORDS = {"shop", "shops", "market", "markets", "mall", "malls",
                     "store", "stores", "vend", "vends", "rental", "rentals",
                     "collection", "resources", "resource", "realm", "realms",
                     "farmers", "buying", "list", "the", "and", "of", "my"}

    def search_token(name):
        """A single distinctive word from a realm name, used as a fallback query
        when a full-name search comes back empty. Prefer the longest non-generic
        word; fall back to the longest word."""
        toks = "".join(c if c.isalnum() else " " for c in name).split()
        if not toks:
            return name.strip()
        non_generic = [t for t in toks if t.lower() not in GENERIC_WORDS]
        return max(non_generic or toks, key=len)

    def find_realm_by_name(name, index=None):
        """Resolve one realm NAME via the realm browser. Returns (match, reason)
        where match is (matched_name, guid) or None, and reason is:
          'cached'  — resolved from `index` with NO network search (free + fast)
          'found'   — matched a realm via a live search
          'empty'   — the browser answered but the realm wasn't in the results
                      (offline, or the line differs from the in-game name)
          'noreply' — the browser didn't answer at all (usually rate-limiting)
        Searches the FULL name first (exactly like the working `crawl <name>`),
        falling back to one distinctive word. Matched with _alnum so case / fancy
        quotes / spacing don't matter.

        `index` (optional) is an alnum-name -> (name, guid) dict shared across a
        batch: every search returns up to ~80 realms, so we fold ALL of them into
        `index`. A later name already sitting in `index` resolves for free — no
        search, no pacing gap — which is the main speed-up for big name lists."""
        want = _alnum(name)
        if index is not None and want in index:
            return index[want], "cached"
        queries = [name]
        tok = search_token(name)
        if tok and _alnum(tok) != want:      # don't search the same thing twice
            queries.append(tok)
        answered = False
        for q in queries:
            if stop.is_set() or crawl["active"]:
                return None, "noreply"
            results = do_search(q)                       # None = no reply at all
            if results is None:
                continue                                 # try the next query
            answered = True
            # Fold the whole result page into the shared index so other names in
            # the batch can resolve without their own search.
            if index is not None:
                for nm, g in results:
                    index[_alnum(nm)] = (nm, g)
            # exact full-name match first; else the single result that contains
            # the wanted name (handles a name shown with extra decoration).
            match = next(((nm, g) for nm, g in results
                          if _alnum(nm) == want), None)
            if not match:
                contains = [(nm, g) for nm, g in results
                            if want and want in _alnum(nm)]
                if len(contains) == 1:
                    match = contains[0]
            if match:
                return match, "found"
        return (None, "empty") if answered else (None, "noreply")

    def resolve_file_crawl(direct, names, path, cap=None, prune=False,
                           auto_start=False, batch=0, resolve_each=False):
        """Stage a crawl from a crawlfile that lists realm NAMES. Each name is
        looked up in the realm browser to get its CURRENT GUID — we resolve by
        name (not store a GUID) because a realm gets a fresh GUID every time it's
        hosted, so a name list keeps working across re-hosts. `direct` is any
        link/GUID lines already resolved. `cap` limits how many realms are staged
        (None = the --crawl-max default, 0 = no limit / the whole list).
        `auto_start` immediately runs the staged crawl after resolution; rescan
        uses it so it no longer needs a separate interactive 'crawl go'.

        The realm browser rate-limits rapid searches (a single search is fine,
        but firing dozens back-to-back gets throttled), so we PACE the lookups
        and, on a no-reply, back off and retry that one name once before giving
        up. The gap grows if throttling persists and resets once it recovers."""
        seen, targets, missing, hit_names = set(), [], [], []
        for g, nm in direct:
            if g not in seen:
                seen.add(g)
                targets.append((g, nm))
        crawl["resolving"] = True
        total = len(names)
        base_gap = max(1.2, args.crawl_discover_gap)     # calm baseline pace
        backoff = base_gap
        index = {}                # alnum name -> (name, guid), shared across the
                                  # batch so overlapping names resolve for free
        cached = 0
        try:
            for i, name in enumerate(names, 1):
                if stop.is_set() or crawl["active"]:
                    return
                match, reason = find_realm_by_name(name, index)
                if reason == "noreply":
                    # throttled — wait, then give this one name a second chance
                    show_line(f"  [{i}/{total}] … '{name}' no reply, cooling "
                              f"down {backoff:.0f}s ...")
                    time.sleep(backoff)
                    match, reason = find_realm_by_name(name, index)
                if match:
                    nm, g = match
                    hit_names.append(name)
                    if g not in seen:
                        seen.add(g)
                        targets.append((g, nm))
                    tag = " (cached)" if reason == "cached" else ""
                    show_line(f"  [{i}/{total}] ✓ '{name}' -> {nm} "
                              f"({g[:8]}…){tag}")
                    backoff = base_gap                   # recovered
                else:
                    missing.append(name)
                    if reason == "noreply":
                        show_line(f"  [{i}/{total}] ✗ '{name}' — still no reply "
                                  f"(rate-limited)")
                        backoff = min(backoff * 2, 20)   # escalate
                    else:
                        show_line(f"  [{i}/{total}] ✗ '{name}' — not in results "
                                  f"(offline, or name differs in-game)")
                # A cache hit did NO network search, so it needs no pacing gap —
                # this is where the batch actually gets faster.
                if reason == "cached":
                    cached += 1
                else:
                    time.sleep(base_gap)
        finally:
            crawl["resolving"] = False
        if cached:
            show_line(f"  {cached}/{total} resolved from cache (no search, "
                      f"no wait)")
        if missing:
            show_line("  not resolved: " + ", ".join(missing))
        # Auto-prune ghosts (rescan only): a watchlisted realm that resolves is
        # reset to 0 misses; one that fails to resolve gets a strike. After
        # --rescan-drop-after consecutive strikes it's dropped, so a rescan stops
        # paying resolve/arrival timeouts on realms that are gone or renamed for
        # good. Keyed by name -> its watchlist GUID; a realm that comes back
        # before hitting the limit loses all its strikes.
        if prune and args.rescan_drop_after > 0:
            by_name = {(v.get("name") or "").lower(): k
                       for k, v in watchlist.items()}
            hit = {n.lower() for n in hit_names}
            missed = {n.lower() for n in missing}
            dropped, changed = [], False
            for nm_low in hit:
                g = by_name.get(nm_low)
                if g and watchlist.get(g, {}).get("misses"):
                    watchlist[g]["misses"] = 0
                    changed = True
            for nm_low in missed:
                g = by_name.get(nm_low)
                if not g or g not in watchlist:
                    continue
                m = watchlist[g].get("misses", 0) + 1
                if m >= args.rescan_drop_after:
                    dropped.append(watchlist[g].get("name") or g[:8])
                    del watchlist[g]
                else:
                    watchlist[g]["misses"] = m
                changed = True
            if changed:
                save_watchlist()
            if dropped:
                show_line(f"  auto-pruned {len(dropped)} dead realm(s) after "
                          f"{args.rescan_drop_after} misses: "
                          + ", ".join(dropped))
        lim = args.crawl_max if cap is None else cap
        if lim:
            targets = targets[:lim]
        if not targets:
            show_line(f"  nothing to crawl from {path}")
        else:
            crawl_prepare(targets, path, auto_start=auto_start,
                          resolve_each=resolve_each)
            if auto_start:
                if batch and len(targets) > batch:
                    show_line(f"  rescan: {len(targets)} realm(s) — running in "
                              f"batches of {batch}, draining the Hollowarp queue "
                              f"between each. 'crawl stop' ends the whole rescan.")
                    threading.Thread(target=run_batched_rescan,
                                     args=(batch,), daemon=True).start()
                else:
                    start_staged_crawl()

    def log_spawn(p, why):
        """Append every server-given spawn to a JSONL log, tagged with the realm
        it happened in — enter the same realm twice and the file shows whether
        the placement is a fixed portal or wherever you last stood."""
        if not args.spawn_log:
            return
        rec = {"time": time.strftime("%Y-%m-%d %H:%M:%S"),
               "realm": state["realm"], "owner": state["realm_owner"],
               "spawn": list(p), "why": why,
               "account": prof["identity"]["display_name"]}
        try:
            with open(args.spawn_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
        except OSError as e:
            show_line(f"  (couldn't write {args.spawn_log}: {e})")

    def do_teleport(guid, msg=None, follow=True):
        """Send a realm-handoff request, follow the handoff, reconnect and
        re-login into the target realm. Runs inside the reader thread so it owns
        the socket recv.

        `follow=True` (teleport, tx 0x0089): after landing, walk onto the target
        player. `follow=False` (realm join, tx 0x00d3 via `msg`): just adopt the
        realm's portal placement — there's no player to chase. `msg` overrides
        the default teleport builder so the join reuses this whole path."""
        with build_action_lock:
            builder = build_runtime.get("controller")
            if builder and builder.active:
                show_line("  realm handoff refused: a verified build is active")
                return
            switching.set()
        show_line("  teleporting ..." if follow else "  joining realm ...")
        # Grab the target's last-known heading NOW, before the realm hop clears
        # player_heading, so we can face their way once we land on them.
        if follow:
            gh = guid.lower() if isinstance(guid, str) else guid.hex()
            state["follow_heading"] = player_heading.get(gh)
        old = conn["ws"]

        # The official client never sends a player teleport cold. Every
        # captured 0x0089 is preceded by a 0x0027 friends refresh and a 0x0088
        # online-friends refresh; the client waits for both replies and then
        # sends the target GUID. Besides matching the official counter/order,
        # this primes the server's live friend-presence state for the transfer.
        if follow:
            preflight = (P.build_refresh_friends(),
                         P.build_refresh_online_friends())
            with lock:
                for prebody in preflight:
                    flog("TX", prebody, note="  [teleport preflight]")
                    old.send_binary(encode_outbound(
                        prebody, conn["key"], conn["outer_key"]))

            target_hex = guid.lower() if isinstance(guid, str) else guid.hex()
            saw_friends = saw_online = target_online = False
            old.settimeout(0.25)
            preflight_deadline = time.time() + 2.0
            while time.time() < preflight_deadline and not (
                    saw_friends and saw_online):
                try:
                    prewire = recv_bin(old)
                except websocket.WebSocketTimeoutException:
                    continue
                except Exception:
                    break
                try:
                    _, prebody, preterm = P.decrypt_frame(
                        prewire, conn["key"])
                except Exception:
                    continue
                if not preterm:
                    continue
                pretype = P.body_type(prebody)
                flog("RX", prebody, note="  [teleport preflight]")
                if pretype == 0x0027:
                    saw_friends = True
                    try:
                        fr, pend = P.parse_friends_full(prebody)
                        friends.clear(); friends.update(fr)
                        requests.clear(); requests.update(pend)
                    except Exception:
                        pass
                elif pretype == 0x0088:
                    saw_online = True
                    target_online = target_hex in P.parse_online_friends(prebody)

            if saw_friends and saw_online:
                show_line("  teleport preflight complete: friend list refreshed; "
                          + ("target reported online"
                             if target_online else
                             "target not present in online-friends response"))
            else:
                show_line("  teleport preflight incomplete "
                          f"(friends={'yes' if saw_friends else 'no'}, "
                          f"online={'yes' if saw_online else 'no'}); "
                          "sending the request anyway")

        with lock:
            wire = encode_outbound(msg or P.build_teleport(guid),
                                   conn["key"], conn["outer_key"])
            old.send_binary(wire)
        # A teleport to a friend in ANOTHER realm makes the server send a
        # handoff (rx 0x0019) then close this connection. We must read past any
        # backlog of world frames to find it, so give it a generous window and
        # report what we saw (diagnostic).
        old.settimeout(1.0)
        newhost = newsel = None
        n_read = 0
        closed = False
        # capture bodies of teleport-response frames (skip pure churn/heartbeat)
        CHURN = {0x005a, 0x0101, 0x0006, 0x0072, 0x0073, 0x0044, 0x000b}
        grabbed = []
        deadline = time.time() + 8
        while time.time() < deadline:
            try:
                wire = recv_bin(old)
            except websocket.WebSocketTimeoutException:
                continue
            except Exception:
                closed = True
                break
            n_read += 1
            _, body, term = P.decrypt_frame(wire, conn["key"])
            if term:
                bt = P.body_type(body)
                flog("RX", body, note="  [do_teleport read]")
                if bt == 0x0019:
                    newhost, newsel = P.parse_backend_handoff(body)
                    break
                if bt not in CHURN and len(grabbed) < 6:
                    grabbed.append((bt, body))
        if newhost is None:
            # Same-realm teleport: the server placed us at the target and told
            # us our new position in a 0x0023 frame. Adopt it and hold it, so
            # the keepalive stops dragging us back to the old spot.
            newpos = None
            for bt, body in grabbed:
                if bt == 0x0023:
                    newpos = P.parse_self_move(body)
                    if newpos:
                        break
            old.settimeout(1.0)
            switching.clear()
            # DIAGNOSTIC: on a failed transfer, dump what the server DID send back
            # in the 8s window. A server-notice text (0x000d/0x00de) or a kick
            # frame means the transfer was actively REFUSED (account throttle /
            # permission gate); an empty grab with frames still read means the
            # request was silently dropped (dead/degraded session). This is the
            # signal that tells 'wait out a throttle' apart from 'reconnect'.
            if not newpos:
                if grabbed:
                    for bt, gbody in grabbed:
                        txt = P.parse_notice(gbody) or P.parse_notice_00de(gbody)
                        if txt:
                            show_line(f"    server replied 0x{bt:04x}: {txt!r}")
                        else:
                            show_line(f"    server replied 0x{bt:04x} "
                                      f"({len(gbody)}B, no text)")
                else:
                    show_line(f"    server sent NO non-churn reply "
                              f"({n_read} frames read, all heartbeat/churn) — "
                              f"request appears silently dropped.")
            if newpos:
                place_at(newpos, "teleported to them at")
            elif not follow:
                pos["frozen"] = True
                show_line(f"  join sent but no handoff (read {n_read} frames) — "
                          f"the server didn't move us. The realm may be gone, "
                          f"private, or already the one we're in. Holding "
                          f"position; watch for a [server] notice.")
            else:
                pos["frozen"] = True
                show_line(f"  no handoff and no placement (read {n_read} frames) "
                          f"— they're offline, or the server refused the "
                          f"teleport (non-friend / private realm). Holding "
                          f"position; watch for a [server] notice.")
            return
        show_line(f"  handoff after {n_read} frames -> {newhost} /{newsel}")
        # The server closes the old realm connection after the handoff, so close
        # it before connecting the new one (matches the real client).
        try:
            old.close()
        except Exception:
            pass
        # Re-login WITH POST_LOGIN so the server pushes the realm's player
        # states (incl. the friend's 0x0005 position, which we need to walk onto
        # them). The resulting backlog is fine — the next teleport reads the
        # handoff by time, not frame count.
        try:
            nws, nkey, nown, nouter = enter_backend(
                newhost, newsel, send_post=True)
        except Exception as e:
            switching.clear()
            show_line(f"  teleport reconnect failed ({e}). Try again in a moment.")
            return
        nws.settimeout(1.0)
        with lock:
            conn["ws"], conn["key"], conn["own"] = nws, nkey, nown
            conn["outer_key"] = nouter
        realm_search["browser_open"] = False   # new connection: reopen browser
        # Adopt the destination realm's identity that login_on captured from the
        # post-login frames (the reader never sees them, so without this the
        # current realm would stay stuck on the one we teleported FROM — which is
        # what made `watch` bookmark the wrong realm). Falls back to the reader's
        # own 0x005f if the frame wasn't among the ones login_on read.
        apply_realm_id(reg.get("realm_info"))
        # New realm: forget the old realm's coordinates entirely — whatever the
        # server reports next (our placement on the friend, or failing that the
        # new realm's portal) is the truth.
        pos["frozen"] = True
        pos["placed"] = False
        pos["provisional"] = False
        pos["home"] = None
        if follow:
            state["follow_guid"] = guid
            switching.clear()
            show_line(f"  arrived in their realm — walking onto them when their "
                      f"position loads ...")
        else:
            state["follow_guid"] = None
            switching.clear()
            show_line(f"  arrived in the realm — adopting the portal spawn ...")

    def do_reconnect(reason=""):
        """Rebuild the connection after the server kicks/drops us. Runs in the
        reader thread (it owns the socket), retrying with EXPONENTIAL BACKOFF —
        rapid reconnects are exactly what the server rate-limits, so we wait
        longer after each failure (--reconnect-delay up to --reconnect-max).
        Returns True once back in world, False if disabled / stopped. Scan data
        (offers/vends/watchlist) is session-wide and kept; only the live realm
        view is reset so we re-adopt whatever realm the server drops us into."""
        if not args.auto_reconnect or reconnecting.is_set() or stop.is_set():
            return False
        reconnecting.set()
        switching.set()                 # freeze all sends while the socket is gone
        try:
            try:
                conn["ws"].close()
            except Exception:
                pass
            delay, attempt = args.reconnect_delay, 0
            while not stop.is_set():
                attempt += 1
                show_line(f"  auto-reconnect: waiting {delay:.0f}s then attempt "
                          f"{attempt} ({reason}) — 'reconnect off' to stop")
                if stop.wait(delay):    # interruptible sleep; True => stop set
                    return False
                try:
                    nws, nkw, nown, nouter = full_connect(send_post=True)
                except Exception as e:
                    show_line(f"  auto-reconnect: attempt {attempt} failed "
                              f"({type(e).__name__}: {e})")
                    ra = _retry_after_seconds(e)
                    if ra:
                        # Cloudflare 429/1015 is IP-level: a fresh login would
                        # 429 too, so wait the FULL Retry-After (+2s), overriding
                        # the normal cap. Bounded so a bogus header can't wedge us.
                        delay = min(max(ra + 2, delay), 900)
                        show_line(f"  (rate-limited — the server asked us to wait "
                                  f"{ra}s; backing off that long instead of "
                                  f"retrying. 'reconnect off' to stop)")
                    elif _is_rate_limited(e):
                        # 429/1015 without a Retry-After: still back off hard.
                        delay = min(max(delay * 2, 60), 900)
                    else:
                        delay = min(delay * 2, args.reconnect_max)   # back off
                    continue
                with lock:
                    conn["ws"], conn["key"], conn["own"] = nws, nkw, nown
                    conn["outer_key"] = nouter
                nws.settimeout(1.0)
                net["last_rx"] = time.time()      # fresh clock for the watchdog
                # re-adopt the fresh spawn and drop the old realm's object view
                pos["placed"] = False
                pos["provisional"] = True
                pos["frozen"] = False
                state["entry_logged"] = False
                world.clear()
                fossil_region["box"] = None   # a coord box is realm-specific
                realm_players.clear()
                player_pos.clear()
                player_heading.clear()
                player_block.clear()
                mannequin_seen.clear()
                show_line(f"  ✓ reconnected after {attempt} attempt(s) — back in "
                          f"world")
                return True
            return False
        finally:
            switching.clear()
            reconnecting.clear()

    def reader():
        conn["ws"].settimeout(1.0)
        while not stop.is_set():
            # Pull the next QUEUED user command, but only when the bot is free
            # and nothing is already being handed to do_teleport — so a
            # tp/guid/summon that arrived mid-scan fires now that we're idle,
            # in the order it came in.
            if (not pending["guid"] and not pending.get("join")
                    and not bot_busy()):
                with cmdq_lock:
                    item = cmdq.popleft() if cmdq else None
                if item:
                    pending["autoscan"] = item["autoscan"]
                    pending["watch_if_vends"] = item.get("watch_if_vends", False)
                    if item["kind"] == "join":
                        pending["join"] = item["value"]
                    else:
                        pending["guid"] = item["value"]
                    left = len(cmdq)
                    show_line(f"  running queued command: {item['label']}"
                              + (f"  ({left} still waiting)" if left else ""))
            active_builder = build_runtime.get("controller")
            building = bool(active_builder and active_builder.active)
            if pending["guid"] and not building:
                g = pending["guid"]; pending["guid"] = None
                try:
                    do_teleport(g)
                except Exception as e:
                    switching.clear()
                    show_line(f"  teleport failed: {e}")
                continue
            if pending.get("join") and not building:
                g = pending["join"]; pending["join"] = None
                try:
                    do_teleport(g, msg=P.build_join_realm(g), follow=False)
                except Exception as e:
                    switching.clear()
                    show_line(f"  realm join failed: {e}")
                continue
            try:
                wire = recv_bin(conn["ws"])
                net["last_rx"] = time.time()      # watchdog: we heard something
            except websocket.WebSocketTimeoutException:
                continue
            except Exception as e:
                if stop.is_set():
                    break
                if switching.is_set():
                    time.sleep(0.2)     # a teleport/reconnect owns the socket
                    continue
                # Only a genuinely-closed socket means we were kicked/dropped;
                # a transient hiccup on a still-open socket is not worth a
                # reconnect (which would burn a fresh login against the server).
                try:
                    alive = conn["ws"].connected
                except Exception:
                    alive = False
                if not alive:
                    show_line(f"  connection lost ({type(e).__name__}) — "
                              f"the server dropped us")
                    if do_reconnect("connection dropped"):
                        continue
                    break               # reconnect disabled or gave up
                continue
            # A malformed/partial frame must NOT be allowed to raise out here and
            # kill the reader thread (that turns the client into a zombie: prompt
            # works, sends go out, nothing is ever read back). Guard + log.
            try:
                _, body, term = P.decrypt_frame(wire, conn["key"])
                t = P.body_type(body) if term else None
            except Exception as e:
                show_line(f"  [reader] frame decode error "
                          f"(len={len(wire)}): {type(e).__name__}: {e}")
                continue
            if not term:
                continue
            offered_key = SEND_CIPHER.parse_key_offer(body)
            if offered_key is not None:
                with lock:
                    conn["outer_key"] = offered_key
                if offered_key:
                    show_line("  [transport] official send cipher enabled "
                              f"({len(offered_key)}-byte session key, counter "
                              f"{outer_send['counter']})")
                else:
                    show_line("  [transport] server supplied an empty send key; "
                              "outer cipher remains disabled")
            flog("RX", body)
            if prize_probe["active"]:            # 'prize test' raw-reply capture
                prize_probe["frames"].append((time.time(), t, body.hex()))
            if tradedebug["on"] and t in _TRADE_DBG_TYPES:
                extra = ""
                if t == 0x00ae:
                    o = P.parse_trade_offer(body)
                    if o:
                        extra = (f"  our={o['our_cubits']} their="
                                 f"{o['their_cubits']} flag={o['flag']}")
                elif t == 0x00a8:
                    rq = P.parse_trade_request(body)
                    if rq:
                        extra = f"  from={rq['name']} guid={rq['trade_guid'][:8]}"
                elif t == 0x00a9:
                    ast = P.parse_trade_accept_state(body)
                    if ast:
                        extra = (f"  guid={ast['trade_guid'][:8]} "
                                 f"accept_state={ast['state']}")
                elif t == 0x00ca:
                    d = P.parse_dialog(body)
                    if d:
                        extra = f"  DIALOG {d['title']!r}"
                elif t == 0x0036:
                    extra = "  <-- Trade Pending (accept ack)"
                elif t == 0x0011:
                    extra = f"  wallet={P.parse_wallet_balance(body)}"
                show_line(f"  [tradedbg] rx 0x{t:04x} {len(body)}B{extra}  "
                          f"{body.hex()}")
            # Hollawarp (in-game spelling "Hollawarp", holl-A-warp): a rx 0x000d
            # server notice tagged "(HOLLA)" carrying ~LINK={realm GUID}. Match
            # "hollawarp"/"(holla" so the "Warp Sugar" vend item never triggers
            # it. Detector extracts the realm and, if auto is on, queues it for
            # join+scan+watchlist.
            if hollow["auto"] and (b"hollawarp" in body.lower()
                                   or b"(holla" in body.lower()):
                hollowarp_detected(t, body)
            # QUIZ release trigger. In this trivia game the host MUTES the realm
            # while asking, then UNMUTES to let players answer — the server
            # announces "This realm has been unmuted!". Scanned on the RAW body
            # (like the Hollawarp notice above) so it fires whether the banner
            # rides an rx 0x000d notice or an 0x000c chat frame. "unmuted" is the
            # release word; it literally contains "muted", so we never match the
            # bare word — b"unmuted" for release, b"been muted" for the mute
            # state. Logged even with nothing held, so the first live run
            # confirms exactly how the banner arrives (frame type + bytes).
            if quizbot["on"]:
                _blow = body.lower()
                if b"unmuted" in _blow:
                    show_line(f"  [quiz] realm-unmute notice seen "
                              f"(rx 0x{t:04x}, {len(body)}B)")
                    try:
                        if quizbot["pending"]:
                            _quiz_release("realm unmuted")
                        _quiz_round_start()           # begin gathering guesses
                    except Exception as _qe:
                        show_line(f"  [quiz] unmute handling failed: "
                                  f"{type(_qe).__name__}: {_qe}")
                elif b"been muted" in _blow:
                    show_line(f"  [quiz] realm-mute notice seen "
                              f"(rx 0x{t:04x}) — holding until unmute")
                    try:
                        _quiz_round_close("realm muted")  # learn crowd's answer
                    except Exception as _qe:
                        show_line(f"  [quiz] round close failed: "
                                  f"{type(_qe).__name__}: {_qe}")
            if t == 0x0027 and len(body) > 100:     # friends list + pending
                try:
                    fr, pend = P.parse_friends_full(body)
                    friends.clear(); friends.update(fr)
                    requests.clear(); requests.update(pend)
                    want = lookup["name"]
                    if want:
                        # a name we just requested shows up in the pending array
                        # carrying its GUID — that's the whole trick. Keep the
                        # server's EXACT spelling of the name: the cancel (0x002b)
                        # matches on it verbatim, so cancelling with the
                        # user-typed variant (different case/spacing) would land
                        # the request but never remove it.
                        # Match exactly first, then fall back to an alphanumeric-
                        # only compare so a name typed with plain quotes/spacing
                        # still matches the server's fancy-quote/odd-spacing form.
                        entries = list(pend.items()) + list(fr.items())
                        wnorm = _alnum(want)
                        hit = next((e for e in entries if e[0].lower() == want),
                                   None)
                        if not hit and wnorm:
                            hit = next((e for e in entries
                                        if _alnum(e[0]) == wnorm), None)
                        if hit:
                            lookup["guid"] = hit[1]
                            lookup["match_name"] = hit[0]
                            lookup["event"].set()
                    else:
                        show_line(f"  (friends list: {len(friends)} entries, "
                                  f"{len(requests)} pending — type 'friends')")
                except Exception:
                    pass
                continue
            if t == 0x000c:
                try:
                    c = P.parse_chat(body)
                    emoji_code = c.get("emoji_code")
                    # A whisper rides this same 0x000c type but is server-tagged.
                    # It is PRIVATE, so it is handled on its own path and never fed
                    # to the public command handlers (nor added to realm_players —
                    # a whisper can come from another realm).
                    w = P.parse_whisper(body)
                    if w is not None:
                        own_guid = conn.get("own")
                        if own_guid and w["sender_guid"] == own_guid:
                            pass                      # echo of our own whisper
                        else:
                            vlog(f"[WHISPER] {w['message']}")
                            if whisperbot["on"]:
                                handle_whisper(w["sender_guid"], w["message"])
                        continue
                    if emoji_code is not None:
                        vlog(f"[CHAT] <emoji 0x{emoji_code:02x}>")
                    else:
                        vlog(f"[CHAT] {c['text']}")
                    # chat is realm-local, so the sender is in our realm — good
                    # enough proof of presence for the summon same-realm guard.
                    realm_players.add(c["sender_guid"])
                    # QUIZ bot runs on public chat INDEPENDENTLY of whisper mode
                    # (it's a public game), so it is handled here before the
                    # serve_public gate. Guarded internally by quizbot["on"].
                    if emoji_code is None:
                        try:
                            handle_quiz(c["sender_guid"], c["text"])
                            _quiz_collect(c["sender_guid"], c["text"])
                        except Exception as _qe:
                            show_line(f"  [quiz] {type(_qe).__name__}: {_qe}")
                    # LIVE TRANSLATOR also runs on public chat independently of
                    # whisper mode (it's a passive service). Guarded internally by
                    # translatebot['on']; all failures are contained inside it.
                    if emoji_code is None:
                        try:
                            handle_translate(c["sender_guid"], c["text"])
                        except Exception as _te:
                            show_line(f"  [translate] "
                                      f"{type(_te).__name__}: {_te}")
                    # Once the whisper bot is on it REPLACES public chat: public
                    # keyword/price/summon/scan commands are ignored so everyone is
                    # served through whispers. --answer-public (whisperbot["public"])
                    # keeps both. Private emoji bytes are not text and must not be
                    # fed to command/chatbot matching as a replacement character.
                    serve_public = whisperbot["public"] or not whisperbot["on"]
                    if emoji_code is None and serve_public:
                        log_mention(c["sender_guid"], c["text"])
                        handle_chat_command(c["sender_guid"], c["text"])
                        handle_price_query(c["sender_guid"], c["text"])
                        handle_summon(c["sender_guid"], c["text"])
                        handle_scan_query(c["sender_guid"], c["text"])
                    elif emoji_code is None:
                        # whisper-only mode: still record mentions, and answer a
                        # public 'help' by WHISPERING the command list back (the
                        # only thing served in public — it teaches the whisper flow).
                        log_mention(c["sender_guid"], c["text"])
                        handle_public_help(c["sender_guid"], c["text"])
                except Exception as e:
                    show_line(f"  [chat handler] {type(e).__name__}: {e}")
                    show_line(f"  <- {describe(t, body)}")
                continue
            if t == P.WHISPER_MENU_TYPE:           # 0x00ba server menu dialog
                # The "Whisper to Who?" picker the server sends after we send a
                # "/whisper <msg>". Hand it to the whisper worker that is mid-
                # handshake; suppress any other/unsolicited menu.
                if whisper_menu["awaiting"]:
                    m = P.parse_whisper_menu(body)
                    if m:
                        whisper_menu["menu"] = m
                        whisper_menu["event"].set()
                    else:
                        supp[t] += 1
                else:
                    supp[t] += 1
                continue
            if t == 0x000e and len(body) > 30:     # object-contents reply
                # rx 0x000e is the inventory form; addressed to a world object's
                # guid it carries that object's contents (a mannequin's outfit).
                # Own inventory is retained separately from queried object
                # contents; the GUID must match the appropriate recipient.
                try:
                    inv = P.parse_inventory(body)
                    if inv and inv["guid"] == conn.get("own"):
                        with player_inventory["lock"]:
                            player_inventory["seq"] += 1
                            snap = dict(inv)
                            snap["items"] = [dict(item) for item in inv["items"]]
                            snap["seq"] = player_inventory["seq"]
                            snap["received_at"] = time.time()
                            player_inventory["snapshot"] = snap
                            player_inventory["event"].set()
                    elif (inv and mwait["guid"]
                          and inv["guid"] == mwait["guid"]):
                        mwait["inv"] = inv
                        mwait["event"].set()
                except Exception:
                    pass
                continue
            if t in (0x000f, 0x0021):             # the realm's objects
                try:
                    objs = P.parse_world_objects(body)
                    world_rx["last"] = time.time()
                    for o in objs:
                        world[o["guid"]] = o
                    # Diagnose silent frame drops (see world_diag above): the
                    # parser returns [] both for a clean-but-empty frame and for
                    # one whose payload doesn't divide evenly. Recompute the
                    # remainder here so a dropped burst is visible, not guessed at.
                    rsize = 70 if t == 0x000f else 44
                    hdr = 4 if t == 0x000f else 8
                    payload = len(body) - hdr
                    world_diag["frames"] += 1
                    world_diag["objs"] += len(objs)
                    if payload > 0 and payload % rsize:
                        world_diag["dropped"] += 1
                        world_diag["remainders"][(t, payload % rsize)] += 1
                        vlog(f"[world] DROPPED 0x{t:04x} frame: {payload}B payload, "
                             f"{payload // rsize} whole {rsize}B records + "
                             f"{payload % rsize}B leftover — burst lost")
                except Exception:
                    pass
                continue
            if t == 0x0014:                        # block query reply
                # PRIZE arm/win ack. The crack ARMS by block-querying the machine,
                # THEN guesses; both produce an rx 0x0014. The machine may answer
                # with the SHORT 19-byte form (coords + 07 00 00, no guid) OR the
                # full 33-byte form (kind + guid) — accept EITHER for the armed
                # block. Phase tells arm from win: a reply during "armed" is the arm
                # ack; a reply during "guessed" is the server ACCEPTING = WIN.
                if (prizewait["active"] and prizewait["block"]
                        and len(body) >= 16):
                    rbx = int.from_bytes(body[4:8], "little")
                    rby = int.from_bytes(body[8:12], "little")
                    rbz = int.from_bytes(body[12:16], "little")
                    if (rbx, rby, rbz) == tuple(prizewait["block"]):
                        if len(body) >= 33:
                            prizewait["dispenser_guid"] = body[17:33].hex()
                            prizewait["arm_kind"] = body[16]
                        if prizewait["phase"] == "armed":
                            prizewait["arm_event"].set()
                        elif prizewait["phase"] == "guessed":
                            # TENTATIVE only: the guess was acknowledged, but a
                            # wrong guess ALSO sends rx 0x0036 right after. Don't
                            # declare the win here — let the loop confirm no 0x0036
                            # arrived. (Fixes the stray-0x0014 false positive.)
                            prizewait["saw_accept"] = True
                if len(body) >= 17:                # short/full occupied reply
                    info = P.parse_block_query_reply(body)
                    if info:
                        qcache[(info["bx"], info["by"], info["bz"])] = info
                        if qwait["block"] == (info["bx"], info["by"], info["bz"]):
                            qwait["reply"] = info
                            qwait["event"].set()
                        elif info["text"] and not qwait["batch"]:
                            vlog(f"[block] ({info['bx']},{info['by']},"
                                 f"{info['bz']}): {info['text']}")
                continue
            if t == 0x00c8:                        # 'Enter Sign Text' after a place
                g = P.parse_sign_prompt(body)
                if g and sign_wait["active"]:
                    sign_wait["guid"] = g
                    sign_wait["event"].set()
                continue
            if t == 0x00ca:                        # server dialog
                d = P.parse_dialog(body)
                if d:
                    if d["guid"] in trades:         # a TRADE confirm dialog
                        handle_trade_dialog(d)
                    elif dwait["active"]:           # an owner-buy vending dialog
                        dwait["dialog"] = d
                        dwait["event"].set()
                    else:
                        show_line(f"[dialog] {d['title']}: {d['text']}")
                        show_line("         (unanswered — this client never "
                                  "confirms dialogs automatically)")
                continue
            if t == 0x00a8:                        # incoming trade request
                if regwait["active"]:              # a register-open probe is waiting
                    req = P.parse_trade_request(body)
                    if req:
                        regwait["req"] = req
                        regwait["event"].set()
                        continue                   # don't let autotrade touch it
                # Record the latest trade for the web console's manual buttons,
                # regardless of whether escrow autotrade will also handle it.
                mreq = P.parse_trade_request(body)
                if mreq and mreq.get("trade_guid"):
                    last_trade.update(guid=mreq["trade_guid"],
                                      name=mreq.get("name") or "?",
                                      at=time.time(), staked=0, our=0, open=True)
                    show_line(f"  [trade] {last_trade['name']} opened a trade "
                              f"window — accept/decline it from the web console.")
                handle_trade_request(body)
                continue
            if t == 0x00a9:                        # accepted/cleared button state
                handle_trade_accept_state(body)
                continue
            if t == 0x00ae:                        # trade offer / stake state
                handle_trade_offer(body)
                continue
            if t == 0x00ac:                        # trade window closed
                handle_trade_close(body)
                continue
            if t == 0x00ab:                        # trade cancelled/reset
                handle_trade_cancel(body)
                continue
            if t == 0x0036:                        # 'Wrong Password!' OR 'Trade Pending'
                wp = P.parse_wrong_password(body)
                if wp is not None:                 # a Password-Sentry rejection is
                    if prizewait["active"]:        # NEVER a trade — swallow it here
                        prizewait["result"] = "wrong"
                        prizewait["text"] = wp["text"]
                        prizewait["event"].set()
                    continue
                handle_trade_pending(body)
                continue
            if t == 0x0011:                       # live wallet-balance broadcast
                bal = P.parse_wallet_balance(body)
                if bal is not None:
                    wallet["cubits"] = bal
                    trade_credit_retry["fn"]()
                supp[t] += 1                      # still churn — don't print it
                continue
            if t == 0x0037:                       # INVENTORY_CHANGED = buy landed
                if buywait["active"]:
                    buywait["result"] = "bought"
                    buywait["event"].set()
                supp[t] += 1
                continue
            if t == 0x00de:                       # short server toast
                txt = P.parse_notice_00de(body)
                if buywait["active"]:
                    if txt and "not enough" in txt.lower():
                        buywait["result"] = "insufficient"
                    else:
                        buywait["result"] = "notice"
                    buywait["text"] = txt
                    buywait["event"].set()
                elif txt:
                    show_line(f"[server] {txt}")
                else:
                    supp[t] += 1
                continue
            if t == 0x005f:                       # realm identity on every entry
                apply_realm_id(P.parse_realm_id(body))
                continue
            if t == 0x00e1:                       # realm-browser 'Search Results'
                want = realm_search["want"]
                if want is None:
                    supp[t] += 1          # a menu we didn't ask for — stay quiet
                    continue
                try:
                    results = P.parse_realm_search(body)
                except Exception:
                    results = []
                realm_search["results"] = results
                match = next(((nm, g) for nm, g in results
                              if nm.lower() == want), None)
                realm_search["match_name"] = match[0] if match else None
                realm_search["guid"] = match[1] if match else None
                realm_search["event"].set()
                if match and (realm_search["then_join"]
                              or realm_search["then_scan"]):
                    want_scan = realm_search["then_scan"]
                    realm_search["then_join"] = False
                    realm_search["then_scan"] = False
                    realm_search["want"] = None
                    show_line(f"  found '{match[0]}' ({match[1][:8]}…) among "
                              f"{len(results)} result(s) — "
                              + ("joining + scanning ..." if want_scan
                                 else "joining ..."))
                    pending["join"] = match[1]
                    if want_scan:
                        pending["autoscan"] = True
                        # a scan-on-command realm gets watchlisted if it turns
                        # out to have vends (same rule as auto-Hollawarp)
                        pending["watch_if_vends"] = True
                elif not match:
                    realm_search["then_join"] = False
                    realm_search["then_scan"] = False
                    realm_search["want"] = None
                    show_line(f"  realm search: no exact name match for "
                              f"'{want}' among {len(results)} result(s) — "
                              f"'searchrealm {want}' to list them")
                continue
            if t == 0x000d:                       # server text notice
                notice = P.parse_notice(body)
                if notice:
                    show_line(f"[server] {notice}")
                else:
                    supp[t] += 1
                continue
            # Passively learn every player's GUID from their state broadcasts, so
            # `guid`/`tp` can resolve them by name even when the friend system
            # rejects the name (decorated names with quotes/symbols).
            if t == 0x0005:
                try:
                    st = P.parse_player_state(body)
                    if st and st.get("guid"):
                        gid = st["guid"]
                        realm_players.add(gid)
                        if st.get("name"):
                            players[gid] = st["name"]
                        # Track position from EVERY 0x0005 that carries it — named or
                        # not — so a player's spot stays CURRENT as they move. (The
                        # name only comes with the spawn/first-seen frame; movement
                        # updates are name-less, so gating on name froze positions at
                        # join, which is why the prize button used a stale spot.)
                        if st.get("x") is not None:
                            track_player_heading(gid, st["x"], st["y"], st.get("z"))
                            if not st.get("name"):
                                # a name-less frame might be a mannequin/statue too —
                                # record its block so `mannequins` can read the outfit
                                b = (st["x"] // P.COORD_BASE,
                                     st["y"] // P.COORD_BASE,
                                     st["z"] // P.COORD_BASE)
                                if b != (0, 0, 0):
                                    mannequin_seen[b] = gid
                except Exception:
                    pass
            # after a cross-realm teleport: settle onto the friend as soon as we
            # see a non-zero position — EITHER our own (the server placed us via
            # the 0x000e registration) OR the friend's (fallback: walk to them).
            if state["follow_guid"] and t in (0x0005, 0x0023):
                guid_in = body[4:20].hex() if len(body) >= 20 else None
                own = conn.get("own")
                p = None
                if t == 0x0005 and guid_in in (state["follow_guid"], own):
                    st = P.parse_player_state(body)
                    if st:
                        p = (st["x"], st["y"], st["z"])
                elif t == 0x0023 and guid_in == own:
                    p = P.parse_self_move(body)
                if p and (p[0] != 0 or p[1] != 0):
                    tgt = state["follow_guid"]
                    state["follow_guid"] = None
                    place_at(p, "settled onto them")
                    face_like(tgt)     # turn to match their angle, if we learned it
                    continue
            # normal realm entry: the server places us at the realm's portal and
            # reports it as our own 0x0005/0x0023. Adopt it instead of guessing —
            # this is what stops us spawning at a stale hardcoded spot.
            if ((not pos["placed"] or pos["provisional"])
                    and t in (0x0005, 0x0023) and len(body) >= 20):
                if body[4:20].hex() == conn.get("own"):
                    p = None
                    if t == 0x0005:
                        st = P.parse_player_state(body)
                        if st:
                            p = (st["x"], st["y"], st["z"])
                    else:
                        p = P.parse_self_move(body)
                    if p:
                        zero = p[0] == 0 and p[1] == 0
                        if not (pos["placed"] and zero):   # never downgrade
                            place_at(p, "spawned at the realm portal"
                                     + (" (0,0 — provisional)" if zero else ""),
                                     home=True, provisional=zero)
                            continue
            # Anything left is either loud churn or a type we don't decode.
            # Neither is worth a console line — count it so 'stats' can show what
            # was hidden, and keep the screen to things that matter.
            supp[t] += 1
    def reader_supervised():
        # A reader that dies silently turns the client into a zombie (prompt and
        # sends work, but nothing is ever read back — every search/teleport then
        # times out forever). Keep it alive: log any escape and restart the loop.
        while not stop.is_set():
            try:
                reader()
                return                       # clean exit (stop set)
            except Exception as e:
                import traceback
                show_line(f"  [reader] CRASHED: {type(e).__name__}: {e} "
                          f"— restarting")
                show_line("  " + traceback.format_exc().replace("\n", "\n  "))
                time.sleep(0.5)
    reader_holder["t"] = threading.Thread(target=reader_supervised, daemon=True)
    reader_holder["t"].start()

    def go_offline(reason="disabled"):
        """Take THIS account fully offline and keep it off until go_online().

        Clears auto-reconnect and closes the socket: the reader sees the dead
        socket, do_reconnect refuses (auto-reconnect off) and the reader thread
        ends — but the process keeps running its command loop, so 'enable' can
        bring it back. Returns (ok, message)."""
        if manual_offline["on"]:
            return False, "already offline"
        manual_offline["prev_reconnect"] = args.auto_reconnect
        manual_offline["on"] = True
        args.auto_reconnect = False       # reader's drop handler won't reconnect
        pos["placed"] = False             # presence idles instead of announcing
        switching.set()                   # freeze all sends while offline
        try:
            conn["ws"].close()
        except Exception:
            pass
        show_line(f"  [link] OFFLINE ({reason}) — 'enable' to log back in")
        return True, "offline"

    def go_online():
        """Log this account back in after go_offline() and restart the reader."""
        if not manual_offline["on"]:
            try:
                if conn["ws"].connected:
                    return False, "already online"
            except Exception:
                pass
        show_line("  [link] logging back in…")
        try:
            nws, nkw, nown, nouter = full_connect(send_post=True)
        except Exception as e:
            return False, f"reconnect failed: {type(e).__name__}: {e}"
        with lock:
            conn["ws"], conn["key"], conn["own"] = nws, nkw, nown
            conn["outer_key"] = nouter
        nws.settimeout(1.0)
        net["last_rx"] = time.time()
        # fresh spawn; drop the old realm's object view (mirror do_reconnect)
        pos["placed"] = False
        pos["provisional"] = True
        pos["frozen"] = False
        state["entry_logged"] = False
        world.clear()
        fossil_region["box"] = None           # a coord box is realm-specific
        realm_players.clear()
        player_pos.clear()
        player_heading.clear()
        player_block.clear()
        mannequin_seen.clear()
        manual_offline["on"] = False
        args.auto_reconnect = manual_offline.get("prev_reconnect", True)
        switching.clear()
        # the supervised reader ended when we went offline — start a fresh one
        if not (reader_holder["t"] and reader_holder["t"].is_alive()):
            reader_holder["t"] = threading.Thread(target=reader_supervised,
                                                  daemon=True)
            reader_holder["t"].start()
        show_line("  [link] ONLINE — back in world")
        return True, "online"

    def presence():
        t_start = time.time()
        while not stop.is_set():
            time.sleep(1.0)
            if not pos["placed"]:
                if time.time() - t_start < args.spawn_timeout:
                    continue
                # server never told us where we are
                if args.x is not None:
                    place_at((args.x, args.y or 0, args.z),
                             "no spawn from server — using --x/--y")
                elif not pos["warned"]:
                    pos["warned"] = True
                    show_line("  server never reported a spawn position — "
                              "avatar not announced. Restart with --x/--y if "
                              "needed.")
                    continue
                else:
                    continue
            if walking.is_set():
                # a synthetic walk owns the avatar right now; its own frames carry
                # the velocity — don't inject a zero-velocity keepalive mid-stride
                continue
            try:
                announce()
            except Exception:
                break
    threading.Thread(target=presence, daemon=True).start()

    def watchdog():
        """Catch a SILENT kick: if no frame has arrived for --idle-timeout
        seconds, the connection is dead even though the socket never closed.
        Close it so the reader's next recv fails and auto-reconnect kicks in.
        We only WATCH here (don't reconnect on this thread) so the reader stays
        the single owner of the socket. Skipped while a teleport/reconnect is in
        flight, and while auto-reconnect is off."""
        last_beat = time.time()
        while not stop.is_set():
            if stop.wait(5.0):
                return
            # LOG-mode extra: a quiet heartbeat every 60s so you can see the
            # connection is alive during idle stretches (hidden in regular mode).
            if time.time() - last_beat >= 60:
                last_beat = time.time()
                vlog(f"  [heartbeat] connected; last frame "
                     f"{time.time() - net['last_rx']:.0f}s ago, "
                     f"{sum(supp.values())} background frames seen")
            if (args.idle_timeout <= 0 or not args.auto_reconnect
                    or switching.is_set() or reconnecting.is_set()):
                net["last_rx"] = time.time()     # don't count time we're paused
                continue
            idle = time.time() - net["last_rx"]
            if idle > args.idle_timeout:
                show_line(f"  watchdog: no data for {idle:.0f}s (>"
                          f"{args.idle_timeout:.0f}s) — treating as a silent "
                          f"kick, dropping the socket to reconnect")
                net["last_rx"] = time.time()     # arm again; reader takes over
                try:
                    conn["ws"].close()           # -> reader recv fails -> reconnect
                except Exception:
                    pass
    threading.Thread(target=watchdog, daemon=True).start()
    threading.Thread(target=whisper_worker, daemon=True).start()
    threading.Thread(target=pub_worker, daemon=True).start()

    def _idle_ok():
        """Safe to fidget: we're placed for real, and nothing that cares about
        our exact position or has a dialog open is in flight."""
        return (pos["placed"] and not pos.get("provisional")
                and not bot_busy() and not scanning.is_set()
                and not regwait["active"] and not buywait["active"]
                and not sign_wait["active"])

    def idle_lookaround():
        """Parked, a real player mostly stands still and occasionally glances
        around. Facing is the +24 heading field, so we can do that WITHOUT walking:
        every so often turn to a new random heading in place (no pacing back and
        forth). Rare and gentle; suppressed while busy/scanning/trading or when
        wander is off."""
        import random
        while not stop.is_set():
            # long, jittered gaps — a parked player is still most of the time
            if stop.wait(random.uniform(25.0, 70.0)):
                return
            if (not wander["on"] or wander["active"] or movelock["frozen"]
                    or drive["active"] or drive["keys"] or not _idle_ok()):
                continue
            # mostly a small glance to a new heading; once in a while a hop
            if random.random() < 0.25:
                do_jump()
            else:
                cur = pos.get("heading", 0)
                delta = random.choice([45, 90, 135, -45, -90, 180])
                pos["heading"] = (cur + delta) % 360
                pos["frozen"] = False
                try:
                    announce(force=True)
                except Exception:
                    pass
    threading.Thread(target=idle_lookaround, daemon=True).start()

    # ---- client-side physics (collision + gravity) for driving ----------
    CB = P.COORD_BASE

    def solid_set():
        """The realm's solid blocks as a set of (bx,by,bz), plus the set of
        (bx,by) columns that hold any geometry. Built from `world` (the realm's
        placed-object list) and cached until `world` changes; `world` is cleared
        on every realm hop, which resets the cache and re-arms calibration."""
        if _solidc["len"] != len(world):
            s, cols = set(), set()
            kinds = physics["solid_kinds"]
            for o in world.values():
                if o["x"] % CB or o["y"] % CB:
                    continue                       # off-grid = a dropped item
                if kinds is not None and o["kind"] not in kinds:
                    continue
                s.add((o["bx"], o["by"], o["bz"]))
                cols.add((o["bx"], o["by"]))
            _solidc["set"], _solidc["cols"], _solidc["len"] = s, cols, len(world)
            if not world:
                physics["calibrated"] = False      # new realm — recalibrate
                physics["ground_bz"] = None
        return _solidc["set"]

    def _note_ground(bz):
        """Remember the deepest floor we've rested on = the realm's base ground,
        so a walk-off into unmapped terrain falls back to it (down = +z, so the
        base ground is the LARGEST rest z)."""
        g = physics["ground_bz"]
        physics["ground_bz"] = bz if g is None else max(g, bz)

    def _fall_target(bx, by, from_bz):
        """Where the bot should end up in column (bx,by): the world floor if the
        column has one, else the remembered base ground if it's below us, else
        stay put (unknown terrain — don't drop into the void)."""
        if (bx, by) in _solidc["cols"]:
            rest = settle_z(bx, by, from_bz)
            if rest is not None:
                _note_ground(rest)
                return rest
        g = physics["ground_bz"]
        if g is not None and g > from_bz:          # fall back to base ground
            return g
        return from_bz

    def _calibrate_ground():
        """Work out which way is 'down' from where the bot is standing. The floor
        block should sit one cell in the `down` direction from the body cell; if
        the spawn shows the solid at the body's own cell, nudge the body up one so
        the floor-at-bz+down model holds. Runs once per realm, when geometry and a
        real placement are available."""
        S = solid_set()
        if not S or not pos["placed"] or pos.get("provisional"):
            return
        bx, by, bz = pos["x"] // CB, pos["y"] // CB, pos["z"] // CB
        if (bx, by, bz + 1) in S:                  # floor just below (+z) — normal
            physics["down"] = 1
        elif (bx, by, bz - 1) in S:                # floor just above — flipped
            physics["down"] = -1
        elif (bx, by, bz) in S:                    # standing coincident with floor
            pos["z"] -= physics["down"] * CB       # lift body into the air cell
        physics["calibrated"] = True
        # The server placed us standing somewhere valid, so trust the spawn z as a
        # ground level even if that exact cell isn't in `world` — this is what a
        # walk-off into unmapped terrain falls back to.
        _note_ground(pos["z"] // CB)

    def _supported(bx, by, bz):
        return (bx, by, bz + physics["down"]) in solid_set()

    def settle_z(bx, by, from_bz):
        """Gravity: from block height `from_bz`, return the z the bot rests at in
        column (bx,by) — the first cell with a solid block directly below. Climbs
        out if it starts inside a block. Returns None for a void / no known floor
        within max_fall, so the caller can hold position instead of dropping into
        unloaded terrain."""
        S = solid_set()
        d = physics["down"]
        bz = from_bz
        for _ in range(physics["max_fall"] + 2):
            if (bx, by, bz) in S:                  # inside a block — step against g
                bz -= d
                continue
            if (bx, by, bz + d) in S:              # solid below — rest here
                return bz
            bz += d                                # fall one cell toward `down`
        return None

    def _try_horizontal(nbx, nby, bz):
        """Entering column (nbx,nby) at body height `bz`: (allowed, new_bz).
        Blocked by a wall 2+ cells tall; climbs a single-block ledge (step-up)."""
        S = solid_set()
        d = physics["down"]
        if (nbx, nby, bz) in S:                    # something at body level
            up = bz - d                            # one step up (against gravity)
            if physics["step_up"] < 1 or (nbx, nby, up) in S:
                return False, bz                   # too tall — a wall
            return True, up
        return True, bz

    def drive_loop():
        """Live WASD driving from the web console. Each tick, read the held keys
        and take one walk-sized step, broadcasting a WALKING motion frame so other
        players see the avatar walk. With physics ON (default) it obeys the realm
        geometry: it won't walk through walls (collision), climbs 1-block ledges,
        steps down stairs, and FALLS off ledges until it lands on solid ground —
        the landing z becomes its position. With physics OFF, Q/E free-fly the z
        axis and there is no collision (the old fly-anywhere behaviour). Manual
        driving overrides `movelock` (the user is steering) but needs an avatar
        and a placement."""
        tick = 0.13                       # ~7.5 frames/s, same feel as walk_to
        seg = P.WALK_TICK * 0.55          # distance per tick = real walk speed
        while not stop.is_set():
            keys = set(drive["keys"])     # snapshot (endpoint mutates it)
            zd, drive["z"] = drive["z"], 0
            if args.no_avatar or not pos["placed"]:
                drive["active"] = False
                if stop.wait(tick if (keys or zd) else 0.05):
                    return
                continue
            phys = physics["on"]
            if phys:
                solid_set()               # refresh geometry cache for this tick
                if not physics["calibrated"]:
                    _calibrate_ground()
            bx, by, bz = pos["x"] // CB, pos["y"] // CB, pos["z"] // CB

            if phys:
                sup = _supported(bx, by, bz)
                physics["dbg"] = (f"blk({bx},{by},{bz}) down={physics['down']:+d} "
                                  f"{'GROUND' if sup else 'AIR'} "
                                  f"known={'Y' if (bx,by) in _solidc['cols'] else 'N'} "
                                  f"base={physics['ground_bz']} blocks={len(_solidc['set'])}")

            if not keys and not zd:
                # Idle: apply gravity so a bot standing on a ledge that walked out
                # from under it (or was placed in the air) drops to the ground.
                fell = False
                if phys and not _supported(bx, by, bz):
                    rest = _fall_target(bx, by, bz)
                    if rest != bz:
                        pos["z"] = rest * CB
                        pos["frozen"] = False
                        pos["seq"] = (pos["seq"] + 1) & 0xFF
                        try:
                            send(P.build_move(pos["x"], pos["y"], pos["z"],
                                              pos["seq"], vy=physics["down"] * 100,
                                              moving=True))
                        except Exception:
                            pass
                        fell = True
                if not fell and drive["moving"]:   # just stopped — plant a frame
                    drive["moving"] = False
                    drive["active"] = False
                    pos["frozen"] = False
                    try:
                        announce(force=True)
                    except Exception:
                        pass
                if stop.wait(tick if fell else 0.05):
                    return
                continue

            drive["active"] = True
            # vertical: only when physics is OFF (otherwise gravity owns z)
            if zd and not phys:
                pos["z"] = max(0, pos["z"] + zd * P.WALK_TICK)
            dx = dy = 0.0
            if "w" in keys:               # forward = NORTH = -Y
                dy -= 1
            if "s" in keys:               # back = SOUTH = +Y
                dy += 1
            if "d" in keys:               # right = EAST = +X
                dx += 1
            if "a" in keys:               # left = WEST = -X
                dx -= 1
            if dx or dy:
                mag = _math.hypot(dx, dy)
                ux, uy = dx / mag, dy / mag
                nx = pos["x"] + int(round(ux * seg))
                ny = pos["y"] + int(round(uy * seg))
                if phys:
                    # collision + terrain, one axis at a time so we SLIDE along a
                    # wall instead of sticking to it
                    nbz = bz
                    ax = pos["x"]
                    if (nx // CB, by) != (bx, by):
                        ok, sbz = _try_horizontal(nx // CB, by, nbz)
                        if ok:
                            ax, nbz = nx, sbz
                    else:
                        ax = nx
                    abx = ax // CB
                    ay = pos["y"]
                    if (abx, ny // CB) != (abx, by):
                        ok, sbz = _try_horizontal(abx, ny // CB, nbz)
                        if ok:
                            ay, nbz = ny, sbz
                    else:
                        ay = ny
                    pos["x"], pos["y"] = ax, ay
                    # gravity / step-down in the new column (world floor, else the
                    # remembered base ground, else hold height for unknown terrain)
                    rest = _fall_target(pos["x"] // CB, pos["y"] // CB, nbz)
                    pos["z"] = rest * CB
                else:
                    pos["x"], pos["y"] = nx, ny
                vx, vy = int(ux * P.WALK_SPEED), int(uy * P.WALK_SPEED)
                pos["heading"] = P.heading_deg(vx, vy)
                pos["frozen"] = False
                pos["seq"] = (pos["seq"] + 1) & 0xFF
                drive["moving"] = True
                try:
                    send(P.build_move(pos["x"], pos["y"], pos["z"], pos["seq"],
                                      vx=vx, vy=vy, moving=True))
                except Exception:
                    pass
            elif zd:                      # only went up/down — a standing frame
                pos["frozen"] = False
                try:
                    announce(force=True)
                except Exception:
                    pass
            if stop.wait(tick):
                return
    threading.Thread(target=drive_loop, daemon=True).start()

    def manual_trade_action(action):
        """Fire one manual trade click for the most recent trade window someone
        opened with us — driven by the web console buttons.

        SAFETY: the bot's side of a trade is always empty (it never stakes cubits
        unless an authorised withdrawal is pending), so ACCEPT and CONFIRM here
        can only ever RECEIVE — they cannot give anything away. As a belt-and-
        braces guard, CONFIRM refuses if the server shows our side is non-empty.
        Returns (ok, message) for the browser."""
        tg = last_trade.get("guid")
        who = last_trade.get("name") or "someone"
        if not tg or not last_trade.get("open"):
            return False, ("no open trade window — have someone open a trade "
                           "with the bot first")
        try:
            if action == "accept":
                send(P.build_trade_accept(tg, phase="accept"))
                show_line(f"  [trade] MANUAL accept -> {who} (received nothing "
                          f"away; our side stays empty)")
                return True, f"clicked Accept on {who}'s trade"
            if action == "confirm":
                if int(last_trade.get("our", 0)) != 0:
                    return False, ("refusing to confirm: the bot's side isn't "
                                   "empty — use the bot console for withdrawals")
                send(P.build_trade_accept(tg, phase="confirm"))
                show_line(f"  [trade] MANUAL confirm (YES) -> {who}")
                return True, f"confirmed {who}'s trade (YES)"
            if action == "cancel":
                send(P.build_trade_cancel(tg))
                last_trade["open"] = False
                show_line(f"  [trade] MANUAL decline -> {who}")
                return True, f"declined {who}'s trade"
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"
        return False, "unknown trade action"

    def search_realm(name, then_join=False, then_scan=False):
        """Query the realm browser for `name` (tx 0x00c8). The reply is an
        rx 0x00e1 markup menu handled in the reader; if `then_join` it fires the
        0x00d3 join on the current GUID of the first exact name match. If
        `then_scan` it joins AND autoscans that realm into the market DB."""
        own = conn.get("own")
        if not own:
            show_line("  can't search realms yet — no player GUID "
                      "(still connecting?)")
            return False
        # The realm browser is a stateful server-side UI: it won't answer a
        # 0x00c8 search until it's been OPENED with the all-FF 0x00d3 frame (the
        # real client does this first). Open once per connection; the server's
        # default-list reply lands while want=None and is harmlessly suppressed.
        if not realm_search["browser_open"]:
            send(P.build_open_realm_browser())
            realm_search["browser_open"] = True
            time.sleep(0.4)                 # let the default list arrive first
        realm_search["want"] = name.lower()
        realm_search["guid"] = None
        realm_search["match_name"] = None
        realm_search["then_join"] = then_join
        realm_search["then_scan"] = then_scan
        realm_search["results"] = []
        realm_search["event"].clear()
        send(P.build_realm_search(name, own))
        return True

    def do_search(name, timeout=5.0):
        """Fire a realm-browser search and WAIT for its reply. Returns the
        results list (which may be empty = 'no such realm') or None if the
        browser never answered at all. The server-side browse session can lapse
        — after which every 0x00c8 search is silently dropped and we'd see 'no
        reply' forever — so on a no-reply we force the browser OPEN again and
        retry once."""
        for attempt in (1, 2):
            if not search_realm(name, then_join=False):
                return None                 # not connected yet
            if realm_search["event"].wait(timeout):
                return realm_search["results"]
            realm_search["browser_open"] = False   # lapsed: reopen on retry
        return None

    def find_guid(name):
        """Look a name up in everything we already know (players seen in-world,
        friends, outstanding requests, previous lookups, or a literal 32-hex
        GUID)."""
        if len(name) == 32:
            try:
                bytes.fromhex(name)
                return name
            except ValueError:
                pass
        for table in (friends, requests):
            for nm, g in table.items():
                if nm.lower() == name.lower():
                    return g
        return known.get(name.lower()) or find_player_by_name(name)

    def lookup_guid(name):
        """Resolve a NON-friend's GUID: send them a friend request, read the GUID
        out of the pending-requests array the server sends back, then cancel the
        request (tx 0x002b) so nothing is left hanging on their end.

        Never runs the cycle against an existing friend or an already-pending
        request — 0x002b would delete/cancel that for real."""
        for nm, g in friends.items():
            if nm.lower() == name.lower():
                known[nm.lower()] = g
                print(f"  {nm} is already a friend -> {g}  (nothing sent)")
                return g
        for nm, g in requests.items():
            if nm.lower() == name.lower():
                known[nm.lower()] = g
                print(f"  request to {nm} was already pending -> {g}  "
                      f"(nothing sent, left alone)")
                return g
        # Best path: they're a player we've seen in-world — read the GUID from
        # their live presence, no friend request (works for decorated names the
        # friend system rejects, like ones with quotes).
        pg = find_player_by_name(name)
        if pg:
            known[name.lower()] = pg
            print(f"  {players.get(pg, name)} is in-world -> {pg}  "
                  f"(no request needed)")
            return pg

        lookup["name"] = name.lower()
        lookup["guid"] = None
        lookup["match_name"] = None
        lookup["event"].clear()
        print(f"  requesting '{name}' ...")
        send(P.build_friend_request(name))
        time.sleep(0.4)
        send(P.build_refresh_friends())
        if not lookup["event"].wait(3.0):
            send(P.build_refresh_friends())      # the list can lag a beat
            lookup["event"].wait(3.0)
        guid = lookup["guid"]
        # Cancel with the name the SERVER returned, verbatim — 0x002b matches the
        # name exactly, and the fuzzy-matched request may have landed under a
        # different case/spacing than we typed. Fall back to the typed name only
        # if we somehow never saw the entry.
        cancel_name = lookup["match_name"] or name
        lookup["name"] = None
        low = cancel_name.lower()

        def still_listed():
            # the entry is normally in pending; if the target auto-accepted it
            # moves to friends — either way we only added it to read the GUID
            return any(nm.lower() == low
                       for nm in list(requests) + list(friends))

        # Confirm the cancel took, RIGHT HERE, before returning — the caller
        # teleports next and do_teleport then owns the socket for seconds,
        # swallowing the refresh replies, so a fire-and-forget cancel would never
        # be seen through. Re-send until the server's own list drops the entry.
        gone = not still_listed()
        for _ in range(5):
            if gone or stop.is_set():
                break
            send(P.build_unfriend(cancel_name))
            send(P.build_refresh_friends())
            t0 = time.time()
            while time.time() - t0 < 1.5:
                if not still_listed():
                    gone = True
                    break
                time.sleep(0.1)

        if guid:
            known[name.lower()] = guid
            if gone:
                print(f"  {name} -> {guid}   (request cancelled)")
            else:
                print(f"  {name} -> {guid}   (WARNING: cancel didn't take — "
                      f"still pending; try  unfriend {cancel_name})")
        else:
            print(f"  couldn't resolve '{name}' — no pending entry came back "
                  f"(wrong spelling, or the server refused the request). "
                  f"Cancel sent anyway.")
            if requests:
                print("  pending requests right now (the target's real spelling "
                      "may be here — copy it verbatim):")
                for nm, g in requests.items():
                    print(f"    {nm!r}  {g}")
            send(P.build_unfriend(cancel_name))
            send(P.build_refresh_friends())
        return guid

    def occupied_blocks():
        """Every grid-aligned block holding at least one world object.

        No type-id filter and no tiers. What makes a block a machine is what
        the server says when you query it. Both object lists count (0x000f
        blocks and 0x0021 functional objects); off-grid objects are dropped
        items and are still skipped."""
        by_block = {}
        for o in world.values():
            if o["x"] % P.COORD_BASE or o["y"] % P.COORD_BASE:
                continue                      # off-grid = a dropped item
            by_block.setdefault((o["bx"], o["by"], o["bz"]), []).append(o)
        return by_block

    def probe_blocks(by_block, reach=1):
        """Blocks worth a 0x0014 query: every occupied block and its z-neighbours.

        Objects and blocks are separate address spaces. Querying the coordinate
        an object was REPORTED at almost never answers — measured 3/194 — while
        querying its z-neighbours answers 201/582, and that is where the machines
        turn up: a row of vends read as z=97 while their goods are listed at
        z=96/98. So the neighbours are the point, not a fallback."""
        probes = set()
        for bx, by, bz in by_block:
            for dz in range(-reach, reach + 1):
                if bz + dz >= 0:
                    probes.add((bx, by, bz + dz))
        return sorted(probes)

    def neighbourhood(block, by_block, reach=1):
        """Objects on a block and its z-neighbours. A machine's own coordinate
        holds nothing, so its goods are the only evidence it exists."""
        bx, by, bz = block
        objs = []
        for dz in range(-reach, reach + 1):
            objs += by_block.get((bx, by, bz + dz), ())
        return objs

    def query_block(bx, by, bz, timeout=3.0):
        """tx 0x0014 — ask what is at a block. Not an interaction: no dialog is
        opened, nothing is spent, and other players are not notified (unlike
        0x000a). Returns the reply dict or None."""
        qwait["block"] = (bx, by, bz)
        qwait["reply"] = None
        qwait["event"].clear()
        send(P.build_block_query(bx, by, bz))
        qwait["event"].wait(timeout)
        qwait["block"] = None
        return qwait["reply"]

    def open_object(guid, timeout=2.0):
        """tx 0x000e + guid -> the object's contents (a mannequin's outfit).
        Read-only: no dialog, nothing spent. Returns a parse_inventory dict or
        None. NOTE the guid must be the BLOCK guid from a 0x0014 query, not the
        0x000f object guid — blocks and objects are separate address spaces, and
        the server only answers 0x000e for the block guid."""
        mwait["guid"] = guid
        mwait["inv"] = None
        mwait["event"].clear()
        send(P.build_query_object(guid))
        mwait["event"].wait(timeout)
        mwait["guid"] = None
        return mwait["inv"]

    def read_mannequin_at(bx, by, bz, reach=1):
        """Read a mannequin's outfit at a block: 0x0014 to get the block guid
        (a mannequin reads kind=20), then 0x000e to open it. Tries the exact
        block then z-neighbours (object coords don't always match the block).
        Returns (inv_dict_or_None, (bx,by,bz) used)."""
        offs = [0] + [d for r in range(1, reach + 1) for d in (-r, r)]
        for dz in offs:
            if bz + dz < 0:
                continue
            rep = query_block(bx, by, bz + dz, timeout=1.2)
            if rep and rep.get("guid"):
                inv = open_object(rep["guid"])
                if inv is not None:
                    return inv, (bx, by, bz + dz)
        return None, None

    def open_and_cancel(machine_guid, timeout=3.0):
        """tx 0x010f to open an object, read the dialog, then ALWAYS cancel.

        The confirm byte (1) is what spends currency; this only ever sends 0."""
        dwait["active"] = True
        dwait["dialog"] = None
        dwait["event"].clear()
        try:
            send(P.build_use_object(machine_guid))
            dwait["event"].wait(timeout)
            d = dwait["dialog"]
            if d:
                send(P.build_dialog_response(d["guid"], False))   # cancel
            return d
        finally:
            dwait["active"] = False

    def bump_hit(bx, by, bz, answer=None, timeout=2.5, at_block=False):
        """Hit a plot bumper at block (bx,by,bz) and read the rent dialog.

        Sends the trigger pair (tx 0x00d9 position, then tx 0x00d7 the target
        block), waits for the server's rx 0x00ca, and classifies it via
        P.classify_rent_dialog. `answer` controls what we send back:
          None  -> ALWAYS cancel (answer NO) — safe probe, never rents/spends
          True  -> confirm (YES) ONLY when the plot is 'available' (rents, spends
                   10 Cubits); any other kind is cancelled instead
          False -> cancel explicitly
        `at_block` decides what the 0x00d9 frame reports as our position:
          False -> our CURRENT tracked position (must be parked on/near the bumper)
          True  -> the BUMPER BLOCK's own coords, so we 'virtually stand on' it and
                   can interact from anywhere — IF the server trusts this frame and
                   does not range-check our real position. Test with 'bumphit … far'.
        Returns {dialog, kind, seconds_left, owner, rented(bool)} or None on no reply."""
        if at_block:
            px, py, pz = (bx * P.COORD_BASE, by * P.COORD_BASE, bz * P.COORD_BASE)
            heading = P.BUMP_FACING
        else:
            px, py, pz = pos["x"], pos["y"], pos["z"]
            heading = pos.get("heading", P.BUMP_FACING)
        dwait["active"] = True
        dwait["dialog"] = None
        dwait["event"].clear()
        try:
            send(P.build_bump_pos(px, py, pz, heading))
            send(P.build_bump_hit(bx, by, bz))
            dwait["event"].wait(timeout)
            d = dwait["dialog"]
        finally:
            dwait["active"] = False
        if not d:
            return None
        info = P.classify_rent_dialog(d["title"], d["text"])
        rented = False
        if answer is True and info["kind"] == "available":
            send(P.build_dialog_response(d["guid"], True))        # YES — spends
            rented = True
        else:
            send(P.build_dialog_response(d["guid"], False))       # cancel/NO
        info.update({"dialog": d, "rented": rented})
        return info

    def describe_offer(off):
        if off.get("item"):
            return (f"SELLS {off['qty']} x {off['item']} for "
                    f"{off['price']} {off['currency']}")
        return f"price {off['price']} {off['currency']} (item not named)"

    def open_and_buy(machine_guid, order, timeout=None):
        """Open a machine, read its offer, and CONFIRM the purchase (confirm
        byte 1 — the byte that spends) only if the offer clears every guard.
        Any offer that fails a guard re-sends cancel (byte 0), so the wallet is
        never touched. Returns {outcome, offer, ...} where outcome is:
          no_dialog | no_offer | wrong_item | too_expensive | over_budget |
          insufficient_funds | bought | insufficient | notice | timeout
        """
        timeout = timeout if timeout is not None else args.dialog_timeout
        dwait["active"] = True
        dwait["dialog"] = None
        dwait["event"].clear()
        try:
            send(P.build_use_object(machine_guid))
            dwait["event"].wait(timeout)
            d = dwait["dialog"]
        finally:
            dwait["active"] = False
        if not d:
            return {"outcome": "no_dialog", "offer": None}
        off = P.parse_vending_offer(d["text"])

        def cancel(outcome):
            send(P.build_dialog_response(d["guid"], False))
            return {"outcome": outcome, "offer": off, "dialog_text": d["text"]}

        if not off or off.get("price") is None or not off.get("item"):
            return cancel("no_offer")
        price = off["price"]
        needle = (order.get("item") or "").lower()
        if needle and needle not in off["item"].lower():
            return cancel("wrong_item")
        if order.get("max_price") is not None and price > order["max_price"]:
            return cancel("too_expensive")
        if order.get("budget") is not None and \
                order.get("spent", 0) + price > order["budget"]:
            return cancel("over_budget")
        # Advisory funds pre-check — the server is the real guard (0x00de).
        if wallet["cubits"] is not None and price > wallet["cubits"]:
            return cancel("insufficient_funds")
        # Auto-snipe value gate: only fires for the synthetic snipe order, and
        # only once the REAL item name is in hand. Refuses to spend unless the
        # item's community-price average clears min_avg (and is priced in
        # cubits). An item with no known community value is refused outright.
        if order.get("autosnipe"):
            why = snipe_reject(off["item"], price, off.get("currency"))
            if why:
                return cancel(why)
        # All guards passed — spend.
        buywait["active"] = True
        buywait["result"] = None
        buywait["text"] = None
        buywait["event"].clear()
        try:
            send(P.build_dialog_response(d["guid"], True))
            buywait["event"].wait(timeout)
            res = buywait["result"]
        finally:
            buywait["active"] = False
        out = {"offer": off, "dialog_text": d["text"], "price": price}
        if res == "bought":
            out["outcome"] = "bought"
        elif res == "insufficient":
            out["outcome"] = "insufficient"
        elif res == "notice":
            out["outcome"] = "notice"
            out["notice"] = buywait["text"]
        else:
            out["outcome"] = "timeout"
        return out

    def matching_order(off):
        """First active order this offer could satisfy, or None. Price is checked
        here; the item name is only checked when the offer ALREADY carries one (a
        purchase dialog). A query-priced offer has item=None — it is treated as a
        price-only candidate and the item is verified later, when open_and_buy
        reads the actual purchase dialog. This is what lets an order act on a
        machine that phase 1 priced from the block query and never opened."""
        if not off or off.get("price") is None:
            return None
        item = (off.get("item") or "").lower()
        for o in buy_orders:
            if not o.get("active", True):
                continue
            if o.get("max_price") is not None and off["price"] > o["max_price"]:
                continue
            needle = (o.get("item") or "").lower()
            if needle and item and needle not in item:
                continue
            return o
        # No explicit order matched — fall back to the always-on auto-snipe rule.
        # It fires purely on price here (<= steal_max, priced in cubits); the
        # community-VALUE gate is enforced in open_and_buy once the real item
        # name is read, so a query-priced offer with no item name still qualifies
        # to be opened and verified. Currency is known even on query offers.
        if autosnipe["on"] and off["price"] <= autosnipe["steal_max"] \
                and (off.get("currency") or "").lower()[:5] == "cubit":
            return autosnipe["order"]
        return None

    def try_fill_order(machine_guid, off):
        """If a standing order wants this offer, buy it (open_and_buy re-checks
        every guard and spends when they pass). Updates the order's tallies."""
        o = matching_order(off)
        if o is None or machine_guid in o["dedup"]:
            return
        res = open_and_buy(machine_guid, o)
        oc = res["outcome"]
        snipe = o.get("autosnipe")
        # Don't reopen the same machine again once we've acted on it. For a snipe
        # that also means a machine we opened and judged NOT a steal (wrong
        # currency, or community value too low/unknown) — dedup it so a low-value
        # 1c item isn't reopened on every future scan.
        if oc in ("bought", "insufficient", "notice", "timeout",
                  "snipe_wrong_currency", "snipe_low_value"):
            o["dedup"].add(machine_guid)
        bal = f" (bal {wallet['cubits']})" if wallet["cubits"] is not None else ""
        label = "snipe" if snipe else f"buy:{o['item']}"
        # A snipe that DIDN'T fire is routine (most 1c items aren't valuables) —
        # keep it in the verbose log only. A real buy is always surfaced.
        report = show_line if (oc == "bought" or not snipe) else vlog
        report(f"  [{label}] {oc.upper()}: {describe_offer(off)}{bal}")
        if oc == "bought":
            if snipe:
                _realm = state.get("realm")
                if not _realm:
                    _owner = state.get("realm_owner")
                    _realm = f"{_owner}'s realm" if _owner else "an unknown realm"
                _av = community_avg(off["item"])
                _flds = [("Item", off["item"], True),
                         ("Paid", f"{res['price']}c", True),
                         ("Realm", _realm, True)]
                if _av:
                    _flds.append(("Community value", f"~{_fmt_num(_av)}c", True))
                if wallet["cubits"] is not None:
                    _flds.append(("Balance", f"{wallet['cubits']}c", True))
                discord_notify(
                    "\U0001F3AF Snipe snagged!",
                    f"Bought a mis-listed **{off['item']}**.",
                    event="snipe", color=0x35C46B, fields=_flds)
            o["spent"] = o.get("spent", 0) + res["price"]
            o["bought"] = o.get("bought", 0) + 1
            if o.get("qty") is not None and o["bought"] >= o["qty"]:
                o["active"] = False
                show_line(f"  [buy:{o['item']}] filled {o['bought']}x "
                          f"(spent {o['spent']}) — order complete")
            elif o.get("budget") is not None and o["spent"] >= o["budget"]:
                o["active"] = False
                show_line(f"  [buy:{o['item']}] budget {o['budget']} reached "
                          f"(spent {o['spent']}) — order complete")
            save_buy_orders()
        elif oc == "insufficient":
            o["active"] = False
            show_line(f"  [buy:{o['item']}] server refused — not enough Cubits; "
                      f"order stopped")
            save_buy_orders()
        elif oc in ("notice", "timeout"):
            # dedup changed (machine marked as acted-on) — persist it
            save_buy_orders()

    def fill_orders_here(report=True):
        """Run active buy orders against every machine ALREADY known in this
        realm (from any prior scan), not just ones a scan happens to re-open.
        This is the robust path: a machine priced from the block query, or
        carried over from an earlier scan, is skipped by phase 2 and may never be
        re-opened — but it still sits in `offers`, so act on it directly here.
        Returns the number of machines that matched an active order. The
        always-on auto-snipe rule counts as an active order here too, so this
        still sweeps for giveaways even when no explicit buy order exists."""
        if not buy_orders and not autosnipe["on"]:
            if report:
                show_line("  no buy orders — 'buy <item> under <price>' first.")
            return 0
        here = state.get("realm")
        known = [(mg, e) for mg, e in list(offers.items())
                 if e.get("realm") == here and e.get("offer")]
        matched = [(mg, e) for mg, e in known
                   if matching_order(e["offer"]) is not None]
        if report:
            show_line(f"  buy: {len(known)} machine(s) known in "
                      f"'{here or '?'}', {len(matched)} match active orders.")
            if known and not matched:
                show_line("       none match — check the item name/price with "
                          "'machines'. Names match as a substring.")
        for mg, e in matched:
            try_fill_order(mg, e["offer"])
        return len(matched)

    def fill_player_orders_here(report=False):
        """Run every OPEN player order (cc_orders / odb) against the machines
        known in this realm, exactly like fill_orders_here does for the owner's
        orders — but each buy spends the ORDER'S player balance. Reuses
        open_and_buy (which re-checks item+price against the real dialog and
        spends the bot's physical wallet); on 'bought' it debits that player's
        ledger via record_purchase, so the pooled wallet and the sum of balances
        stay in step. One (order, machine) pair is only ever tried once."""
        if odb is None:
            return 0
        here = state.get("realm")
        known = [(mg, e) for mg, e in list(offers.items())
                 if e.get("realm") == here and e.get("offer")]
        try:
            open_rows = odb.open_orders()
        except Exception as ex:
            show_line(f"  [orders] couldn't read open orders: {ex}")
            return 0
        if report:
            show_line(f"  player orders: {len(open_rows)} open, "
                      f"{len(known)} machine(s) known in '{here or '?'}'.")
        bought = 0
        for row in open_rows:
            oid = row["id"]
            name = row["account"]                 # normalised account key
            needle = (row["item_query"] or "").lower()
            for mg, e in known:
                if (oid, mg) in player_dedup:
                    continue
                off = e.get("offer")
                if not off or off.get("price") is None:
                    continue
                if off["price"] > row["max_unit_price"]:
                    continue
                oitem = (off.get("item") or "").lower()
                if needle and oitem and needle not in oitem:
                    continue
                # Pre-check the PLAYER's ledger before spending real cubits.
                try:
                    if odb.balance(name) < off["price"]:
                        continue
                except Exception:
                    continue
                # Reuse the owner engine: it re-reads the dialog, re-checks the
                # item name + price ceiling, and spends the physical wallet.
                res = open_and_buy(mg, {"item": row["item_query"],
                                        "max_price": row["max_unit_price"]})
                player_dedup.add((oid, mg))
                oc = res.get("outcome")
                show_line(f"  [order#{oid} {name}] {oc.upper()}: "
                          f"{describe_offer(off)}")
                if oc == "bought":
                    try:
                        odb.record_purchase(oid, res["price"],
                                            idem_key=f"ord{oid}-m{mg}")
                        bought += 1
                    except cc_orders.OrderError as ex:
                        # Physical cubits were spent but the ledger refused — a
                        # discrepancy the operator must reconcile. Shout about it.
                        show_line(f"  [order#{oid}] ⚠ LEDGER MISMATCH after a "
                                  f"real purchase: {ex}")
                    cur = odb.get_order(oid)
                    if not cur or cur["status"] != cc_orders.S_OPEN:
                        break                     # order filled — stop scanning
        return bought

    # ---- auto-trade: hands-off deposits (Stage 10) -----------------------
    def _credit_deposit(tr, tg):
        """The trade committed — credit the depositor's escrow balance with what
        they staked. Idempotent on the trade GUID; guarded by an actual wallet
        increase so a trade that didn't move money is never credited.

        Returns True when this pending record is finished, or False while it
        must remain queued for a later wallet 0x0011 broadcast."""
        if odb is None or tr.get("credited"):
            return True
        amt = int(tr.get("staked") or 0)
        if amt <= 0:
            return True
        wb = tr.get("wallet_before")
        current = wallet["cubits"]
        if wb is None or current is None or current < wb + amt:
            return False
        try:
            bal = odb.deposit(tr["name"], amt, idem_key=f"trade:{tg}",
                              guid=tr.get("their_guid") or None,
                              note=f"trade deposit {tg[:8]}")
            tr["credited"] = True
            show_line(f"  [trade] CREDITED {tr['name']}: +{amt} cubits "
                      f"(balance {bal}).")
            return True
        except cc_orders.OrderError as e:
            if "duplicate transaction" in str(e).lower():
                tr["credited"] = True
                return True
            show_line(f"  [trade] credit failed for {tr['name']}: {e}")
            return True

    def _retry_pending_trade_credits():
        """Wallet updates can arrive after rx 0x00ac (observed live). Retry every
        committed deposit and retain it until the physical Cubits are visible."""
        for tg, tr in list(pending_trade_credits.items()):
            if _credit_deposit(tr, tg):
                pending_trade_credits.pop(tg, None)
        for tg, tr in list(pending_withdraw_debits.items()):
            if _debit_withdrawal(tr, tg):
                pending_withdraw_debits.pop(tg, None)

    def _debit_withdrawal(tr, tg):
        """A withdrawal trade committed — debit the player's ledger by the amount we
        staked, but ONLY once the bot's physical wallet has actually dropped by at
        least that much (so a payout is never recorded for cubits that didn't leave).
        Idempotent on the trade GUID. Returns True when finished, False while it must
        stay queued for a later wallet 0x0011 broadcast."""
        if odb is None or tr.get("debited"):
            return True
        amt = int(tr.get("withdraw") or 0)
        if amt <= 0:
            return True
        wb = tr.get("wallet_before")
        current = wallet["cubits"]
        if wb is None or current is None or current > wb - amt:
            return False                # wallet hasn't dropped by `amt` yet
        try:
            bal = odb.payout(tr["name"], amt, idem_key=f"withdraw:{tg}",
                             note=f"withdrawal via trade {tg[:8]}")
            tr["debited"] = True
            pending_withdrawals.pop(cc_orders.normalize_name(tr["name"]), None)
            show_line(f"  [trade] WITHDRAWN to {tr['name']}: -{amt} cubits "
                      f"(balance {bal}).")
            return True
        except cc_orders.OrderError as e:
            if "duplicate transaction" in str(e).lower():
                tr["debited"] = True
                return True
            show_line(f"  [trade] withdrawal debit failed for {tr['name']}: {e}")
            return True

    trade_credit_retry["fn"] = _retry_pending_trade_credits

    def _trade_phase_message(tg, tr, phase):
        """Build ``phase`` with the same candidate profile selected at open."""
        candidates = P.trade_accept_candidates(
            tg, tr.get("their_guid", ""), tr.get("token", ""),
            our_cubits=0, phase=phase)
        by_label = dict(candidates)
        label = tr.get("accept_label")
        if label not in by_label:
            raise ValueError(f"unknown trade state profile {label!r}")
        return by_label[label]

    def _accept_worked(tg, via):
        """The server proved the ACCEPT + final-YES profile for trade ``tg``.
        Record it so probe mode stops and every future deposit reuses it."""
        tr = trades.get(tg)
        label = tr.get("accept_label") if tr else None
        if not label and probe.get("last") and probe["last"].get("guid") == tg:
            label = probe["last"]["label"]
        if not label:
            return
        if probe["winner"] != label:
            probe["winner"] = label
            probe["on"] = False
            save_trade_accept()
            show_line(f"  [trade] ✅ ACCEPT WORKED — server sent {via}. Winning "
                      f"profile: '{label}'. Saved to trade_accept.json; automatic "
                      f"probing is now off.")

    def handle_trade_request(body):
        """rx 0x00a8 — a player opened a trade. Record it and wait for Cubits.

        The server has already opened the window. Do not send an OPEN packet:
        live testing showed that the extra packet resets the trade. Select a
        profile now, but send its first packet only after a positive offer."""
        if WORKER_SILENT:                     # worker role never trades/registers
            return
        if not autotrade["on"] or odb is None:
            return
        req = P.parse_trade_request(body)
        if not req or not req.get("name"):
            return
        tg = req["trade_guid"]
        trades[tg] = {"name": req["name"], "their_guid": req["their_guid"],
                      "token": req.get("token", ""),
                      "staked": 0, "our_cubits": 0, "confirmed": False,
                      "offer_seen": False, "accept_sent": False,
                      "accept_acknowledged": False, "accept_state": None,
                      "offer_signature": None, "reaccepts": 0,
                      "attempted_labels": set(),
                      "credited": False, "wallet_before": wallet["cubits"],
                      "accept_label": None}
        # Asking for the ACCEPT phase gives us the same stable profile labels
        # while making it explicit that no OPEN phase is transmitted here.
        cands = P.trade_accept_candidates(tg, req["their_guid"],
                                          req.get("token", ""), phase="accept")
        by_label = dict(cands)
        if probe["on"]:
            i = probe["idx"] % len(cands)
            label, _ = cands[i]
            probe["last"] = {"guid": tg, "label": label, "idx": i}
            probe["idx"] = i + 1
            show_line(f"  [trade/probe] {req['name']} opened a trade — armed "
                      f"state profile #{i + 1}/{len(cands)} '{label}' "
                      f"and waiting for Cubits (no packet sent yet).")
        elif probe["winner"] and probe["winner"] in by_label:
            label = probe["winner"]
            show_line(f"  [trade] {req['name']} opened a trade — waiting for "
                      f"Cubits (known-good profile '{label}').")
        else:
            label, _ = cands[0]
            show_line(f"  [trade] {req['name']} opened a trade — waiting for "
                      f"Cubits ('{label}', UNVERIFIED; run 'autotrade probe on' "
                      f"to find the working button shape).")
        trades[tg]["accept_label"] = label
        trades[tg]["attempted_labels"].add(label)
        # WITHDRAWAL: if this player asked to withdraw, stake their cubits now and
        # click Accept. The YES is gated on the server echoing exactly this amount
        # (handle_trade_dialog), so a wrong stake can never pay out.
        wname = cc_orders.normalize_name(req["name"])
        wamt = pending_withdrawals.get(wname)
        if wamt:
            avail = odb.available(req["name"])
            wamt = min(int(wamt), int(avail))
            if wamt <= 0:
                pending_withdrawals.pop(wname, None)
                show_line(f"  [trade] {req['name']} has a withdrawal but no "
                          f"available balance now — treating as a normal trade.")
            else:
                tr = trades[tg]
                tr["withdraw"] = wamt
                tr["wallet_before"] = wallet["cubits"]
                # Consume the request now so a second concurrent trade can't reuse
                # it (each 'withdraw' is single-use; re-ask if the trade falls through).
                pending_withdrawals.pop(wname, None)
                show_line(f"  [trade] {req['name']} is WITHDRAWING {wamt}c — "
                          f"staking it and clicking Accept.")
                try:
                    send(P.build_trade_offer(tg, wamt))           # stake our cubits
                    send(_trade_phase_message(tg, tr, "accept"))  # click Accept
                    tr["accept_sent"] = True
                except Exception as e:
                    show_line(f"  [trade] withdrawal stake/accept failed: "
                              f"{type(e).__name__}: {e}")

    def handle_trade_pending(body):
        """rx 0x0036 'Trade Pending'/'Waiting for your partner' — the server's ack
        that the required button clicks went through. Attribute it to the in-flight trade
        so the probe can record the winning state profile."""
        via = "rx 0x0036 'Trade Pending'"
        tg = None
        if probe.get("last"):
            tg = probe["last"].get("guid")
        if tg not in trades and tg not in pending_trade_credits:
            tg = next((k for k, v in trades.items() if v.get("confirmed")), None)
        if tg is None:
            tg = next(iter(trades), None)
        if tg:
            _accept_worked(tg, via)
        else:
            show_line(f"  [trade] {via} (no trade in flight to attribute).")

    def _schedule_trade_accept(tg, reason, delay):
        """Schedule one ACCEPT click for the current unchanged positive offer."""
        tr = trades.get(tg)
        if (not tr or tr.get("confirmed") or tr.get("confirming")
                or tr.get("accept_sent") or int(tr.get("staked") or 0) <= 0
                or int(tr.get("our_cubits") or 0) != 0):
            return
        old = tr.get("accept_timer")
        if old is not None:
            old.cancel()
        amount = int(tr["staked"])

        def _fire(tgg=tg, amt=amount, why=reason):
            current = trades.get(tgg)
            if current:
                current["accept_timer"] = None
            if (not current or current.get("confirmed")
                    or current.get("confirming") or current.get("accept_sent")
                    or int(current.get("staked") or 0) != amt
                    or int(current.get("our_cubits") or 0) != 0):
                return
            show_line(f"  [trade] {current['name']}'s {amt}-cubit offer {why} "
                      f"— clicking ACCEPT ('{current.get('accept_label')}').")
            try:
                send(_trade_phase_message(tgg, current, "accept"))
                current["accept_sent"] = True
            except Exception as e:
                show_line(f"  [trade] ACCEPT send failed: "
                          f"{type(e).__name__}: {e}")

        timer = threading.Timer(delay, _fire)
        timer.daemon = True
        tr["accept_timer"] = timer
        timer.start()

    def handle_trade_accept_state(body):
        """React when the server clears a previously accepted trade.

        The recording shows Accepted! -> deciding dots -> Accept Trade while the
        Cubit amount stays fixed. That transition is rx 0x00a9 state 0, not an
        0x00ae amount change. Re-click only if a nonzero accepted state was seen
        first; this avoids retry loops when an invalid probe packet is rejected
        immediately with state 0.
        """
        state = P.parse_trade_accept_state(body)
        if not state:
            return
        tr = trades.get(state["trade_guid"])
        if not tr:
            return
        previous = tr.get("accept_state")
        tr["accept_state"] = state["state"]
        if state["state"] != 0:
            if tr.get("accept_sent"):
                tr["accept_acknowledged"] = True
            return
        was_accepted = bool(tr.get("accept_acknowledged") or
                            (previous is not None and previous != 0))
        if (not tr.get("accept_sent") or tr.get("confirmed")
                or tr.get("confirming")):
            return
        if not was_accepted:
            # The candidate did not produce Accepted! at all. While probing,
            # advance immediately to the next empty-side button layout instead
            # of requiring the user to close and reopen the trade seven times.
            if probe["on"] and not probe.get("winner"):
                candidates = P.trade_accept_candidates(
                    state["trade_guid"], tr.get("their_guid", ""),
                    tr.get("token", ""), our_cubits=0, phase="accept")
                attempted = tr.setdefault("attempted_labels", set())
                next_choice = next(((i, label) for i, (label, _) in
                                    enumerate(candidates)
                                    if label not in attempted), None)
                if next_choice is None:
                    show_line(f"  [trade/probe] all {len(candidates)} safe "
                              f"ACCEPT shapes returned state 0; reopen the "
                              f"trade after we inspect this log.")
                    return
                i, label = next_choice
                attempted.add(label)
                tr["accept_label"] = label
                tr["accept_sent"] = False
                tr["accept_acknowledged"] = False
                probe["last"] = {"guid": state["trade_guid"],
                                 "label": label, "idx": i}
                probe["idx"] = i + 1
                show_line(f"  [trade/probe] '{tr['name']}' was not accepted by "
                          f"the previous shape (server state 0); trying "
                          f"#{i + 1}/{len(candidates)} '{label}' in the same "
                          f"open trade.")
                _schedule_trade_accept(state["trade_guid"],
                                       "needs the next button shape",
                                       REACCEPT_DELAY_SECS)
            return
        # The bot ACCEPTED, then the state cleared with the Cubit amount UNCHANGED.
        # This is the paired-accept handshake: the other player is toggling their
        # own accept. rx 0x00a9 carries a single shared state byte with no player
        # id, so we cannot tell whose accept cleared — and re-clicking here starts a
        # war (our re-accept is a change that clears THEIR accept, they re-accept,
        # we see state 0 again, ...). So DO NOT re-click on a bare clear. Hold our
        # accept as sent and wait: the confirm dialog fires once both sides are
        # accepted at the same moment. Only a real OFFER change (handled in
        # handle_trade_offer) re-arms a single fresh ACCEPT.
        tr["accept_acknowledged"] = False
        tr["reaccepts"] = int(tr.get("reaccepts") or 0) + 1
        show_line(f"  [trade] {tr['name']}'s acceptance cleared (state "
                  f"{previous}->0, Cubits unchanged) — HOLDING, not re-clicking "
                  f"(that would reset your accept). Click Accept on your side; the "
                  f"confirm dialog fires when both are accepted together.")

    def handle_trade_offer(body):
        """rx 0x00ae — the stake on the table changed. Record what they put in, and
        once the amount settles, send the distinct ACCEPT phase."""
        off = P.parse_trade_offer(body)
        if not off:
            return
        if off["trade_guid"] == last_trade.get("guid"):   # keep manual view fresh
            last_trade["staked"] = off["their_cubits"]
            last_trade["our"] = off["our_cubits"]
        tr = trades.get(off["trade_guid"])
        if tr is None:
            return
        tr["staked"] = off["their_cubits"]
        tr["our_cubits"] = off["our_cubits"]
        tr["offer_seen"] = True
        if tr.get("withdraw"):
            # WITHDRAWAL: the bot already staked its side and clicked Accept in
            # handle_trade_request. Just keep our_cubits current for the confirm
            # gate; never run the deposit accept/debounce logic (our side is meant
            # to be non-empty here), and never reset accept_sent.
            return
        previous = tr.get("offer_signature")
        signature = (off["our_cubits"], off["their_cubits"], off["flag"])
        changed = previous is not None and previous != signature
        tr["offer_signature"] = signature
        if changed:
            tr["accept_sent"] = False
            tr["accept_acknowledged"] = False

        if off["our_cubits"] != 0:
            show_line(f"  [trade] NOT accepting {tr['name']} — my side isn't "
                      f"empty (our_cubits={off['our_cubits']}).")
            return
        if off["their_cubits"] > 0:
            # Only restart the debounce when the actual offer tuple changes.
            # Identical retransmissions no longer postpone ACCEPT forever.
            if (previous is None or changed or
                    (not tr.get("accept_sent") and tr.get("accept_timer") is None)):
                _schedule_trade_accept(off["trade_guid"], "settled",
                                       ACCEPT_SETTLE_SECS)

    def handle_trade_dialog(d):
        """The 'ARE YOU SURE?' confirm (0x00ca) for a trade we're in. Confirm it,
        but only after a matching, positive, empty-bot-side offer was accepted.

        The UI exposes one YES button, but the official capture sends two state
        messages after that click: CONFIRM, then COMMIT about 0.38s later."""
        tr = trades.get(d["guid"])
        if tr is None:
            return
        # The dialog proves OPEN + ACCEPT, but not the final state in this
        # button profile. Only rx 0x0036 records a reusable winner.
        if (not autotrade["on"] or tr.get("confirmed")
                or tr.get("confirming")):
            return
        amounts = [int(raw.replace(",", "")) for raw in
                   re.findall(r"([\d,]+)\s+Cubits\b", d.get("text", ""),
                              flags=re.IGNORECASE)]
        # WITHDRAWAL confirm — a strict, separate gate (the bot's side is NON-empty
        # here, so it can only ever click YES for an authorised, exactly-matched
        # payout). Every check must pass or we abort and give nothing away.
        wamt = int(tr.get("withdraw") or 0)
        if wamt:
            our = int(tr.get("our_cubits") or 0)
            their = int(tr.get("staked") or 0)
            avail = odb.available(tr["name"]) if odb else 0
            # The authoritative guard is the SERVER-echoed stake (our == wamt) with
            # the player staking nothing; that alone proves we're giving exactly the
            # authorised amount. The dialog text is a bonus check — the withdrawal
            # (giving) popup is worded differently and may not name the amount, so
            # only block on it if it shows a DIFFERENT number, never when empty.
            show_line(f"  [trade] withdrawal dialog text: {d.get('text','')!r}")
            reason = None
            if not tr.get("accept_sent"):
                reason = "accept not sent"
            elif our != wamt:
                reason = f"server shows my stake {our} != authorised {wamt}"
            elif their != 0:
                reason = f"they also staked {their} (expected 0)"
            elif amounts and amounts != [wamt]:
                reason = f"dialog names {amounts}, not {wamt}"
            elif wamt > avail:
                reason = f"{wamt} exceeds available {avail}"
            if reason:
                show_line(f"  [trade] NOT confirming withdrawal to {tr['name']} — "
                          f"{reason}.")
                return
            timer = tr.get("accept_timer")
            if timer is not None:
                timer.cancel()
            tr["wallet_before"] = wallet["cubits"]
            show_line(f"  [trade] confirming WITHDRAWAL to {tr['name']}: {wamt}c "
                      f"(clicking YES).")
            try:
                send(_trade_phase_message(d["guid"], tr, "confirm"))
                tr["confirmed"] = True     # mark now (no commit message exists)
                tr["confirming"] = False
            except Exception as e:
                tr["confirming"] = False
                show_line(f"  [trade] withdrawal confirm failed: "
                          f"{type(e).__name__}: {e}")
            return
        staked = int(tr.get("staked") or 0)
        if not tr.get("offer_seen") or not tr.get("accept_sent") or staked <= 0:
            show_line(f"  [trade] NOT confirming {tr['name']} — no positive, "
                      f"accepted Cubit offer is recorded.")
            return
        if int(tr.get("our_cubits") or 0) != 0:
            show_line(f"  [trade] NOT confirming {tr['name']} — my side isn't "
                      f"empty (our_cubits={tr['our_cubits']}).")
            return
        if amounts != [staked]:
            show_line(f"  [trade] NOT confirming {tr['name']} — dialog amounts "
                      f"{amounts} don't exactly match the {staked}-cubit offer.")
            return
        timer = tr.get("accept_timer")
        if timer is not None:
            timer.cancel()
        tr["wallet_before"] = wallet["cubits"]
        show_line(f"  [trade] confirming deposit from {tr['name']}: "
                  f"{staked} cubits (clicking YES).")
        try:
            send(_trade_phase_message(d["guid"], tr, "confirm"))
            # The proven flow has NO commit message (plaintext capture: only ACCEPT
            # then YES). Mark confirmed NOW — a delayed commit timer used to lose the
            # credit when the trade closed inside that window.
            tr["confirmed"] = True
            tr["confirming"] = False
        except Exception as e:
            tr["confirming"] = False
            show_line(f"  [trade] confirm send failed: {type(e).__name__}: {e}")

    def _settle_trade(tg, via):
        """A trade ended (close 0x00ac OR cancel 0x00ab — a completed deposit has
        been seen using either). Pop it and, if we confirmed, apply the ledger
        effect. Every money move stays guarded by the ACTUAL wallet change, so a
        genuine cancel that moved nothing never credits/debits."""
        if tg == last_trade.get("guid"):        # manual view: window is gone
            last_trade["open"] = False
        tr = trades.pop(tg, None)
        if not tr:
            return
        for k in ("accept_timer", "confirm_timer"):
            t = tr.get(k)
            if t is not None:
                t.cancel()
        if not tr.get("confirmed"):
            return
        show_line(f"  [trade] {tr['name']}'s trade ended ({via}); settling "
                  f"(wallet={wallet['cubits']}, before={tr.get('wallet_before')}).")
        if tr.get("withdraw"):
            pending_withdraw_debits[tg] = tr
            if _debit_withdrawal(tr, tg):
                pending_withdraw_debits.pop(tg, None)
            else:
                show_line(f"  [trade] {tr['name']}'s withdrawal: waiting for the "
                          f"wallet to drop before debiting {tr['withdraw']}c.")
        else:
            pending_trade_credits[tg] = tr
            if _credit_deposit(tr, tg):
                pending_trade_credits.pop(tg, None)
            else:
                show_line(f"  [trade] {tr['name']}'s deposit: waiting for the "
                          f"wallet to rise before crediting {tr['staked']}c.")

    def handle_trade_close(body):
        """rx 0x00ac — a trade window closed."""
        c = P.parse_trade_close(body)
        if not c:
            return
        tg = c["trade_guid"]
        if tg == "00" * 16:             # second UI-close notification, no trade id
            return
        _settle_trade(tg, "close 0x00ac")

    def handle_trade_cancel(body):
        """rx 0x00ab — a trade was cancelled/reset. A COMPLETED deposit has been
        observed ending here too, so settle the same way — the wallet-change guard
        makes a real cancel (no cubits moved) a no-op."""
        if len(body) < 20:
            return
        _settle_trade(body[4:20].hex(), "cancel 0x00ab")

    FIELDS = ["realm", "link", "x", "y", "z", "item", "qty", "price",
              "currency", "stock", "guid", "found_by", "text"]

    def by_realm_then_block(rec):
        return (rec.get("realm") or "", rec["block"])

    def machine_rows():
        """The scan's findings, one flat row per machine.

        Findings accumulate across realms — teleporting somewhere new doesn't
        throw away what the last realm sold — so every row carries its realm.

        This is what a dump is for. The raw object list is thousands of
        ordinary blocks and drowns the handful of vends, so it moved to
        `dump raw`."""
        rows = []
        for rec in sorted(offers.values(), key=by_realm_then_block):
            bx, by, bz = rec["block"]
            o = rec["offer"]
            # Same rule as the catalogue and the history DB: a 0 price is not a
            # sale. This is the chokepoint for the crawl log (crawl.csv), the
            # 'dump' command and the 'machines' listing, so filtering here keeps
            # every output consistent with what actually gets recorded.
            if unsellable(o.get("price")):
                continue
            rows.append({"realm": rec.get("realm"),
                         "link": link_for(rec.get("realm"),
                                          rec.get("realm_guid")),
                         "x": bx, "y": by, "z": bz,
                         "item": o.get("item"), "qty": o.get("qty"),
                         "price": o.get("price"), "currency": o.get("currency"),
                         "stock": o.get("stock"), "guid": rec["machine"],
                         "found_by": rec["how"], "text": rec["text"]})
        return rows

    def publish_realm(realm=None, guid=None):
        """Write THIS realm's vends into the persistent catalogue (vends.json),
        REPLACING whatever it held for this realm before — so a rescan refreshes
        the realm's list in place instead of piling up duplicates, while every
        other realm stays untouched. Keyed by realm name => a realm is never
        listed twice. Publishing an empty list is fine: it means 'rescanned,
        no machines now', which correctly clears out a stale entry."""
        realm = realm or state["realm"]
        guid = guid or reg["guid"]
        if not realm:
            return
        mine = [rec for rec in offers.values()
                if rec.get("realm_guid") == guid or rec.get("realm") == realm]
        # A realm with nothing to sell that we've never catalogued: don't clutter
        # the vends list with an empty entry (auto-Hollawarp scans lots of these).
        # But if it's ALREADY in the catalogue, still overwrite — a rescan that
        # now finds nothing must clear the stale entry.
        if not mine and realm not in vends:
            return
        machines = []
        zeros = 0
        for rec in sorted(mine, key=by_realm_then_block):
            o = rec["offer"]
            if unsellable(o.get("price")):
                zeros += 1
                continue
            # Block coords (x/y/z) and stock are intentionally NOT saved — they
            # don't matter for the catalogue and change per host anyway.
            machines.append({"item": o.get("item"), "qty": o.get("qty"),
                             "price": o.get("price"),
                             "currency": o.get("currency"),
                             "guid": rec["machine"], "text": rec["text"]})
        vends[realm] = {"guid": guid, "owner": state["realm_owner"],
                        "link": link_for(realm, guid),
                        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "machines": machines}
        save_vends()
        show_line(f"  catalogue: '{realm}' -> {len(machines)} machine(s) "
                  f"saved to vends.json ({len(vends)} realm(s) total)"
                  + (f"; skipped {zeros} priced 0" if zeros else ""))
        maybe_republish()

    def publish_scan_result(realm, guid, started_at, status, error,
                            observed_guids, probes_attempted, probes_answered):
        """Hand one finished scan to the market-history DB.

        Builds the observed-offer list from exactly the machines THIS scan saw
        (observed_guids), tagged with this realm's GUID, and lets cc_storage
        decide current-vs-history and whether an unseen listing may be removed
        (only for a 'completed' scan). No-op if the DB isn't open."""
        if mdb is None or not guid:
            return
        offer_list = []
        for g in observed_guids:
            rec = offers.get(g)
            if not rec or rec.get("realm_guid") != guid:
                continue
            o = rec.get("offer") or {}
            if unsellable(o.get("price")):
                continue
            bx, by, bz = rec.get("block", (None, None, None))
            offer_list.append({
                "machine_guid": g, "item": o.get("item"),
                "qty": o.get("qty"), "price": o.get("price"),
                "currency": o.get("currency"), "stock": o.get("stock"),
                "x": bx, "y": by, "z": bz,
            })
        try:
            mdb.publish_scan({
                "status": status, "realm_guid": guid, "realm_name": realm,
                "realm_owner": state["realm_owner"],
                "realm_link": link_for(realm, guid),
                "started_at": started_at, "source": "live_scan",
                "offers": offer_list, "error": error,
                "probes_attempted": probes_attempted,
                "probes_answered": probes_answered,
            })
            n = len(offer_list)
            extra = "" if status == "completed" else \
                f" (status={status}: unseen listings kept)"
            show_line(f"  history DB: recorded {status} scan of "
                      f"'{realm or guid[:8]}' — {n} offer(s){extra}")
        except Exception as e:
            show_line(f"  (couldn't record scan in history DB: {e})")

    # --- market-history terminal reports (read-only queries over mdb) --------
    def _fmt_price(p, cur=""):
        return f"{'?' if p is None else p} {cur}".strip()

    def _print_history(term, days=None):
        if mdb is None:
            print("  market history DB is not open")
            return
        best = mdb.cheapest_current(term)
        current = mdb.current_for_item(term)
        stats = mdb.item_price_stats(term)
        if not current and not stats and not mdb.item_history(term, days):
            print(f"  no history for '{term}'")
            return
        print(f"  history for '{term}':")
        if best:
            for cur, r in best.items():
                print(f"    cheapest CURRENT: {_fmt_price(r['price'], cur)} "
                      f"in {r['realm']} ({len(current)} active listing(s))")
        else:
            print(f"    no active listings ({len(current)} current)")
        for cur, s in stats.items():
            print(f"    [{cur or '?'}] min {s['min']}  max {s['max']}  "
                  f"avg {s['avg']}  median {s['median']}  "
                  f"({s['count']} obs)")
        pc = mdb.price_changes(hours=days * 24 if days else None, term=term)
        if pc:
            print(f"    {len(pc)} price change(s):")
            for r in pc[:8]:
                print(f"      {r['created_at'][:16]}  "
                      f"{r['old_price']} -> {r['new_price']} "
                      f"{r['new_currency'] or ''}  {r['realm'] or ''}")
        recent = mdb.item_history(term, days=days)
        if recent:
            print(f"    recent observations"
                  + (f" (last {days}d)" if days else "") + ":")
            for r in recent[:8]:
                print(f"      {r['observed_at'][:16]}  "
                      f"{_fmt_price(r['price'], r['currency'] or '')}  "
                      f"{(r['qty'] or 1)}x {r['item']}  @ {r['realm'] or '?'} "
                      f"[{r['event_type'] or 'obs'}]")

    def _print_changes(hours):
        if mdb is None:
            print("  market history DB is not open")
            return
        ch = mdb.changes(hours)
        total = sum(len(v) for v in ch.values())
        print(f"  changes in the last {hours}h — {total} event(s):")
        labels = [("added", "new listings"), ("removed", "removed"),
                  ("reappeared", "reappeared"), ("price_changed", "price"),
                  ("item_changed", "item"), ("quantity_changed", "quantity"),
                  ("stock_changed", "stock")]
        for key, label in labels:
            rows = ch.get(key, [])
            if not rows:
                continue
            print(f"    {label} ({len(rows)}):")
            for r in rows[:10]:
                if key == "price_changed":
                    detail = (f"{r['old_price']} -> {r['price']} "
                              f"{r['currency'] or ''}")
                elif key == "removed":
                    detail = f"was {_fmt_price(r['old_price'])}"
                else:
                    detail = _fmt_price(r['price'], r['currency'] or '')
                print(f"      {r['created_at'][:16]}  "
                      f"{r['item'] or r.get('old_item') or '?'}  {detail}  "
                      f"@ {r['realm'] or '?'}")
            if len(rows) > 10:
                print(f"      … and {len(rows) - 10} more")

    def _print_deals(term, max_price=None):
        if mdb is None:
            print("  market history DB is not open")
            return
        rows = mdb.current_for_item(term)
        rows = [r for r in rows if r["price"] is not None]
        if max_price is not None:
            rows = [r for r in rows if r["price"] <= max_price]
        rows.sort(key=lambda r: r["price"])
        cap = f" at or below {max_price}" if max_price is not None else ""
        if not rows:
            print(f"  no current listings for '{term}'{cap}")
            return
        print(f"  '{term}'{cap}: {len(rows)} current listing(s), cheapest "
              f"first:")
        for r in rows[:30]:
            link = f"  {r['link']}" if r.get("link") else ""
            print(f"    {str(r['price']):>7} {(r['currency'] or ''):<6} "
                  f"{(r['qty'] or 1)}x {(r['item'] or '?')[:28]:<28} "
                  f"@ {(r['realm'] or '?')[:22]}{link}")
        if len(rows) > 30:
            print(f"    … and {len(rows) - 30} more")

    def _print_scans(n):
        if mdb is None:
            print("  market history DB is not open")
            return
        rows = mdb.recent_scans(n)
        if not rows:
            print("  no scans recorded yet")
            return
        print(f"  last {len(rows)} scan(s):")
        for s in rows:
            probes = ""
            if s["probes_attempted"] is not None:
                probes = (f"  probes {s['probes_answered']}/"
                          f"{s['probes_attempted']}")
            err = f"  ! {s['error']}" if s["error"] else ""
            print(f"    #{s['id']} {(s['realm'] or s['realm_guid'] or '?')[:22]:<22} "
                  f"{s['status']:<11} {s['offers_found']} offer(s)  "
                  f"{(s['started_at'] or '')[:16]}{probes}{err}")

    def _print_scanstatus():
        if mdb is None:
            print("  market history DB is not open")
            return
        running = "yes" if scanning.is_set() else "no"
        s = mdb.scan_status()
        print(f"  scan running now: {running}"
              + (f" (realm '{state['realm']}')" if scanning.is_set() else ""))
        if not s:
            print("    no completed scans recorded yet")
            return
        print(f"    most recent recorded scan: #{s['id']} "
              f"'{s['realm'] or s['realm_guid']}' — {s['status']}")
        print(f"      started {s['started_at']}  completed "
              f"{s['completed_at'] or '(n/a)'}  {s['offers_found']} offer(s)")
        if s["probes_attempted"] is not None:
            print(f"      probes {s['probes_answered']}/"
                  f"{s['probes_attempted']}")
        if s["error"]:
            print(f"      error: {s['error']}")

    def _print_stale(hours):
        if mdb is None:
            print("  market history DB is not open")
            return
        rows = mdb.stale_current(hours)
        if not rows:
            print(f"  no realm catalogues older than {hours}h — all fresh")
            return
        print(f"  {len(rows)} realm catalogue(s) with no completed scan in "
              f"{hours}h:")
        for r in rows:
            last = r["last_completed"] or "never"
            print(f"    {(r['realm'] or r['realm_guid'])[:28]:<28} "
                  f"{r['current_offers']} listing(s)  last completed {last}")

    def _print_machine_history(guid):
        h = mdb.machine_history(guid)
        info = h["machine"]
        if not info and not h["observations"]:
            print(f"  no machine with guid {guid}")
            return
        if info:
            print(f"  machine {guid}")
            print(f"    realm {info['realm'] or info['realm_guid']}  "
                  f"at ({info['x']},{info['y']},{info['z']})")
        print(f"    {len(h['observations'])} observation(s):")
        for o in h["observations"][:20]:
            print(f"      {o['observed_at'][:16]}  "
                  f"{_fmt_price(o['price'], o['currency'] or '')}  "
                  f"{(o['qty'] or 1)}x {o['item']}  [{o['status']}]")
        print(f"    {len(h['events'])} event(s):")
        for e in h["events"][:20]:
            print(f"      {e['created_at'][:16]}  {e['event_type']}")

    def dump_machines(path):
        """Write the vends. .csv and .txt by extension, JSON otherwise."""
        rows = machine_rows()
        ext = os.path.splitext(path)[1].lower()
        with open(path, "w", encoding="utf-8", newline="") as fh:
            if ext == ".csv":
                w = csv.DictWriter(fh, fieldnames=FIELDS)
                w.writeheader()
                w.writerows(rows)
            elif ext == ".txt":
                seen, first = None, True
                for rec in sorted(offers.values(), key=by_realm_then_block):
                    if first or rec.get("realm") != seen:
                        seen = rec.get("realm")
                        url = link_for(seen, rec.get("realm_guid"))
                        fh.write(("" if first else "\n") + f"# {seen}"
                                 + (f"  {url}" if url else "") + "\n")
                        first = False
                    bx, by, bz = rec["block"]
                    fh.write(f"  ({bx},{by},{bz})  "
                             f"{describe_offer(rec['offer'])}\n")
            else:
                json.dump({"realm": state["realm"],
                           "owner": state["realm_owner"],
                           "machines": rows}, fh, indent=1, default=str)
        return len(rows)

    def _price_num(p):
        """A machine price (int, or a string like '1,499') as a float for
        sorting; None/garbage sorts to the very end."""
        if p is None:
            return float("inf")
        try:
            return float(str(p).replace(",", "").strip())
        except (ValueError, TypeError):
            return float("inf")

    def market_rows(term=None):
        """Every machine in the whole catalogue (vends.json) selling an item that
        matches `term` — case/spacing/punctuation-forgiving substring, so 'acorn
        pack' finds 'Acorn Backpack'. term None/empty = the entire catalogue.
        Returned cheapest-first, each row carrying its realm + share link."""
        key = _alnum(term) if term else ""
        rows = []
        for realm, e in vends.items():
            link = e.get("link") or link_for(realm, e.get("guid"))
            for m in e.get("machines", []):
                item = m.get("item")
                if not item:
                    continue
                # Also filtered on read, not just on write: a catalogue
                # collected before --keep-zero-price defaulted off still holds
                # 0-priced rows, and they must not reach the published site.
                if unsellable(m.get("price")):
                    continue
                if key and key not in _alnum(item):
                    continue
                rows.append({"item": item, "price": m.get("price"),
                             "currency": m.get("currency") or "",
                             "qty": m.get("qty"),
                             "realm": realm, "owner": e.get("owner") or "",
                             "link": link or "",
                             "updated": e.get("updated") or ""})
        rows.sort(key=lambda r: (_price_num(r["price"]), r["item"].lower()))
        return rows

    MARKET_FIELDS = ["item", "price", "currency", "qty", "realm",
                     "owner", "link", "updated"]

    def buy_travel():
        """Catalogue-wide buy. Finds every realm in the SAVED catalogue
        (vends.json — what past scans recorded across all ~220 realms) that has a
        listing matching an active order under its price, then crawls those
        realms. Each stop is a real join + scan, and the post-scan sweep buys the
        match on arrival. Stops early once every order is complete. Reuses
        crawl_run, so 'crawl stop' aborts it and --crawl-delay paces it."""
        active = [o for o in buy_orders if o.get("active", True)]
        if not active:
            print("  no active buy orders — add one with "
                  "'buy <item> under <price> [max N] [budget C]' first.")
            return
        if crawl["active"]:
            print("  a crawl is already running — 'crawl stop' first.")
            return
        seen, targets = set(), []
        for o in active:
            for r in market_rows(o["item"]):
                if o.get("max_price") is not None and \
                        _price_num(r["price"]) > o["max_price"]:
                    continue
                realm = r["realm"]
                g = (vends.get(realm, {}).get("guid")
                     or realm_ref(r.get("link") or ""))
                if not g or g in seen:
                    continue
                seen.add(g)
                targets.append((g, realm))
        if not targets:
            print("  no realm in the catalogue has a matching listing under "
                  "your price. ('market <item>' checks what's on record; the "
                  "catalogue only holds realms past scans saved.)")
            return
        capped = len(targets) > args.crawl_max
        targets = targets[:args.crawl_max]
        print(f"  buy travel: {len(targets)} realm(s) have a match"
              + (f" (capped at --crawl-max {args.crawl_max})" if capped else "")
              + f". Crawling — each is a full join+scan, buying on arrival, "
              f"paced {args.crawl_delay:.0f}s apart. 'crawl stop' aborts.")
        threading.Thread(target=crawl_run,
                         args=(targets, args.crawl_delay, args.crawl_file),
                         daemon=True).start()

    def export_market(path, term=None):
        """Write the catalogue (or a `term` search) to a file the user can share
        or browse. .csv = a flat spreadsheet; anything else = a self-contained,
        searchable, sortable HTML page (no external assets, works offline, realm
        links are clickable). Returns the row count."""
        rows = market_rows(term)
        ext = os.path.splitext(path)[1].lower()
        if ext == ".csv":
            with open(path, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=MARKET_FIELDS)
                w.writeheader()
                w.writerows(rows)
            return len(rows)
        # --- self-contained HTML (default) ---
        realms = len({r["realm"] for r in rows})
        title = (f"Cubic Castles market — '{term}'" if term
                 else "Cubic Castles market")
        payload = json.dumps(rows, ensure_ascii=False)
        html = _MARKET_HTML.replace("__TITLE__", _hesc(title)) \
            .replace("__ROWS__", str(len(rows))) \
            .replace("__REALMS__", str(realms)) \
            .replace("__WHEN__", time.strftime("%Y-%m-%d %H:%M")) \
            .replace("__DATA__", payload)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return len(rows)

    # Files a static web server may serve. This list is the whole security
    # story of `market publish`: every entry is DERIVED from the catalogue or
    # the history DB, so nothing here can contain a login token, a session key,
    # or an account id. Never add a raw project file to it — login_profile.json,
    # profile.json, captures/*.jsonl and spawns.jsonl all carry account
    # credentials or tie the accounts to activity, and none of them are needed
    # to show prices.
    pubstate = {"last": 0.0}

    def maybe_republish():
        """Refresh the hosted static site after a scan, when --publish-dir is
        set. Debounced: a crawl scans realm after realm and each publish
        rewrites ~12 MB, so refresh at most once per --publish-every seconds
        instead of once per realm. 'market publish' always writes immediately."""
        outdir = args.publish_dir
        if not outdir or args.publish_every <= 0:
            return
        now = time.time()
        if now - pubstate["last"] < args.publish_every:
            return
        pubstate["last"] = now
        try:
            files = publish_market(outdir)
        except Exception as e:
            show_line(f"  (couldn't refresh the published site: {e})")
        else:
            total = sum(sz for _, sz in files)
            show_line(f"  published site refreshed -> {outdir} "
                      f"({len(files)} files, {total:,} bytes)")

    def unsellable(price):
        """True when a listing must not be recorded because its price is 0.

        You cannot buy anything for 0 Cubits, so a 0 is never a real sale — it
        is an empty or idle vending slot, a display piece, or a blank the
        scanner read as 0. Recording them pollutes the catalogue and makes
        every 'cheapest' answer wrong, so they are dropped by default at both
        write points (vends.json and the history DB) and filtered out of the
        catalogue views. --keep-zero-price records them anyway.

        A NULL/None price is different: it means the scanner could not parse a
        price, not that the price is zero, so it is kept."""
        if args.keep_zero_price:
            return False
        try:
            return float(price) == 0
        except (TypeError, ValueError):
            return False               # None or unparseable — not a zero

    def public_stats():
        """mdb.stats() with the local filesystem stripped out. The raw dict
        carries db_path — an absolute path that names the Windows user and the
        folder layout — which must never reach a hosted file or a public
        route."""
        s = dict(mdb.stats())
        s.pop("db_path", None)
        return {"stats": s, "scan": mdb.scan_status()}

    def publish_market(outdir):
        """Write the public price site into `outdir` as plain static files, so
        a file server can host it with the bot switched off. Returns a list of
        (filename, bytes) written."""
        os.makedirs(outdir, exist_ok=True)
        rows = market_rows()
        written = []

        def _atomic(name, blob):
            """Write bytes to outdir/name without the file ever being visible
            half-written. A web server is reading this folder while we publish,
            and opening the real path 'w' truncates it first, so a request
            landing mid-write would get a partial file. Write a temp file beside
            it and rename: os.replace is atomic on POSIX and Windows, so readers
            see either the old file or the new one, never a torn one.

            Skips the write entirely when the bytes are unchanged — most scans
            change nothing, and rewriting ~12 MB every two minutes is pointless
            churn on the disk and on anything watching the folder."""
            p = os.path.join(outdir, name)
            try:
                with open(p, "rb") as fh:
                    if fh.read() == blob:
                        written.append((name, len(blob)))
                        return
            except OSError:
                pass                       # missing or unreadable — just write
            tmp = p + ".tmp"
            try:
                with open(tmp, "wb") as fh:
                    fh.write(blob)
                    fh.flush()
                    os.fsync(fh.fileno())  # survive a crash mid-publish
                # POSIX renames over an open file happily. Windows refuses
                # while a reader holds the destination, so retry briefly —
                # a web server's handle closes in milliseconds.
                for attempt in range(12):
                    try:
                        os.replace(tmp, p)
                        break
                    except PermissionError:
                        if attempt == 11:
                            # Still locked. Fall back to an in-place write so
                            # publishing degrades instead of failing; this is
                            # the non-atomic path, and only Windows reaches it.
                            with open(p, "wb") as fh:
                                fh.write(blob)
                            os.remove(tmp)
                            break
                        time.sleep(0.05)
            except OSError:
                try:
                    os.remove(tmp)         # don't leave .tmp litter in a served dir
                except OSError:
                    pass
                raise
            written.append((name, len(blob)))

        def put(name, text):
            _atomic(name, text.encode("utf-8"))

        realms = len({r["realm"] for r in rows})
        # Named market.html, not index.html, because a hosting folder usually
        # already has its own index.html and publishing must never clobber it.
        # Point --publish-page at index.html if this site owns the folder.
        put(args.publish_page or "market.html",
            _MARKET_HTML.replace("__TITLE__", "Cubic Castles market")
            .replace("__ROWS__", str(len(rows)))
            .replace("__REALMS__", str(realms))
            .replace("__WHEN__", time.strftime("%Y-%m-%d %H:%M"))
            .replace("__DATA__", json.dumps(rows, ensure_ascii=False)))
        put("market.json", json.dumps(rows, ensure_ascii=False))
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=MARKET_FIELDS)
        w.writeheader()
        w.writerows(rows)
        put("market.csv", buf.getvalue())
        if mdb is not None:
            put("changes.json", json.dumps(mdb.price_changes(hours=168),
                                           ensure_ascii=False, default=str))
        # vends.json is copied verbatim so the site serves the real catalogue
        # file, not only the reshaped view. It is safe: audited to hold realm
        # names, GUIDs, share links, owners and prices — the same public data
        # already in market.json, and no account fields. The original stays in
        # stage2/; the bot keeps reading and writing that one.
        # cubic_market.db is deliberately NOT here: it is live WAL SQLite, so a
        # visitor could download a torn copy mid-write. Use 'dbbackup' for that.
        try:
            with open(vends_path, "rb") as fh:
                _atomic(os.path.basename(vends_path), fh.read())
        except OSError:
            pass                           # not created yet — nothing to copy
        return written

    def query_many(blocks, timeout=30.0, quiet=0.5):
        """Fire a batch of block queries and collect the replies by coordinate.

        A query is one cheap round trip (~40ms in capture) and opens no dialog,
        so they pipeline instead of being waited on one at a time.

        The server simply never answers for a lot of blocks, so waiting for the
        full set always burned the whole timeout. Stop instead once nothing new
        has arrived for `quiet` seconds — the replies stream back while we are
        still sending, so a gap that long means the rest are not coming."""
        blocks = list(blocks)
        for b in blocks:
            qcache.pop(b, None)
        qwait["batch"] = True
        try:
            for i, (bx, by, bz) in enumerate(blocks, 1):
                if stop.is_set():
                    break
                send(P.build_block_query(bx, by, bz))
                if args.query_gap:
                    time.sleep(args.query_gap)
                if i % 250 == 0:
                    got = sum(1 for b in blocks if b in qcache)
                    print(f"           sent {i}/{len(blocks)}, {got} back")
            deadline = time.time() + timeout
            seen, last = sum(1 for b in blocks if b in qcache), time.time()
            while time.time() < deadline and not stop.is_set():
                got = sum(1 for b in blocks if b in qcache)
                if got == len(blocks):
                    break
                if got > seen:
                    seen, last = got, time.time()
                elif time.time() - last > quiet:
                    break
                time.sleep(0.05)
        finally:
            qwait["batch"] = False
        return {b: qcache.get(b) for b in blocks}

    def _report_signs(probes, dump_path=None):
        """Query a list of blocks and print/collect the ones that carry SIGN text
        (a 0x0014 reply whose text isn't a vending-machine description)."""
        if scanning.is_set():
            print("  a scan is already running — ctrl-c stops it")
            return
        probes = sorted(set(probes))
        if not probes:
            print("  nothing to probe")
            return
        print(f"  reading {len(probes)} block(s) for sign text ...")
        scanning.set()
        try:
            replies = query_many(probes)
        finally:
            scanning.clear()
        signs, seen = [], set()
        for b, rep in replies.items():
            if not (rep and rep.get("text")):
                continue
            txt = rep["text"].strip()
            if not txt or P.parse_vending_offer(txt):
                continue                     # blank, or a vending machine
            key = (b[0], b[1], txt)          # collapse z-neighbour duplicates
            if key in seen:
                continue
            seen.add(key)
            signs.append((b, txt))
        signs.sort()
        if not signs:
            print("  no sign text on any of those blocks")
            return
        print(f"  {len(signs)} sign(s) in {state.get('realm') or 'this realm'}:")
        for (bx, by, bz), txt in signs:
            print(f"    ({bx},{by},{bz})  {txt.replace(chr(10), ' / ')}")
        if dump_path:
            here = _APP_DIR
            path = (dump_path if os.path.isabs(dump_path)
                    else os.path.join(here, dump_path))
            try:
                if path.lower().endswith(".json"):
                    data = [{"x": bx, "y": by, "z": bz, "text": txt}
                            for (bx, by, bz), txt in signs]
                    with open(path, "w", encoding="utf-8") as fh:
                        json.dump({"realm": state.get("realm"), "signs": data},
                                  fh, indent=1, ensure_ascii=False)
                else:
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(f"# signs in {state.get('realm')}\n")
                        for (bx, by, bz), txt in signs:
                            fh.write(f"({bx},{by},{bz})\t{txt}\n")
                print(f"  wrote {len(signs)} sign(s) to {path}")
            except OSError as e:
                print(f"  couldn't write {path}: {e}")

    def _cube(cx, cy, cz, r):
        """Every block within `r` of (cx,cy,cz) (a (2r+1)-cube), clamped >= 0."""
        return [(cx + dx, cy + dy, cz + dz)
                for dx in range(-r, r + 1)
                for dy in range(-r, r + 1)
                for dz in range(-r, r + 1)
                if cx + dx >= 0 and cy + dy >= 0 and cz + dz >= 0]

    def read_signs_bulk(dump_path=None, reach=1, cap=12000):
        """Read signs by probing a `reach`-block neighbourhood around every
        OCCUPIED block (blocks holding a world object). Good for shops whose
        object list loaded; useless if the object stream is empty (then use
        'signs here', which probes around the bot instead)."""
        by_block = occupied_blocks()
        if not by_block:
            print("  no world objects loaded here, so nothing to probe around — "
                  "use 'signs here [r]' (probes around the bot) or stand next to "
                  "a sign and type 'sign'")
            return
        probes = set()
        for bx, by, bz in by_block:
            probes.update(_cube(bx, by, bz, reach))
        probes = sorted(probes)
        if len(probes) > cap:
            print(f"  {len(probes)} blocks — capping at {cap} (smaller reach, or "
                  f"'sign <bx> <by> <bz>' for a specific one)")
            probes = probes[:cap]
        _report_signs(probes, dump_path)

    def read_signs_here(r=3, dump_path=None):
        """Read signs by probing a cube around the BOT's own position — works
        even when the object list is empty. Walk near the signs, then run it."""
        if not pos["placed"]:
            print("  not placed in a realm yet")
            return
        cx = pos["x"] // P.COORD_BASE
        cy = pos["y"] // P.COORD_BASE
        cz = pos["z"] // P.COORD_BASE
        print(f"  scanning a {2 * r + 1}-block cube around ({cx},{cy},{cz}) ...")
        _report_signs(_cube(cx, cy, cz, r), dump_path)

    def record_machine(block, guid, text, offer, how, by_block, reach=1):
        """File a confirmed machine, keyed by its GUID so that the same machine
        reached from two neighbouring blocks is counted once."""
        first = guid not in offers
        offers[guid] = {"block": block, "machine": guid, "text": text,
                        "offer": offer, "how": how, "realm": state["realm"],
                        "realm_guid": reg["guid"],
                        "objs": neighbourhood(block, by_block, reach)}
        return first

    def scan_machines(limit=None, open_them=True, include_all=False, reach=1):
        # an autoscan and a typed `scan` would otherwise fight over qwait/dwait,
        # which are single slots
        if scanning.is_set():
            print("  a scan is already running — ctrl-c stops it")
            return
        by_block = occupied_blocks()
        if not by_block:
            print("  nothing to scan — no world objects received yet")
            remote_scan["seq"] += 1   # let a remote poller stop waiting
            return
        scanning.set()
        # z-neighbours are not an extra: querying the coordinate an object was
        # reported at answers almost never (3/194), the neighbours answer 201/582,
        # and the machines are all in the neighbours. 'scan near' drops back to
        # the object coordinates alone, 'scan wide' reaches z±2.
        probes = probe_blocks(by_block, reach) if reach else sorted(by_block)
        note = f"  (z±{reach})" if reach else "  (object coordinates only)"
        vlog(f"  {len(world)} object(s) on {len(by_block)} block(s) -> "
             f"{len(probes)} block queries{note}")
        before = len(offers)
        # Track this run for the history DB: which machine GUIDs THIS scan
        # actually observed (not the global `offers` accumulator, which carries
        # machines from earlier scans of other realms and would defeat removal
        # detection), plus the realm and outcome. A scan is authoritative enough
        # to REMOVE unseen listings only if it reaches 'completed'.
        scan_started = cc_storage.utcnow_iso() if cc_storage else None
        scan_realm, scan_guid = state["realm"], reg["guid"]
        observed_guids = set()
        scan_status, scan_error = "completed", None
        answered = {}
        try:
            # --- phase 1: query every probe. Cheap, opens no dialog, and the
            # reply text sometimes carries the price outright.
            vlog("  phase 1: querying ...")
            replies = query_many(probes)
            answered = {b: r for b, r in replies.items() if r}
            vlog(f"           {len(answered)}/{len(probes)} answered")
            for b, rep in answered.items():
                off = P.parse_vending_offer(rep["text"]) if rep["text"] else None
                if off:
                    observed_guids.add(rep["guid"])
                    if record_machine(b, rep["guid"], rep["text"], off,
                                      "query", by_block, reach):
                        vlog(f"  ({b[0]},{b[1]},{b[2]})  {describe_offer(off)}"
                             f"   [from query]")
                    # A query-priced machine is skipped by phase 2, so a standing
                    # buy order must get its chance here. off has no item name yet
                    # (the query text carries only the price); open_and_buy re-opens
                    # the machine, reads the item off the real dialog, and verifies
                    # it before spending.
                    if buy_orders or autosnipe["on"]:
                        try_fill_order(rep["guid"], off)
            if offers:
                vlog(f"           {len(offers)} priced straight from the query")

            # --- phase 2: open the rest. A dialog round trip is the slow part,
            # so open the most machine-like blocks first — but ORDER only, never
            # a filter. A machine's own coordinate holds no objects, so the
            # signal is how much stock is stacked AROUND it; type ids turned out
            # to be worthless for this and are gone. `scan N` caps the work.
            todo = [(b, r) for b, r in answered.items()
                    if r.get("guid") and r["guid"] not in offers]
            todo.sort(key=lambda it: (-len(neighbourhood(it[0], by_block, reach)),
                                      it[0]))
            if limit:
                todo = todo[:limit]
            if open_them and todo:
                # A miss is only detectable by timeout, so the timeout IS the
                # per-block cost for everything that isn't a machine. Start at
                # the configured ceiling and shrink to what the server actually
                # takes once a few dialogs have come back.
                budget = [args.dialog_timeout]
                seen_rtt = []

                def note_rtt(dt):
                    seen_rtt.append(dt)
                    if len(seen_rtt) == 5 or (seen_rtt and
                                              len(seen_rtt) % 25 == 0):
                        worst = sorted(seen_rtt)[-1]
                        new = min(args.dialog_timeout, max(0.15, worst * 4))
                        if new < budget[0] * 0.9:
                            budget[0] = new
                            vlog(f"           (server answers in "
                                 f"{worst * 1000:.0f}ms — dropping the miss "
                                 f"timeout to {new:.2f}s)")

                per = args.dialog_timeout + args.scan_delay
                vlog(f"\n  phase 2: opening {len(todo)} block(s), up to "
                     f"~{len(todo) * per / 60:.1f} min (dialog timeout "
                     f"{args.dialog_timeout}s, tightened once the server's "
                     f"real latency is known; always cancelled; ctrl-c stops)")
                # A query-reply `kind` byte that has never once produced a dialog
                # is probably terrain, so stop paying its timeout — but park those
                # blocks instead of dropping them, and come back to them if that
                # same kind turns out to answer later on.
                hits = collections.Counter()
                misses = collections.Counter()
                parked = []
                queue = list(todo)
                done = 0
                while queue:
                    if stop.is_set():
                        break
                    b, rep = queue.pop(0)
                    k = rep["kind"]
                    if not hits[k] and misses[k] >= 15:
                        parked.append((b, rep))
                        continue
                    t0 = time.time()
                    d = open_and_cancel(rep["guid"], timeout=budget[0])
                    done += 1
                    if done % 50 == 0:
                        vlog(f"           {done}/{len(todo)} opened, "
                             f"{len(offers)} machine(s) so far")
                    time.sleep(args.scan_delay)
                    if not d:
                        misses[k] += 1
                        continue
                    note_rtt(time.time() - t0)
                    hits[k] += 1
                    if parked:               # this kind answers after all
                        revive = [p for p in parked if p[1]["kind"] == k]
                        if revive:
                            parked = [p for p in parked if p[1]["kind"] != k]
                            queue.extend(revive)
                    off = P.parse_vending_offer(d["text"])
                    if off:
                        observed_guids.add(rep["guid"])
                        if record_machine(b, rep["guid"], d["text"], off,
                                          "dialog", by_block, reach):
                            vlog(f"  ({b[0]},{b[1]},{b[2]})  "
                                 f"{describe_offer(off)}")
                        if buy_orders or autosnipe["on"]:
                            try_fill_order(rep["guid"], off)
                if parked:
                    kinds = sorted({p[1]["kind"] for p in parked})
                    vlog(f"  ({len(parked)} block(s) left unopened — kind "
                         f"byte(s) {kinds} never produced a dialog in 15 "
                         f"tries. 'scan all' forces them.)")
                    if include_all:
                        vlog(f"  forcing {len(parked)} parked block(s) ...")
                        for b, rep in parked:
                            if stop.is_set():
                                break
                            d = open_and_cancel(rep["guid"],
                                                timeout=budget[0])
                            time.sleep(args.scan_delay)
                            off = P.parse_vending_offer(d["text"]) if d else None
                            if off:
                                observed_guids.add(rep["guid"])
                                if record_machine(b, rep["guid"], d["text"],
                                                  off, "dialog", by_block,
                                                  reach):
                                    vlog(f"  ({b[0]},{b[1]},{b[2]})  "
                                         f"{describe_offer(off)}")
                                if buy_orders or autosnipe["on"]:
                                    try_fill_order(rep["guid"], off)
        except KeyboardInterrupt:
            print("\n  stopped.")
            scan_status = "interrupted"
        except Exception as e:
            scan_status, scan_error = "failed", f"{type(e).__name__}: {e}"
            show_line(f"  scan failed: {scan_error}")
        finally:
            scanning.clear()
            remote_scan["seq"] += 1   # this scan is over — wake any remote poller
        # A stop signal (quit / realm hop mid-scan) means we can't treat what we
        # have as a full, authoritative view of the realm.
        if scan_status == "completed" and stop.is_set():
            scan_status = "interrupted"
        print(f"\n  done: {len(offers)} machine(s) with an offer "
              f"(+{len(offers) - before} this run). 'machines' reprints them, "
              f"'dump' writes them to a file.")
        # Record the scan in the history DB (always, with its true status) and
        # refresh the current catalogue. Only a COMPLETED scan is authoritative
        # enough to remove listings it didn't see this time.
        publish_scan_result(scan_realm, scan_guid, scan_started, scan_status,
                            scan_error, observed_guids, len(probes),
                            len(answered))
        # Keep vends.json in sync for compatibility — but only when the scan was
        # authoritative, so a partial/interrupted/failed scan never erases valid
        # current listings from the JSON either.
        if scan_status == "completed":
            publish_realm()
        # After the scan is fully done (scanning cleared, so dwait/open_and_buy is
        # free), sweep active buy orders over every machine now known in this
        # realm. This catches machines phase 2 never opened (query-priced or
        # carried over from an earlier scan). Quiet unless a buy actually fires.
        if not stop.is_set():
            if buy_orders or autosnipe["on"]:
                fill_orders_here(report=False)
            # Player buy orders (deposited-balance, whisper-placed) fill off the
            # same freshly-scanned machines, independent of any owner orders.
            fill_player_orders_here(report=False)
            # On a 'buy travel' crawl, end the trip the moment every order is
            # complete instead of visiting the rest of the matching realms.
            if crawl.get("active") and buy_orders and not any(
                    o.get("active", True) for o in buy_orders):
                crawl["stop"] = True
                show_line("  buy travel: all orders complete — ending crawl.")

    def scan_all_blocks(reach=1, box=False, pad=1, cap=60000,
                        grid=None, zpad=0):
        """ACTIVE block finder — the vend method, repurposed to enumerate blocks
        instead of only machines. Same packet retrieval: build the candidate
        coordinate set, fire tx 0x0014 at every one via query_many, and keep the
        coords the server ANSWERS for. Passive-safe: 0x0014 opens no dialog and
        spends nothing (same call the vend scan's phase 1 uses).

        Two candidate sets:
          reach mode (default): occupied blocks + z-neighbours (exactly what the
            vend scan probes) — fast, but only near known objects.
          box mode: the whole XY bounding box of the realm's objects (padded) at
            every occupied Z. This queries coords with NO object in the passive
            burst — i.e. it can surface blocks that aren't on the `blocks` list.

        A coord that answers but has no burst object is marked NEW (found only by
        querying). Names come from the burst object at that coord when there is
        one; the 0x0014 reply itself carries no type_id, so query-only hits show
        their `kind` byte + any text, not a catalogue name."""
        if scanning.is_set():
            print("  a scan is already running — ctrl-c stops it")
            return
        by_block = occupied_blocks()
        if not by_block:
            print("  nothing to scan from — no world objects received yet "
                  "(enter a realm first)")
            return
        if grid:
            # FULL-REALM sweep: the object bounding box misses everything built
            # in regions with no burst object, so sweep the whole footprint the
            # user gives (a realm is WxH cells) at the objects' Z range, padded.
            # This is an explicit request, so it is NOT capped — only warned.
            W, H = grid
            zs = [b[2] for b in by_block]
            z0, z1 = min(zs) - zpad, max(zs) + zpad
            probes = [(x, y, z) for z in range(z0, z1 + 1)
                      for x in range(0, W + 1)
                      for y in range(0, H + 1)]
            print(f"  full grid: X[0..{W}] Y[0..{H}] Z[{z0}..{z1}] "
                  f"= {len(probes)} coord(s)  (uncapped — explicit sweep)")
        elif box:
            xs = [b[0] for b in by_block]
            ys = [b[1] for b in by_block]
            zs = [b[2] for b in by_block]
            x0, x1 = min(xs) - pad, max(xs) + pad
            y0, y1 = min(ys) - pad, max(ys) + pad
            z0, z1 = min(zs), max(zs)
            probes = [(x, y, z) for z in range(z0, z1 + 1)
                      for x in range(x0, x1 + 1)
                      for y in range(y0, y1 + 1)]
            print(f"  box: X[{x0}..{x1}] Y[{y0}..{y1}] Z[{z0}..{z1}] "
                  f"= {len(probes)} coord(s)")
            if len(probes) > cap:
                print(f"  that's over the {cap}-coord cap — falling back to "
                      f"z±{reach} neighbours. Use 'blocks scan grid 99 99' for a "
                      f"full uncapped sweep of a 99x99 realm.")
                probes = probe_blocks(by_block, reach)
        else:
            probes = probe_blocks(by_block, reach)

        # coord -> type_id from the passive burst, for naming + NEW detection.
        burst = {}
        for o in world.values():
            burst.setdefault((o["bx"], o["by"], o["bz"]), o.get("type_id"))

        est = len(probes) * (args.query_gap or 0)
        eta = f", ~{est / 60:.1f} min of sends" if est >= 30 else ""
        scanning.set()
        print(f"  querying {len(probes)} coord(s) by the vend method "
              f"(tx 0x0014, passive-safe{eta}) — replies stream back; "
              f"ctrl-c stops ...")
        try:
            replies = query_many(probes)
        except KeyboardInterrupt:
            print("\n  stopped.")
            replies = {}
        finally:
            scanning.clear()

        def real(guid):
            return bool(guid) and set(guid) != {"0"}
        answered = {b: r for b, r in replies.items()
                    if r and real(r.get("guid"))}
        if not answered:
            print(f"  0 of {len(probes)} coord(s) answered — the server returns "
                  f"nothing for plain build blocks; only functional/queryable "
                  f"objects reply to 0x0014.")
            return
        new = [(b, r) for b, r in answered.items() if b not in burst]
        known = [(b, r) for b, r in answered.items() if b in burst]
        from collections import Counter
        by_kind = Counter(r.get("kind") for r in answered.values())
        realm = state.get("realm") or "unknown-realm"
        safe = re.sub(r"[^0-9A-Za-z._-]+", "_", realm).strip("_") or "realm"
        here = _APP_DIR

        print(f"  {len(answered)}/{len(probes)} coord(s) answered  "
              f"({len(known)} already in the burst, {len(new)} NEW — found only "
              f"by querying).")
        print(f"  reply 'kind' bytes: "
              + ", ".join(f"kind {k}:{n}" for k, n in by_kind.most_common()))
        # Per-Z-layer breakdown: structural floors/platforms show up as whole Z
        # planes full of answers. This is how we spot the ground layer(s).
        by_z = Counter(b[2] for b in answered)
        by_z_new = Counter(b[2] for b, _ in new)
        print("  answers per Z layer (z: total / NEW):")
        for z in sorted(by_z):
            print(f"    z={z}: {by_z[z]}  / {by_z_new.get(z, 0)} NEW")
        me = player_block.get(conn.get("own"))

        def bdist(b):
            return (abs(b[0] - me[0]) + abs(b[1] - me[1]) + abs(b[2] - me[2])
                    if me else 0)
        rows = sorted(answered.items(), key=lambda it: (bdist(it[0]), it[0]))
        CAP = 200
        for b, r in rows[:CAP]:
            tid = burst.get(b)
            nm = item_label(tid) if tid is not None else \
                f"(no burst object — kind {r.get('kind')})"
            tag = "  NEW" if b not in burst else ""
            txt = f"  “{r['text']}”" if r.get("text") else ""
            print(f"    ({b[0]}, {b[1]}, {b[2]})  {nm}{tag}{txt}")
        if len(rows) > CAP:
            print(f"  (showed first {CAP} of {len(rows)})")

        path = os.path.join(here, f"blocks-{safe}-scan.txt")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(f"# active scan: {len(answered)}/{len(probes)} coord(s) "
                         f"answered in realm {realm!r} "
                         f"({len(new)} NEW, not in the passive burst)\n")
                fh.write("# x\ty\tz\tkind\tguid\tin_burst\ttype_id\tname\ttext\n")
                for b, r in rows:
                    tid = burst.get(b)
                    fh.write(f"{b[0]}\t{b[1]}\t{b[2]}\t{r.get('kind')}\t"
                             f"{r.get('guid')}\t{b in burst}\t"
                             f"{tid if tid is not None else ''}\t"
                             f"{item_names.get(tid, '') if tid is not None else ''}\t"
                             f"{(r.get('text') or '').replace(chr(9), ' ')}\n")
            print(f"  full scan written to {path}")
        except OSError as e:
            print(f"  (couldn't write {path}: {e})")
        if not new:
            print("  NB: nothing NEW — every answering coord was already in the "
                  "burst, so active querying didn't surface blocks the list "
                  "missed. Try 'blocks scan box' to sweep the gaps between "
                  "objects.")

    STEP = args.step

    def apply_move(x, y, z, why):
        """Walk the avatar to (x, y, z) and broadcast it. Now a REAL walk: it faces
        the direction of travel and animates via walk_to (off-thread so the console
        stays responsive), so it looks the way it's walking. Vertical (u/d) is
        applied directly. Clears the post-teleport freeze first."""
        if not pos["placed"]:
            show_line("  not placed in a realm yet — can't move")
            return
        x, y, z = int(x), int(y), int(z)
        dx, dy = x - pos["x"], y - pos["y"]
        pos["z"] = z                      # vertical is instant
        pos["frozen"] = False
        if dx or dy:
            pos["heading"] = P.heading_deg(dx, dy)   # face where we're walking
            threading.Thread(target=lambda: walk_to(x, y), daemon=True).start()
        else:
            announce(force=True)
        show_line(f"  {why} -> ({x},{y},{z})")

    print("\n  CONNECTED to the live world as "
          f"{prof['identity']['display_name']}.")
    if hollow["auto"]:
        print("  ⚑ auto-Hollawarp ON: will join every Hollawarp broadcast, scan "
              "it, watchlist it\n    if it has vends, then park. 'hwarp off' to "
              "stop; --no-auto-hollowarp to launch off.")
        if not (state.get("after_realm") or state.get("after_guid")
                or state.get("after")):
            print("    (no park target set — 'parkrealm <home>' or 'after "
                  "<friend>' so it leaves each realm after scanning.)")
    def print_help():
        if getattr(args, "simple", False):
            # SIMPLE build: only list what this build actually runs (the rest are
            # refused, so don't advertise them).
            print("  commands ('help' to show again):")
            print("   MOVE      tp <name> | guid/find <name> | goto | move | "
                  "jump | portal | where | offmap | wander on|off")
            print("   REALMS    joinname <name> | joinrealm <link|guid> | "
                  "searchrealm <name> | link <url> | parkrealm <name> | park")
            print("   SCAN      scan [N] | rescan [N] | vends | machines | "
                  "machinehistory <guid>")
            print("   MARKET    market <item> | deals <item> | history <item> | "
                  "changes | dbstats")
            print("   SCAN LOG  scans | scanstatus | stale | dbexport | dbbackup")
            print("   WATCH     watch [link|guid] | watchlist | unwatch <name|guid>")
            print("   CRAWL     crawl <term> [max] | crawlfile <path>")
            print("   DISCORD   webhook set <url> | webhook test | webhook off | "
                  "link | control")
            print("   BASICS    reconnect [on|off] | help | quit")
            return
        print("  commands ('help' to show again):")
        print("   HOLLAWARP  hwarp on|off (auto-join+scan every Hollawarp) | "
              "hwarp cooldown <sec> (skip a realm that re-hollers too soon)")
        print("   WANDER     wander on|off   (while scanning, walk over to the "
              "vending machines it's reading; while idle, turn to face new "
              "directions in place — so it doesn't look AFK/frozen)")
        print("   VENDS      vends | vends <realm>            (what realms sell)")
        print("   MARKET     market <item> (search all realms, cheapest first) "
              "| market export [file.html|.csv]")
        print("   HISTORY    dbstats | history <item> [days] | changes [hours] "
              "| deals <item> [max] | machinehistory <guid>")
        print("   SCAN LOG   scans [N] | scanstatus | stale [hours]   "
              "(scan sessions + out-of-date catalogues)")
        print("   DATABASE   dbexport [file.json] (current listings) | "
              "dbbackup [file.db] (safe snapshot)")
        print("   WATCHLIST  watch [link|guid] | watchlist | unwatch <name|guid> "
              "| rescan [N]  (resolves, then crawls automatically in batches of "
              f"{args.rescan_batch}, draining the Hollowarp queue between "
              "batches; 'crawl stop' ends it) | rescan fast [N] (no up-front "
              "resolve wait — starts now, resolves each realm's name to its "
              "current GUID just before joining it; no auto-prune)")
        print("   SCAN       scan [N] [all] [wide|near] | machines | "
              "dump [file|raw]")
        print("   MINE       fossils | fossils region <x1> <y1> [z1] <x2> <y2> "
              "[z2] | fossils learn <id> | objects   (enter a mine, then "
              "'fossils' lists each fossil's XYZ; draw the fossil square with "
              "'fossils region' — two opposite corners, every block inside "
              "counts)")
        print("   REALM MAP  blocks | blocks count | blocks scan[/wide/box] | "
              "blocks <name> | blocks all | blocks json [file]   (enter a realm, "
              "then 'blocks' lists placed blocks w/ name + XYZ; 'blocks count' = "
              "tally of each type; 'blocks scan' = ACTIVE 0x0014 sweep, the vend "
              "method, to find coords the passive list misses)")
        print("   BUILD      build inventory | build arm <exact realm> <x> <y> "
              "<z> | build suite | build status | build pause/resume/cancel\n"
              "              (realm-locked; empty-area + inventory preflight; "
              "every placement confirmed by inventory change + block query)")
        print("   BUY        buy <item> under <price> [max N] [budget C] | "
              "buy travel | buy now | buy cancel <item> | buy off   "
              "(buys off the scanned list now; 'buy travel' crawls all saved "
              "realms with a match; guards: price, budget, max)")
        print("   SNIPE      snipe [on|off] | snipe avg <c> | snipe max <c>   "
              "(ALWAYS ON: auto-buys any item listed <= 1c whose community value "
              "is >= 2,000c — a mis-listed valuable; both gates must hold)")
        print("   WEBHOOK    webhook set <url> | webhook test | webhook prize "
              "on|off | webhook snipe on|off | webhook off   (Discord alerts: "
              "pings your channel on a prize crack / snipe snag — toggle each "
              "type; off until you set a URL)")
        print("   INVENTORY  inventory  (all items on display in this realm; "
              "passive) | inventory <file.csv|.json> | glass (in-case only)")
        print("   MANNEQUINS mannequins  (WALK PAST them first so they load, then "
              "reads each outfit) | mannequins <file> | mannequin <bx> <by> <bz>")
        print("   SIGNS      sign [<bx> <by> <bz>] | signs here [r] | signs "
              "[wide|file] | writesign <bx> <by> <bz> <text>")
        print("              place <sign item id> <bx> <by> <bz> (requires armed "
              "builder), then writesign; legacy placesign is disabled")
        print("   REALMS     joinname <name> | joinrealm <link|guid> | "
              "searchrealm <name> | link <url>")
        print("   PARK       parkrealm <name> | after <link|player> | park "
              "(go there now)")
        print("   QUEUE      queue (show waiting moves) | queue clear   "
              "(tp/guid/summon wait here while busy)")
        print("   RECONNECT  reconnect [on|off]   (auto re-login after a "
              "server kick; on by default)")
        print("   LOG        log [on|off]   (LOG mode = full detail; REGULAR = "
              "essentials only; bare 'log' toggles)")
        print("   CRAWL      crawl <term> [max] | crawlfile <path> (realm "
              "names, one per line)")
        print("              -> 'crawl go' (all) or 'crawl go <N>' (first N, "
              "rest stay staged) | 'crawl status' (live ETA) | 'crawl stop'")
        print("   PLAYERS    players | tp <name> | guid <name> | find <name> | "
              "friends | friend/unfriend <name>")
        print("   PRICEBOT   pricebot on|off   (answer 'price of <item>' / 'pc "
              "<item>' / 'how much is <item>' in chat, rate-limited)")
        print("   QUIZ       quiz host <name> | quiz on|off | quiz test <q>   "
              "(offline INSTANT trivia auto-answer: math computed, facts looked "
              "up, host reveals learned; raises hand + waits for 'you're allowed "
              "to talk'. 'quiz' alone shows status)")
        print("   SUMMON     summon on|off     ('summon <name>' in chat -> tp to "
              "them, same realm only)")
        print("   SCANBOT    scanbot on|off    ('<name> scan realm <exact "
              "name>' in chat -> join + scan it)")
        print("   CMDS       commands on|off   (keyword chat commands: '<name> "
              "help', '<name> realm [name]'; bare '<name>' greets; on by "
              "default)")
        print("   WHISPER    whisper on|off | public on|off | whisper <name> "
              "<msg>   (answer private whispers; by default REPLACES public chat)")
        print("   TRANSLATE  translate on|off | public | whisper | to <name> | "
              "provider <name> | models | install <code> | test <text> | status")
        print("              (LOCAL offline translation, NO API key: auto-detects "
              "foreign chat -> posts '<player> said in LANG: english', public or "
              "whispered. Default engine = Argos (on-device neural model); "
              "'install es fr de pt ja ru' or auto-downloads on first use)")
        print("   APPROVED   approved | approve <name> | unapprove <name>   "
              "(allowlist for summon + scan realm)")
        print("   CONSOLE    control [port] | control off   (web button + "
              "approved-user manager in a browser)")
        print("   PUBLIC     public [port] | public off   (read-only market "
              "site: prices + history, no bot control)")
        print("   MOVE       n|s|e|w [count] | u|d (up/down) | goto <x> <y> "
              "[z] | move <dx> <dy> | portal | where")
        print("   PRIZE      prize <lo> <hi> [delay]   (park by the machine — "
              "auto-finds the dispenser, brute-forces the code, grabs the prize)")
        print("              also: prize find [r] | prize <lo> <hi> <bx> <by> <bz> "
              "[delay] | prize test [<bx> <by> <bz>] <code> | prize stop")
        print("   MISC       say <text> | sayc {red}5 {blue}1 (coloured, "
              "experimental) | emoji <c9|e5> | stats | quit")
    print_help()
    print("  'scan' queries every occupied block AND its z-neighbours — that is "
          "where the\n  machines are — then opens whatever the query didn't "
          "price. Dialogs are always\n  CANCELLED, never bought. "
          "'machines' reprints the\n  results, 'dump [file]' writes just the "
          "vends (.csv/.txt/.json by extension;\n  'dump raw' writes the whole "
          "object list instead).")
    print("  'link' shows this realm's Share URL — built from its GUID, no "
          "browser needed —\n  and every dump's 'link' column is filled the same "
          "way. 'link <url>' overrides one\n  realm if it ever differs; 'link "
          "off' drops the override.")
    print("  spawn: we wait for the server to place us at the realm portal and "
          "adopt that\n  position — 'portal' walks back to it.")
    print("  'guid <name>' resolves ANY player's GUID — sends a friend request, "
          "reads the\n  GUID out of the pending list, cancels the request — "
          "then teleports to them.\n  'find <name>' does the same lookup but "
          "stops at the GUID.\n")

    # --- on-screen web console (a browser button -> teleport) ----------------
    # A tiny local HTTP server the bot hosts itself. Open its URL in a browser
    # and the button POSTs a name back here; we resolve it and teleport, reusing
    # the exact same pending["guid"] path as the 'tp' command. Bound to
    # 127.0.0.1 by default (this PC only). 'control' toggles it; --control-port
    # auto-starts it.
    webctl = {"httpd": None, "host": None, "port": None}
    pubweb = {"httpd": None, "host": None, "port": None}
    # Rendering the whole catalogue costs a pass over vends + a JSON dump, so a
    # public page that anyone can refresh needs a cache in front of it. Keyed by
    # (path, query) -> (built_at, body, ctype); entries expire after
    # --public-cache seconds.
    pubcache = {}
    pubcache_lock = threading.Lock()
    CONSOLE_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cubic Castles Bot Console</title>
<link id="favicon" rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>&#127984;</text></svg>">
<style>
 :root{
   --bg0:#070912; --bg1:#0d1024; --bg2:#141834; --card:#151933cc;
   --line:#28305c; --line2:#343d70; --ink:#eef1ff; --ink-dim:#9aa3d4;
   --ink-faint:#6b74a8; --acc:#7c5cff; --acc2:#22d3ee; --acc3:#f472b6;
   --ok:#34d399; --warn:#fbbf24; --err:#fb7185; --gold:#ffd24a;
   --glow:0 0 0 1px #ffffff10, 0 12px 40px #0009;
 }
 *{box-sizing:border-box}
 html,body{margin:0}
 body{font-family:"Segoe UI",system-ui,-apple-system,sans-serif;color:var(--ink);
   min-height:100vh;background:
     radial-gradient(1200px 700px at 15% -10%,#1b1e46 0%,transparent 55%),
     radial-gradient(1000px 800px at 100% 0%,#122a3a 0%,transparent 50%),
     linear-gradient(160deg,var(--bg0),var(--bg1) 60%,#0a0d1e);
   background-attachment:fixed;padding:22px 16px 48px}
 a{color:var(--acc2)}
 .wrap{max-width:1120px;margin:0 auto}
 .top{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:18px}
 .brand{display:flex;align-items:center;gap:12px;font-weight:800;font-size:1.35rem;
   letter-spacing:.2px}
 .brand .logo{width:42px;height:42px;display:grid;place-items:center;font-size:1.5rem;
   border-radius:13px;background:linear-gradient(135deg,var(--acc),var(--acc3));
   box-shadow:0 8px 24px #7c5cff55}
 .brand b{background:linear-gradient(90deg,#c4b5ff,#9be7ff);-webkit-background-clip:text;
   background-clip:text;color:transparent}
 .brand small{display:block;font-size:.7rem;font-weight:600;color:var(--ink-faint);
   letter-spacing:2px;text-transform:uppercase}
 .pill{margin-left:auto;display:flex;align-items:center;gap:9px;padding:9px 15px;
   border-radius:999px;background:#0c1024cc;border:1px solid var(--line);
   font-size:.85rem;font-weight:600;backdrop-filter:blur(6px)}
 .dot{width:10px;height:10px;border-radius:50%;background:var(--warn);
   box-shadow:0 0 0 4px #fbbf2422;animation:pulse 1.6s infinite}
 .dot.on{background:var(--ok);box-shadow:0 0 0 4px #34d39926}
 .dot.off{background:var(--err);box-shadow:0 0 0 4px #fb718522;animation:none}
 @keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}

 .grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;align-items:start}
 @media(max-width:860px){.grid2{grid-template-columns:1fr}}
 .col{display:flex;flex-direction:column;gap:16px;min-width:0}

 .card{background:var(--card);border:1px solid var(--line);border-radius:18px;
   padding:18px 18px 20px;box-shadow:var(--glow);backdrop-filter:blur(10px)}
 .card h2{font-size:.82rem;margin:0 0 4px;text-transform:uppercase;letter-spacing:1.4px;
   color:var(--ink-dim);display:flex;align-items:center;gap:8px}
 .card .hint{font-size:.78rem;line-height:1.45;color:var(--ink-faint);margin:0 0 14px}
 .card .hint b{color:var(--ink-dim)}

 input{width:100%;padding:12px 14px;border-radius:11px;border:1px solid var(--line2);
   background:#0a0d20;color:var(--ink);font-size:.98rem;outline:none;
   transition:border-color .15s,box-shadow .15s}
 input:focus{border-color:var(--acc);box-shadow:0 0 0 3px #7c5cff33}
 input::placeholder{color:#525a8a}
 label.chk{display:flex;align-items:center;gap:9px;font-size:.83rem;color:var(--ink-dim);
   margin:2px 0 12px;cursor:pointer}
 label.chk input{width:auto}

 button{font-family:inherit;font-weight:700;border:0;border-radius:12px;cursor:pointer;
   color:#fff;transition:transform .06s,filter .15s,box-shadow .15s;font-size:.98rem}
 button:active{transform:translateY(1px) scale(.99)}
 button:disabled{opacity:.5;cursor:default}
 .btn-primary{width:100%;padding:15px;font-size:1.05rem;
   background:linear-gradient(135deg,var(--acc),#a855f7);box-shadow:0 8px 22px #7c5cff44}
 .btn-primary:hover{filter:brightness(1.08)}
 .btn-gold{width:100%;padding:16px;font-size:1.08rem;color:#3a2a00;
   background:linear-gradient(135deg,#ffe066,var(--gold));box-shadow:0 8px 22px #ffd24a44}
 .btn-alt{background:linear-gradient(135deg,#2b3162,#232a54);border:1px solid var(--line2)}
 .btn-alt:hover{filter:brightness(1.15)}

 .quick{display:grid;grid-template-columns:1fr 1fr;gap:10px}
 .quick button{padding:14px 10px;font-size:.95rem;
   background:linear-gradient(135deg,#232a54,#1a2048);border:1px solid var(--line2)}
 .quick button:hover{filter:brightness(1.2);border-color:var(--acc)}
 .quick button.warm{background:linear-gradient(135deg,#3a2450,#2a1a44)}
 .quick button.danger{background:linear-gradient(135deg,#4a2036,#3a1830)}

 .row3{display:flex;gap:8px}
 .row3 input{text-align:center}
 .stack>*{margin-bottom:11px}.stack>*:last-child{margin-bottom:0}
 .msg{margin-top:14px;min-height:1.2em;font-size:.9rem;font-weight:600}
 .msg.ok{color:var(--ok)}.msg.err{color:var(--err)}

 /* approved chips */
 #alist{list-style:none;margin:0 0 12px;padding:0;display:flex;flex-wrap:wrap;gap:8px}
 #alist li{display:flex;align-items:center;gap:6px;background:#0b0f24;
   border:1px solid var(--line2);border-radius:999px;padding:5px 6px 5px 13px;
   font-size:.85rem}
 #alist .x{cursor:pointer;border:0;background:#2a2f52;color:var(--ink);width:20px;
   height:20px;line-height:1;border-radius:50%;padding:0;font-size:.9rem}
 #alist .x:hover{background:var(--err)}
 #alist .empty{opacity:.5;font-size:.82rem}
 .addrow{display:flex;gap:8px}
 .addrow input{margin:0}
 .addrow button{padding:11px 18px;background:linear-gradient(135deg,var(--acc),#a855f7)}

 /* live log */
 .logcard{position:sticky;top:14px}
 .logbar{display:flex;align-items:center;gap:10px;margin-bottom:10px}
 .logbar h2{margin:0}
 .live{display:inline-flex;align-items:center;gap:6px;font-size:.66rem;font-weight:800;
   letter-spacing:1.5px;color:var(--acc3);text-transform:uppercase}
 .live i{width:8px;height:8px;border-radius:50%;background:var(--acc3);
   box-shadow:0 0 8px var(--acc3);animation:pulse 1.2s infinite;font-style:normal}
 .logbar .sp{margin-left:auto}
 .logbar button{padding:7px 12px;font-size:.78rem;background:#1a2048;
   border:1px solid var(--line2)}
 #log{height:min(62vh,640px);overflow:auto;background:#05070f;border:1px solid var(--line);
   border-radius:12px;padding:12px 14px;font-family:"Cascadia Code",Consolas,
   ui-monospace,monospace;font-size:.79rem;line-height:1.55;color:#c3cbf5;
   white-space:pre-wrap;word-break:break-word}
 #log .l{padding:1px 0;border-left:2px solid transparent;padding-left:8px;margin-left:-8px}
 #log .l.prize{color:var(--gold);border-color:var(--gold);background:#ffd24a0e}
 #log .l.err{color:var(--err)}
 #log .l.warn{color:var(--warn)}
 #log .l.console{color:var(--acc2)}
 #log .l.win{color:#fff;background:linear-gradient(90deg,#ffd24a22,transparent);
   border-color:var(--gold);font-weight:700}
 #log .empty{color:var(--ink-faint)}
 #log::-webkit-scrollbar{width:10px}
 #log::-webkit-scrollbar-thumb{background:#232a54;border-radius:8px}

 /* password-found banner */
 #found{display:none;margin-bottom:16px;padding:20px;border-radius:18px;color:#3a2a00;
   background:linear-gradient(135deg,#ffe37a,#ffce3d 55%,#ffb84d);
   border:1px solid #fff6cf;box-shadow:0 14px 44px #ffcf4a55,var(--glow);
   position:relative;overflow:hidden;animation:pop .4s ease}
 #found.show{display:block}
 @keyframes pop{0%{transform:scale(.92);opacity:0}100%{transform:scale(1);opacity:1}}
 #found .fh{font-size:1.15rem;font-weight:900;letter-spacing:.3px;
   display:flex;align-items:center;gap:9px}
 #found .code{font-family:"Cascadia Code",Consolas,ui-monospace,monospace;
   font-size:2.5rem;font-weight:900;letter-spacing:2px;margin:6px 0 4px;
   text-shadow:0 2px 0 #fff7}
 #found .frow{display:flex;gap:10px;margin-top:12px}
 #found button{padding:11px 18px;color:#3a2a00}
 #found .cp{background:#fff;border:1px solid #e8c65a}
 #found .cl{background:#00000018;border:1px solid #00000022}
 #found .spark{position:absolute;font-size:1.4rem;opacity:.9;animation:rise 2.4s linear infinite}
 @keyframes rise{0%{transform:translateY(20px);opacity:0}
   15%{opacity:.9}100%{transform:translateY(-90px);opacity:0}}
 /* live drive pad */
 .dpad{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;max-width:260px;
   margin:0 auto}
 .dpad button{padding:16px 0;font-size:1.15rem;background:linear-gradient(135deg,#232a54,#1a2048);
   border:1px solid var(--line2);user-select:none;touch-action:none}
 .dpad button:hover{filter:brightness(1.2);border-color:var(--acc)}
 .dpad button.held{background:linear-gradient(135deg,var(--acc),#a855f7);
   border-color:var(--acc);box-shadow:0 0 0 3px #7c5cff44}
 .dpad .sp{visibility:hidden}
 .dpad .jump{grid-column:1 / -1;background:linear-gradient(135deg,#2b3a62,#213154)}
 .vpad{display:flex;gap:8px;max-width:260px;margin:8px auto 0}
 .vpad button{flex:1;padding:12px 0;background:linear-gradient(135deg,#232a54,#1a2048);
   border:1px solid var(--line2)}
 .drivestat{text-align:center;font-size:.8rem;color:var(--ink-dim);margin:10px 0 0}
 .drivestat b{color:var(--acc2)}
 .tradebox{display:none;margin-top:12px;padding:12px 14px;border-radius:12px;
   background:#0b0f24;border:1px solid var(--warn)}
 .tradebox.show{display:block}
 .tradebox .tt{font-weight:700;color:var(--warn);margin-bottom:9px}
 .tradebox .trow{display:flex;gap:8px}
 .tradebox button{flex:1;padding:11px 0;font-size:.9rem}
 .tradebox .acc{background:linear-gradient(135deg,#1f7a4d,#15633c)}
 .tradebox .con{background:linear-gradient(135deg,#b98900,#8f6b00)}
 .tradebox .dec{background:linear-gradient(135deg,#4a2036,#3a1830)}
 .foot{text-align:center;color:var(--ink-faint);font-size:.74rem;margin-top:24px}
</style></head>
<body><div class="wrap">

 <div class="top">
   <div class="brand">
     <span class="logo">&#127984;</span>
     <span>Cubic Castles <b>Bot Control</b><small>live console</small></span>
   </div>
   <div class="pill"><span id="dot" class="dot"></span><span id="stat">connecting&#8230;</span></div>
 </div>

 <div id="found">
   <div class="fh">&#127881; Prize password FOUND!</div>
   <div class="code" id="foundcode">--</div>
   <div style="font-size:.85rem;font-weight:600;opacity:.85">The prize was left untouched. Copy the code and claim it in-game.</div>
   <div class="frow">
     <button class="cp" id="foundcopy">Copy code</button>
     <button class="cl" id="foundclose">Dismiss</button>
   </div>
 </div>

 <div class="grid2">
  <div class="col">

   <div class="card">
     <h2>&#9889; Quick actions</h2>
     <div class="quick">
       <button data-act="/hwarp?on=1">Hollawarp ON</button>
       <button class="warm" data-act="/hwarp?on=0">Hollawarp OFF</button>
       <button data-act="/wander?on=1">Wander ON</button>
       <button class="warm" data-act="/wander?on=0">Wander OFF</button>
       <button class="danger" data-act="/freeze?on=1">&#10052;&#65039; Freeze</button>
       <button data-act="/freeze?on=0">Unfreeze</button>
       <button data-act="/scan">Scan realm</button>
       <button data-act="/park">Park</button>
     </div>
   </div>

   <div class="card">
     <h2>&#127918; Live drive (WASD)</h2>
     <div class="hint">Click here first, then use <b>W A S D</b> to walk and
       <b>Space</b> to jump. Hold a key to keep walking &#8212; the avatar walks
       with the normal animation for everyone in the realm. Or press the on-screen
       buttons. With <b>Physics ON</b> it won't walk through walls, climbs ledges,
       and falls to the ground off a drop; <b>Q</b>/<b>E</b> free-fly the height
       only when physics is OFF.</div>
     <label class="chk" style="margin:0 0 12px"><input type="checkbox" id="phys" checked>
       Physics (collision + gravity) &#8212; <span id="physinfo" style="opacity:.7"></span></label>
     <div class="dpad" id="dpad">
       <span class="sp"></span>
       <button data-k="w">&#9650;<br><small>W</small></button>
       <span class="sp"></span>
       <button data-k="a">&#9664;<br><small>A</small></button>
       <button data-k="s">&#9660;<br><small>S</small></button>
       <button data-k="d">&#9654;<br><small>D</small></button>
       <button class="jump" id="jbtn">&#11014;&#65039; Jump (Space)</button>
     </div>
     <div class="vpad">
       <button data-z="1">&#8593; Up (Q)</button>
       <button data-z="-1">&#8595; Down (E)</button>
     </div>
     <div class="drivestat">walking: <b id="dstat">&#8212;</b></div>
     <div class="tradebox" id="tradebox">
       <div class="tt" id="tradett">Trade request</div>
       <div class="trow">
         <button class="acc" id="tacc">Accept</button>
         <button class="con" id="tcon">Confirm (YES)</button>
         <button class="dec" id="tdec">Decline</button>
       </div>
     </div>
   </div>

   <div class="card">
     <h2>&#128100; Account: __ACCOUNT__</h2>
     <div class="hint">Log <b>__ACCOUNT__</b> off the server. It stays offline
       (no auto-reconnect) until you press Enable, which logs it back in.</div>
     <div class="quick">
       <button class="danger" data-act="/disable">&#9940; Disable __ACCOUNT__</button>
       <button data-act="/enable">&#9989; Enable __ACCOUNT__</button>
     </div>
   </div>

   <div class="card">
     <h2>&#128225; Summon bot</h2>
     <div class="hint">Teleports the bot to a player by name.</div>
     <div class="stack">
       <input id="name" value="frostyer" autocomplete="off" spellcheck="false"
         placeholder="player to summon to">
       <button class="btn-primary" id="go">Summon bot to me</button>
     </div>
   </div>

   <div class="card">
     <h2>&#127873; Crack prize machine</h2>
     <div class="hint">Stand dead-center on the prize machine and take a step so I
       have your spot, then click. I arm <b>exactly the block `height off` below
       you</b> (default 2) and crack it &#8212; no walking, no picking a different
       machine.</div>
     <div class="stack">
       <div class="row3">
         <input id="px" inputmode="numeric" placeholder="X (54)">
         <input id="py" inputmode="numeric" placeholder="Y (12)">
         <input id="pz" inputmode="numeric" placeholder="Z (92)">
       </div>
       <div class="hint" style="margin:0">Type the <b>S X / Y / Z</b> from the
         top-left of your game screen (most reliable), or leave blank and use your
         name.</div>
       <input id="pname" value="" placeholder="YOUR in-game name (if no coords)"
         autocomplete="off" spellcheck="false">
       <div class="row3">
         <input id="poff" value="2" inputmode="numeric" placeholder="height off">
         <input id="plo" value="0" inputmode="numeric" placeholder="from">
         <input id="phi" value="9999" inputmode="numeric" placeholder="to">
       </div>
       <label class="chk"><input type="checkbox" id="ptp"> teleport to me first
         (only if my position looks stale)</label>
       <button class="btn-gold" id="pgo">&#128273; Crack this prize machine</button>
       <button class="btn-alt" id="pstop" style="width:100%;padding:12px">Stop prize crack</button>
     </div>
     <div id="msg" class="msg"></div>
   </div>

   <div class="card">
     <h2>&#128273; Approved users</h2>
     <div class="hint">Only these usernames can use privileged in-game commands
       (summon, scan realm). Price checks, help and realm info stay open to
       everyone.</div>
     <ul id="alist"><li class="empty">loading&#8230;</li></ul>
     <div class="addrow">
       <input id="aname" placeholder="username to approve" autocomplete="off"
         spellcheck="false">
       <button id="add">Add</button>
     </div>
   </div>

  </div>
  <div class="col">
   <div class="card logcard">
     <div class="logbar">
       <h2>&#128220; Live log</h2>
       <span class="live"><i></i>live</span>
       <span class="sp"></span>
       <label class="chk" style="margin:0"><input type="checkbox" id="autofollow" checked> follow</label>
       <button id="logclear">Clear</button>
     </div>
     <div id="log"><span class="empty">waiting for the bot&#8230;</span></div>
   </div>
  </div>
 </div>

 <div class="foot">Cubic Castles bot console &#183; controls run directly on the bot</div>
</div>
<script>
 var TOKEN="__TOKEN__";
 function tok(first){return TOKEN?(first?"?":"&")+"token="+encodeURIComponent(TOKEN):"";}
 function q(s){return document.querySelector(s);}

 /* ---- status ---- */
 function refresh(){
   fetch("/status"+tok(true)).then(function(r){return r.json();}).then(function(j){
     if(j.offline){
       q("#dot").className="dot off";
       q("#stat").textContent="DISABLED — "+(j.account||"account")+" is logged off";
     } else {
       q("#dot").className="dot "+(j.connected?"on":"off");
       q("#stat").textContent=j.connected?("in realm: "+(j.realm||"?")):"bot not connected";
     }
     if(j.prize_found)markFound(j.prize_found);
   }).catch(function(){q("#dot").className="dot off";q("#stat").textContent="bot offline";});
 }

 /* ---- generic action helpers ---- */
 function show(j){var m=q("#msg");m.className="msg "+(j&&j.ok?"ok":"err");
   m.textContent=(j&&j.msg)||"done";}
 function act(path,btn){
   if(btn)btn.disabled=true;
   var sep=path.indexOf("?")>=0;
   fetch(path+tok(!sep)).then(function(r){return r.json();}).then(show)
    .catch(function(){q("#msg").className="msg err";
      q("#msg").textContent="couldn't reach the bot";})
    .then(function(){if(btn)setTimeout(function(){btn.disabled=false;},700);});
 }
 Array.prototype.forEach.call(document.querySelectorAll("button[data-act]"),
   function(b){b.addEventListener("click",function(){act(b.getAttribute("data-act"),b);});});

 /* ---- summon ---- */
 function summon(){
   var name=(q("#name").value||"").trim()||"frostyer";
   var b=q("#go"),m=q("#msg");
   b.disabled=true;m.className="msg";m.textContent="sending...";
   fetch("/tp?name="+encodeURIComponent(name)+tok(false)).then(function(r){return r.json();})
    .then(function(j){m.className="msg "+(j.ok?"ok":"err");m.textContent=j.msg;})
    .catch(function(){m.className="msg err";m.textContent="couldn't reach the bot";});
   setTimeout(function(){b.disabled=false;},1200);
 }
 q("#go").addEventListener("click",summon);

 /* ---- prize crack ---- */
 function prizeGo(){
   var nm=(q("#pname").value||"").trim();
   var xx=(q("#px").value||"").trim(),yy=(q("#py").value||"").trim(),zz=(q("#pz").value||"").trim();
   var hasCoords=xx&&yy&&zz;
   if(!nm&&!hasCoords){show({ok:false,msg:"type your X/Y/Z, or your name"});return;}
   var lo=(q("#plo").value||"0").trim(),hi=(q("#phi").value||"9999").trim();
   var off=(q("#poff").value||"0").trim();
   var tp=q("#ptp").checked?"1":"0";
   hideFound();ackedCode=null;   // fresh crack: allow the next win to surface
   act("/prizehere?name="+encodeURIComponent(nm)+"&off="+encodeURIComponent(off)
       +"&lo="+encodeURIComponent(lo)+"&hi="+encodeURIComponent(hi)+"&tp="+tp
       +"&x="+encodeURIComponent(xx)+"&y="+encodeURIComponent(yy)
       +"&z="+encodeURIComponent(zz),q("#pgo"));
 }
 q("#pgo").addEventListener("click",prizeGo);
 q("#pstop").addEventListener("click",function(){act("/prizestop",q("#pstop"));});

 /* ---- PASSWORD FOUND banner + tab title ---- */
 var origTitle=document.title, blinkTimer=null, shownFound=null, ackedCode=null;
 function setFav(emoji){
   var svg="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>"+emoji+"</text></svg>";
   var f=q("#favicon");if(f)f.setAttribute("href",svg);
 }
 function markFound(code){
   if(shownFound===code||ackedCode===code)return;   // don't reopen a dismissed one
   shownFound=code;
   q("#foundcode").textContent=code;
   var fnd=q("#found");fnd.classList.add("show");
   spark(fnd);
   setFav("&#127881;");
   var on=true;
   if(blinkTimer)clearInterval(blinkTimer);
   blinkTimer=setInterval(function(){
     document.title=(on?"🎉 PASSWORD FOUND — "+code:"⭐ "+code+" ⭐");
     on=!on;
   },900);
   document.title="🎉 PASSWORD FOUND — "+code;
 }
 function hideFound(){
   ackedCode=shownFound||q("#foundcode").textContent||ackedCode; // remember it stays hidden
   shownFound=null;q("#found").classList.remove("show");
   if(blinkTimer){clearInterval(blinkTimer);blinkTimer=null;}
   document.title=origTitle;setFav("&#127984;");
   // best-effort: tell the bot to drop the found flag so pollers stop resurfacing it
   fetch("/prizeack"+tok(true)).catch(function(){});
 }
 function spark(el){
   var e=["✨","🎊","⭐","🎉"];
   for(var i=0;i<7;i++){
     var s=document.createElement("span");s.className="spark";
     s.textContent=e[i%e.length];
     s.style.left=(6+Math.random()*88)+"%";
     s.style.bottom="6px";s.style.animationDelay=(Math.random()*2)+"s";
     el.appendChild(s);
   }
 }
 q("#foundcopy").addEventListener("click",function(){
   var c=q("#foundcode").textContent;
   if(navigator.clipboard)navigator.clipboard.writeText(c);
   this.textContent="Copied ✓";var self=this;
   setTimeout(function(){self.textContent="Copy code";},1500);
 });
 q("#foundclose").addEventListener("click",hideFound);

 /* ---- live log stream ---- */
 var logSeq=0, logEl=q("#log"), logStarted=false;
 function classify(t){
   var s=t.toLowerCase();
   if(s.indexOf("password found")>=0||s.indexOf(">>> password")>=0)return "win";
   if(s.indexOf("[prize]")>=0)return "prize";
   if(s.indexOf("[console]")>=0)return "console";
   if(s.indexOf("error")>=0||s.indexOf("can't")>=0||s.indexOf("fail")>=0||s.indexOf("abort")>=0)return "err";
   if(s.indexOf("warn")>=0||s.indexOf("busy")>=0||s.indexOf("retry")>=0)return "warn";
   return "";
 }
 function esc(s){return String(s).replace(/[&<>"]/g,function(c){
   return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
 function pollLogs(){
   fetch("/logs?since="+logSeq+tok(false)).then(function(r){return r.json();})
    .then(function(j){
      if(j.prize_found)markFound(j.prize_found);
      if(j.lines&&j.lines.length){
        if(!logStarted){logEl.innerHTML="";logStarted=true;}
        var follow=q("#autofollow").checked;
        var atBottom=logEl.scrollHeight-logEl.scrollTop-logEl.clientHeight<40;
        j.lines.forEach(function(ln){
          var d=document.createElement("div");
          d.className="l "+classify(ln.text);
          d.textContent=ln.text||" ";
          logEl.appendChild(d);
        });
        while(logEl.childNodes.length>800)logEl.removeChild(logEl.firstChild);
        if(follow&&atBottom)logEl.scrollTop=logEl.scrollHeight;
      }
      if(typeof j.seq==="number")logSeq=j.seq;
    }).catch(function(){});
 }
 q("#logclear").addEventListener("click",function(){
   logEl.innerHTML="";logStarted=true;
 });

 /* ---- approved users ---- */
 function renderApproved(list){
   var ul=q("#alist");ul.innerHTML="";
   if(!list||!list.length){ul.innerHTML='<li class="empty">no approved users yet</li>';return;}
   list.forEach(function(n){
     var li=document.createElement("li");
     li.innerHTML=esc(n)+' <button class="x" title="remove">×</button>';
     li.querySelector(".x").addEventListener("click",function(){removeApproved(n);});
     ul.appendChild(li);
   });
 }
 function loadApproved(){
   fetch("/approved"+tok(true)).then(function(r){return r.json();})
    .then(function(j){renderApproved(j.approved);}).catch(function(){});
 }
 function addApproved(){
   var n=(q("#aname").value||"").trim();if(!n)return;
   fetch("/approve?name="+encodeURIComponent(n)+tok(false)).then(function(r){return r.json();})
    .then(function(j){if(j.approved){renderApproved(j.approved);q("#aname").value="";}})
    .catch(function(){});
 }
 function removeApproved(n){
   fetch("/unapprove?name="+encodeURIComponent(n)+tok(false)).then(function(r){return r.json();})
    .then(function(j){if(j.approved)renderApproved(j.approved);}).catch(function(){});
 }
 q("#add").addEventListener("click",addApproved);
 q("#aname").addEventListener("keydown",function(e){if(e.key==="Enter")addApproved();});

 /* ---- live drive (WASD) ---- */
 var held={w:false,a:false,s:false,d:false};
 function heldStr(){var o=[];["w","a","s","d"].forEach(function(k){if(held[k])o.push(k);});return o.join(",");}
 function sendDrive(z){
   var qp="/drive?keys="+encodeURIComponent(heldStr());
   if(z)qp+="&z="+z;
   fetch(qp+tok(false)).catch(function(){});
   var s=heldStr().toUpperCase();q("#dstat").textContent=s||"—";
   Array.prototype.forEach.call(document.querySelectorAll("#dpad button[data-k]"),
     function(b){b.classList.toggle("held",!!held[b.getAttribute("data-k")]);});
 }
 function setKey(k,on){if(held[k]===on)return;held[k]=on;sendDrive(0);}
 function nudge(z){sendDrive(z);}
 function jump(){fetch("/jump"+tok(true)).catch(function(){});}
 function typing(){var a=document.activeElement;return a&&(a.tagName==="INPUT"||a.tagName==="TEXTAREA");}
 document.addEventListener("keydown",function(e){
   if(typing())return;
   var k=(e.key||"").toLowerCase();
   if(k===" "||e.code==="Space"){e.preventDefault();jump();return;}
   if(k==="q"||k==="r"){e.preventDefault();nudge(1);return;}
   if(k==="e"||k==="f"){e.preventDefault();nudge(-1);return;}
   if(k==="w"||k==="a"||k==="s"||k==="d"){e.preventDefault();if(!e.repeat)setKey(k,true);}
 });
 document.addEventListener("keyup",function(e){
   if(typing())return;
   var k=(e.key||"").toLowerCase();
   if(k==="w"||k==="a"||k==="s"||k==="d"){e.preventDefault();setKey(k,false);}
 });
 window.addEventListener("blur",function(){held={w:false,a:false,s:false,d:false};
   fetch("/drivestop"+tok(true)).catch(function(){});q("#dstat").textContent="—";
   Array.prototype.forEach.call(document.querySelectorAll("#dpad button[data-k]"),
     function(b){b.classList.remove("held");});});
 Array.prototype.forEach.call(document.querySelectorAll("#dpad button[data-k]"),
   function(b){var k=b.getAttribute("data-k");
     b.addEventListener("pointerdown",function(e){e.preventDefault();setKey(k,true);});
     b.addEventListener("pointerup",function(e){e.preventDefault();setKey(k,false);});
     b.addEventListener("pointerleave",function(){setKey(k,false);});
     b.addEventListener("pointercancel",function(){setKey(k,false);});});
 Array.prototype.forEach.call(document.querySelectorAll(".vpad button[data-z]"),
   function(b){b.addEventListener("click",function(){nudge(parseInt(b.getAttribute("data-z"),10));});});
 q("#jbtn").addEventListener("click",jump);
 q("#phys").addEventListener("change",function(){
   fetch("/physics?on="+(this.checked?1:0)+tok(false)).then(function(r){return r.json();})
    .then(function(j){q("#physinfo").textContent=(j.on?("on, "+j.blocks+" blocks"):"off (fly)");})
    .catch(function(){});
 });
 function pollPhys(){
   fetch("/physics"+tok(true)).then(function(r){return r.json();}).then(function(j){
     if(!j.on){q("#physinfo").textContent="off (fly)";return;}
     q("#physinfo").textContent=j.dbg||("on, "+j.blocks+" blocks");
   }).catch(function(){});
 }

 /* ---- trade popup buttons ---- */
 function tradeAct(action){
   fetch("/trade?action="+action+tok(false)).then(function(r){return r.json();})
    .then(function(j){var m=q("#msg");m.className="msg "+(j.ok?"ok":"err");m.textContent=j.msg;})
    .catch(function(){});
 }
 q("#tacc").addEventListener("click",function(){tradeAct("accept");});
 q("#tcon").addEventListener("click",function(){tradeAct("confirm");});
 q("#tdec").addEventListener("click",function(){tradeAct("cancel");});
 function pollTrade(){
   fetch("/tradestatus"+tok(true)).then(function(r){return r.json();}).then(function(j){
     var box=q("#tradebox");
     if(j.open){box.classList.add("show");
       var t=(j.name||"someone")+" opened a trade";
       if(j.staked)t+=" — they staked "+j.staked+"c";
       q("#tradett").textContent=t;
     } else box.classList.remove("show");
   }).catch(function(){});
 }

 /* ---- boot ---- */
 refresh();setInterval(refresh,4000);
 loadApproved();
 pollLogs();setInterval(pollLogs,1000);
 pollTrade();setInterval(pollTrade,2000);
 pollPhys();setInterval(pollPhys,1000);
</script></body></html>"""

    def _web_teleport(name):
        """Resolve a player name and queue a teleport to them — the same path the
        'tp' command uses. Returns (ok, message) for the browser."""
        name = (name or "").strip() or "frostyer"
        guid = find_guid(name)
        if not guid:
            return False, (f"don't know {name}'s GUID yet — add them as a friend "
                           f"(they must be online) or run 'guid {name}' in the "
                           f"bot once, then try again")
        depth = queue_move("guid", guid, f"console tp to {name}", autoscan=False)
        busy = bot_busy()
        show_line(f"  [console] button pressed -> {name} "
                  f"({'queued (busy)' if busy else 'on my way'}) ...")
        if busy:
            return True, f"queued — {name} is #{depth} in line (bot busy)"
        return True, f"on my way to {name}!"

    def start_control_server(port, host, token):
        import http.server, urllib.parse
        _acct = "".join(c for c in prof["identity"]["display_name"]
                        if c not in '<>&"')
        page = (CONSOLE_HTML.replace("__TOKEN__", (token or "").replace('"', ""))
                            .replace("__ACCOUNT__", _acct or "this account"))

        def _count_vends():
            """Sellable vending machines known for the CURRENT realm — the same
            filter publish_realm() uses for vends.json (matches by realm GUID, or
            by realm name as a fallback), skipping unsellable/zero-priced ones.
            `remote_scan["seq"]` (main scope) is bumped by scan_machines itself on
            every scan completion, so a poller sees it advance no matter HOW the
            scan was started (typed, remote, auto-Hollawarp, or a `guid` warp)."""
            guid = reg.get("guid")
            realm = state.get("realm")
            n = 0
            for rec in offers.values():
                if rec.get("realm_guid") == guid or rec.get("realm") == realm:
                    o = rec.get("offer") or {}
                    if not unsellable(o.get("price")):
                        n += 1
            return realm, guid, n

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass                       # don't spam the bot console

            def _cors(self):
                self.send_header("Access-Control-Allow-Origin", "*")

            def _send(self, code, body, ctype):
                if isinstance(body, str):
                    body = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self._cors()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

            def _json(self, code, obj):
                self._send(code, json.dumps(obj), "application/json")

            def do_OPTIONS(self):
                self.send_response(204)
                self._cors()
                self.end_headers()

            def do_GET(self):
                u = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(u.query)
                if u.path in ("/", "/console", "/index.html"):
                    self._send(200, page, "text/html; charset=utf-8")
                    return
                # Serve the browser tools (console-crack.js, pick.html, crack.html)
                # off the SAME port as the dashboard. Public like the page itself -
                # it's just tool source, no bot control. basename() blocks traversal.
                if u.path == "/console-crack.js" or u.path.startswith("/webtools/"):
                    import os
                    name = os.path.basename(u.path) or "index.html"
                    fp = os.path.join(_APP_DIR,
                                      "..", "webtools", name)
                    ctype = ("application/javascript; charset=utf-8" if name.endswith(".js")
                             else "text/html; charset=utf-8" if name.endswith(".html")
                             else "application/octet-stream")
                    try:
                        with open(fp, "rb") as f:
                            self._send(200, f.read(), ctype)
                    except OSError:
                        self._json(404, {"ok": False, "msg": "not found: " + name})
                    return
                if token and qs.get("token", [""])[0] != token:
                    self._json(403, {"ok": False, "msg": "bad token"})
                    return
                if u.path == "/status":
                    self._json(200, {"ok": True,
                                     "connected": bool(conn.get("own")),
                                     "offline": bool(manual_offline["on"]),
                                     "account": prof["identity"]["display_name"],
                                     "realm": state.get("realm"),
                                     "prize_active": bool(prize_ctl.get("active")),
                                     "prize_found": prize_ctl.get("found"),
                                     "webhook_set": bool(
                                         (webhook.get("url") or "").strip()),
                                     "webhook_prize": bool(
                                         webhook.get("prize", True)),
                                     "webhook_snipe": bool(
                                         webhook.get("snipe", True)),
                                     "log_seq": log_seq["n"]})
                    return
                if u.path == "/disable":         # log THIS account off, stay off
                    ok, msg = go_offline("web console")
                    self._json(200, {"ok": ok, "msg": msg,
                                     "offline": bool(manual_offline["on"])})
                    return
                if u.path == "/enable":          # log THIS account back on
                    ok, msg = go_online()
                    self._json(200 if ok else 500, {"ok": ok, "msg": msg,
                                     "offline": bool(manual_offline["on"])})
                    return
                if u.path == "/logs":
                    try:
                        since = int(qs.get("since", ["0"])[0])
                    except ValueError:
                        since = 0
                    with log_lock:
                        rows = [{"seq": s, "text": t}
                                for (s, t) in log_ring if s > since]
                        last = log_seq["n"]
                    self._json(200, {"ok": True, "lines": rows, "seq": last,
                                     "prize_found": prize_ctl.get("found"),
                                     "prize_active": bool(prize_ctl.get("active"))})
                    return
                if u.path == "/tp":
                    ok, msg = _web_teleport(qs.get("name", ["frostyer"])[0])
                    self._json(200 if ok else 404, {"ok": ok, "msg": msg})
                    return
                if u.path == "/join":                # DEBUG: join a realm by GUID
                    g = qs.get("guid", [""])[0].strip()
                    if len(g) == 32:
                        queue_move("join", g, f"debug join {g[:8]}…")
                        self._json(200, {"ok": True, "msg": f"queued join {g[:8]}"})
                    else:
                        self._json(400, {"ok": False, "msg": "need 32-hex guid"})
                    return
                # ---- approved-user allowlist management -------------------
                if u.path == "/approved":
                    self._json(200, {"ok": True, "approved": sorted(approved)})
                    return
                if u.path == "/approve":
                    nm = qs.get("name", [""])[0].strip().lstrip("@").lower()
                    if not nm:
                        self._json(400, {"ok": False, "msg": "name required"})
                        return
                    approved.add(nm)
                    save_approved()
                    show_line(f"  [console] approved {nm}")
                    self._json(200, {"ok": True, "msg": f"approved {nm}",
                                     "approved": sorted(approved)})
                    return
                if u.path == "/unapprove":
                    nm = qs.get("name", [""])[0].strip().lstrip("@").lower()
                    approved.discard(nm)
                    save_approved()
                    show_line(f"  [console] unapproved {nm}")
                    self._json(200, {"ok": True, "msg": f"removed {nm}",
                                     "approved": sorted(approved)})
                    return
                # ---- clickable GUI actions (buttons call bot functions) ------
                if u.path == "/wander":
                    on = qs.get("on", ["1"])[0] not in ("0", "off", "false")
                    wander["on"] = on
                    if not on:
                        wander["active"] = False
                    self._json(200, {"ok": True,
                                     "msg": "wander " + ("ON" if on else "OFF")})
                    return
                if u.path == "/freeze":
                    on = qs.get("on", ["1"])[0] not in ("0", "off", "false")
                    movelock["frozen"] = on
                    if on:
                        wander["active"] = False
                    self._json(200, {"ok": True, "msg": "movement " +
                                     ("FROZEN — bot won't move at all" if on
                                      else "UNFROZEN")})
                    return
                if u.path == "/hwarp":
                    on = qs.get("on", ["1"])[0] not in ("0", "off", "false")
                    hollow["auto"] = on
                    if on and hollow["q"] and not hollow["driver"]:
                        threading.Thread(target=warp_driver, daemon=True).start()
                    self._json(200, {"ok": True, "msg": "auto-Hollawarp "
                                     + ("ON" if on else "OFF")})
                    return
                if u.path == "/scan":
                    if scanning.is_set() or bot_busy():
                        self._json(200, {"ok": False,
                                         "msg": "busy right now — try again shortly",
                                         "scanning": True,
                                         "seq": remote_scan["seq"],
                                         "realm": state.get("realm")})
                    else:
                        threading.Thread(target=scan_machines,
                                         daemon=True).start()
                        self._json(200, {"ok": True,
                                         "msg": "scanning this realm…",
                                         "scanning": True,
                                         "seq": remote_scan["seq"],
                                         "realm": state.get("realm")})
                    return
                if u.path == "/items":
                    # Distinct item names this bot has scanned (from the vends
                    # catalogue) — fed to the relay so Discord /market can offer
                    # autocomplete of only items we actually have data for.
                    names = set()
                    for e in vends.values():
                        for m in (e.get("machines") or []):
                            it = (m.get("item") or "").strip()
                            if it:
                                names.add(it)
                    self._json(200, {"ok": True, "items": sorted(names)})
                    return
                if u.path == "/scanstatus":
                    # Cheap poll for a remote (Discord) scan: is a scan running,
                    # how many vends so far, and the completion counter. The caller
                    # started the scan at some seq S and treats seq > S as "the
                    # whole realm is scanned" (see _remote_scan_run).
                    realm, guid, n = _count_vends()
                    self._json(200, {"ok": True,
                                     "scanning": bool(scanning.is_set()),
                                     "seq": remote_scan["seq"],
                                     "realm": realm, "vends": n, "guid": guid})
                    return
                if u.path == "/park":
                    threading.Thread(target=go_to_waiting,
                                     kwargs={"lead": ""}, daemon=True).start()
                    self._json(200, {"ok": True, "msg": "heading to the park realm…"})
                    return
                if u.path == "/prizestop":
                    prize_ctl["stop"] = True
                    self._json(200, {"ok": True, "msg": "stopping the prize crack"})
                    return
                if u.path == "/cmd":
                    # run ANY console command (the team console routes f/w/b here
                    # over HTTP instead of the FIFO). The command loop drains
                    # console_inject exactly like a FIFO / typed line.
                    line = qs.get("line", [""])[0].strip()
                    if not line:
                        self._json(400, {"ok": False, "msg": "empty command"})
                        return
                    console_inject.append(line)
                    self._json(200, {"ok": True, "msg": f"queued: {line}"})
                    return
                if u.path == "/runcmd":
                    # Like /cmd, but runs the command and returns ONLY the log
                    # lines it produced — a precise capture for remote (Discord)
                    # control. The rolling /logs feed interleaves live chat and
                    # events, so a poll-and-window approach loses the answer in a
                    # busy realm; here we snapshot the log sequence, inject the
                    # command, and wait for its output to settle, then return the
                    # exact lines produced. (Ambient chat that lands in the same
                    # instant is filtered by the caller.)
                    line = qs.get("line", [""])[0].strip()
                    if not line:
                        self._json(400, {"ok": False, "msg": "empty command"})
                        return
                    with log_lock:
                        base = log_seq["n"]
                    console_inject.append(line)
                    deadline = time.time() + 6.0
                    last_n = base
                    last_change = time.time()
                    consumed = False
                    while time.time() < deadline:
                        time.sleep(0.1)
                        if not consumed and line not in console_inject:
                            consumed = True     # command loop picked it up
                        with log_lock:
                            n = log_seq["n"]
                        if n != last_n:
                            last_n = n
                            last_change = time.time()
                        quiet = time.time() - last_change
                        # done: consumed + produced output that's now settled ...
                        if consumed and n > base and quiet > 0.7:
                            break
                        # ... or consumed + produced nothing after a short grace.
                        if consumed and n == base and quiet > 1.2:
                            break
                    with log_lock:
                        rows = [t for (s, t) in log_ring if s > base]
                    self._json(200, {"ok": True, "lines": rows})
                    return
                if u.path == "/prizeblock":
                    # Crack an EXPLICIT dispenser block over a range, optionally
                    # descending. Used by the team split (front ascends its half,
                    # worker descends its half). Freezes movement so the bot arms
                    # from where it stands. Reliable HTTP path — no FIFO.
                    if prize_ctl.get("active"):
                        self._json(200, {"ok": False,
                                         "msg": "a prize crack is already running "
                                                "here — stop it first"})
                        return
                    try:
                        bx = int(qs.get("bx", [""])[0])
                        by = int(qs.get("by", [""])[0])
                        bz = int(qs.get("bz", [""])[0])
                        lo = int(qs.get("lo", ["0"])[0])
                        hi = int(qs.get("hi", ["9999"])[0])
                        delay = float(qs.get("delay", ["0.1"])[0])
                    except ValueError:
                        self._json(400, {"ok": False,
                                         "msg": "bx/by/bz/lo/hi must be integers, "
                                                "delay a number"})
                        return
                    if lo < 0 or hi < lo:
                        self._json(400, {"ok": False,
                                         "msg": "bad range: need 0 <= lo <= hi"})
                        return
                    desc = qs.get("desc", ["0"])[0] in ("1", "on", "true",
                                                        "yes", "down")
                    # hold still so arming works from right here
                    movelock["frozen"] = True
                    wander["on"] = False
                    wander["active"] = False
                    threading.Thread(
                        target=run_prize_crack,
                        args=(lo, hi, (bx, by, bz), max(0.0, delay)),
                        kwargs={"descending": desc},
                        daemon=True).start()
                    arrow = "down from " + str(hi) if desc else "up from " + str(lo)
                    self._json(200, {"ok": True,
                                     "msg": f"cracking {lo}-{hi} {arrow} on block "
                                            f"({bx},{by},{bz})"})
                    return
                if u.path == "/prizeack":
                    # browser dismissed the "password found" banner — clear the
                    # flag so /status and /logs stop resurfacing it every poll
                    prize_ctl["found"] = None
                    self._json(200, {"ok": True, "msg": "cleared"})
                    return
                if u.path == "/prizehere":
                    if prize_ctl.get("active"):
                        self._json(200, {"ok": False,
                                         "msg": "a prize crack is already running"})
                        return
                    nm = qs.get("name", [""])[0].strip()
                    # MANUAL COORDS (from the on-screen S X/Y/Z) — the reliable path:
                    # no teleport, no position tracking. If given, name isn't needed.
                    mx = qs.get("x", [""])[0].strip()
                    my = qs.get("y", [""])[0].strip()
                    mz = qs.get("z", [""])[0].strip()
                    manual = None
                    if mx or my or mz:
                        try:
                            manual = (int(mx), int(my), int(mz))
                        except ValueError:
                            self._json(400, {"ok": False, "msg": "x / y / z must "
                                             "all be numbers (or all blank)"})
                            return
                    g = who = None
                    if not manual:
                        if not nm:
                            self._json(400, {"ok": False, "msg": "type your coords "
                                             "(the S X/Y/Z on your screen), or your "
                                             "in-game name"})
                            return
                        g = find_player_by_name(nm)
                        own = conn.get("own")
                        if g and g == own:
                            self._json(404, {"ok": False, "msg": f"'{nm}' matched ME "
                                             "(the bot). Type YOUR coords instead."})
                            return
                        if not g:
                            seen = (", ".join(sorted(players.values()))
                                    or "(nobody yet)")
                            self._json(404, {"ok": False, "msg": f"never seen '{nm}'"
                                             f". Players I know: {seen}. Or just "
                                             "type your coords."})
                            return
                        who = players.get(g, nm)
                    try:
                        off = int(qs.get("off", ["2"])[0])
                        lo = int(qs.get("lo", ["0"])[0])
                        hi = int(qs.get("hi", ["9999"])[0])
                    except ValueError:
                        self._json(400, {"ok": False,
                                         "msg": "off/lo/hi must be numbers"})
                        return
                    # default OFF: use EXACTLY `off` below the player (a packed shop
                    # has many machines, so auto-find grabs the wrong one). Opt in
                    # with &auto=1 only if you're not sure where the machine is.
                    auto = qs.get("auto", ["0"])[0] in ("1", "on", "true", "yes")
                    do_tp = qs.get("tp", ["0"])[0] in ("1", "on", "true", "yes")

                    def _prize_op():
                        was_frozen = movelock["frozen"]
                        was_wander = wander["on"]
                        # FREEZE up front so the bot NEVER runs — it arms from right
                        # where it's standing (next to you), no walking to the block.
                        movelock["frozen"] = True
                        wander["on"] = False
                        wander["active"] = False
                        try:
                            if manual:
                                # you typed your on-screen coords — most reliable
                                cbx, cby, cbz = manual
                                show_line(f"  [prize] using typed coords "
                                          f"({cbx},{cby},{cbz}) — no teleport")
                            elif do_tp:
                                # teleport ONTO the player for a fresh exact spot,
                                # then hold absolutely still
                                show_line(f"  [prize] teleporting to {who}…")
                                prev = (pos["x"], pos["y"], pos["z"])
                                queue_move("guid", g, f"prize: go to {who}",
                                           autoscan=False)
                                deadline = time.time() + 45
                                while time.time() < deadline and not stop.is_set():
                                    if stop.wait(0.4):
                                        return
                                    if (not switching.is_set() and pos["placed"]
                                            and (pos["x"], pos["y"], pos["z"])
                                            != prev):
                                        break
                                stop.wait(1.0)
                                cbx = pos["x"] // P.COORD_BASE
                                cby = pos["y"] // P.COORD_BASE
                                cbz = pos["z"] // P.COORD_BASE
                                show_line(f"  [prize] landed on {who} at "
                                          f"({cbx},{cby},{cbz})")
                            else:
                                # NO teleport — use the player's tracked position
                                if g not in player_block:
                                    show_line(f"  [prize] no tracked position for "
                                              f"{who} yet — tick 'teleport to me', "
                                              f"or have {who} take a step near me")
                                    return
                                cbx, cby, cbz = player_block[g]
                                show_line(f"  [prize] using {who}'s tracked spot "
                                          f"({cbx},{cby},{cbz}) — no teleport")
                            prim = (cbx, cby, cbz + off)   # `off` below (default +2)
                            mb = None
                            query_many([prim])
                            if (qcache.get(prim) or {}).get("kind") == 0x13:
                                mb = prim
                                show_line(f"  [prize] {off} below IS a Prize "
                                          f"Dispenser — {mb}")
                            elif auto:
                                mb = find_dispenser_near(cbx, cby, cbz)
                                if mb:
                                    show_line(f"  [prize] found the dispenser at {mb}")
                                else:
                                    show_line("  [prize] none found nearby — trying "
                                              f"{prim}")
                            if not mb:
                                mb = prim
                            # NO walking — arm straight from where we stand
                            show_line(f"  [prize] arming {mb} (no walking)")
                            run_prize_crack(lo, hi, mb, 0.1)
                        finally:
                            movelock["frozen"] = was_frozen
                            wander["on"] = was_wander
                    threading.Thread(target=_prize_op, daemon=True).start()
                    src = (f"your coords {manual}" if manual
                           else f"teleporting to {who}" if do_tp
                           else f"{who}'s tracked spot")
                    self._json(200, {"ok": True, "msg": f"using {src}; arming "
                                     f"{off} below and cracking {lo}–{hi} — watch "
                                     "the bot console"})
                    return
                # ---- live WASD driving --------------------------------------
                if u.path == "/drive":
                    # keys=w,a,s,d — the FULL set currently held (sent on each
                    # keydown/keyup); z=1 (up) / z=-1 (down) is a one-shot nudge.
                    raw = qs.get("keys", [""])[0].lower()
                    held = {k for k in raw.replace(" ", "").split(",")
                            if k in ("w", "a", "s", "d")}
                    drive["keys"] = held
                    try:
                        z = int(qs.get("z", ["0"])[0])
                    except ValueError:
                        z = 0
                    if z:
                        drive["z"] = 1 if z > 0 else -1
                    self._json(200, {"ok": True, "keys": sorted(held),
                                     "placed": bool(pos["placed"]),
                                     "msg": ("".join(sorted(held)).upper()
                                             or "stop")})
                    return
                if u.path == "/drivestop":
                    drive["keys"] = set()
                    drive["z"] = 0
                    self._json(200, {"ok": True, "msg": "stop"})
                    return
                if u.path == "/physics":
                    if "on" in qs:
                        physics["on"] = qs.get("on", ["1"])[0] not in (
                            "0", "off", "false")
                    if qs.get("flip", ["0"])[0] in ("1", "on", "true", "yes"):
                        physics["down"] = -physics["down"]
                        physics["calibrated"] = True
                    if qs.get("recal", ["0"])[0] in ("1", "on", "true", "yes"):
                        physics["calibrated"] = False
                    self._json(200, {"ok": True, "on": physics["on"],
                                     "down": physics["down"],
                                     "blocks": len(solid_set()),
                                     "dbg": physics.get("dbg", ""),
                                     "msg": ("physics " +
                                             ("ON — collision + gravity"
                                              if physics["on"] else
                                              "OFF — fly, no collision"))})
                    return
                if u.path == "/jump":
                    if args.no_avatar or not pos["placed"]:
                        self._json(200, {"ok": False,
                                         "msg": "not placed in a realm yet"})
                    else:
                        do_jump()
                        self._json(200, {"ok": True, "msg": "jump!"})
                    return
                if u.path == "/trade":
                    # action=accept|confirm|cancel — manual trade-popup buttons
                    ok, msg = manual_trade_action(
                        qs.get("action", [""])[0].strip().lower())
                    self._json(200 if ok else 400, {"ok": ok, "msg": msg})
                    return
                if u.path == "/tradestatus":
                    self._json(200, {"ok": True,
                                     "open": bool(last_trade.get("open")),
                                     "name": last_trade.get("name"),
                                     "staked": last_trade.get("staked", 0),
                                     "our": last_trade.get("our", 0)})
                    return
                self._json(404, {"ok": False, "msg": "unknown path"})

        try:
            httpd = http.server.ThreadingHTTPServer((host, port), H)
        except OSError as e:
            show_line(f"  [console] can't start on {host}:{port} — {e}")
            return False
        webctl.update(httpd=httpd, host=host, port=port)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        shown = "<this-PC-LAN-IP>" if host == "0.0.0.0" else host
        show_line(f"  [console] open http://{shown}:{port}/ in a browser — the "
                  f"button teleports the bot to the name shown"
                  + ("   (LAN-exposed — set --control-token to lock it)"
                     if host == "0.0.0.0" else ""))
        return True

    def stop_control_server():
        if not webctl["httpd"]:
            return False
        try:
            webctl["httpd"].shutdown()
        except Exception:
            pass
        webctl["httpd"] = None
        return True

    # ----------------------------------------------------------------------
    # public market site  (read-only, no bot control)
    # ----------------------------------------------------------------------
    # Deliberately a SEPARATE server on its own port from the control console.
    # The console can teleport the bot; this one can only read prices. Keeping
    # them apart means you can forward/tunnel the public port to the internet
    # without any route that moves the bot being reachable from outside.
    # Everything here is GET-only and touches no mutable state.

    def _pub_rows(term=None, limit=0):
        rows = market_rows(term or None)
        return rows[:limit] if limit else rows

    def _pub_build(path, q, days, hours, limit):
        """Return (body, content_type) for a public route. Raises KeyError for
        an unknown path and RuntimeError when a route needs the history DB and
        it isn't open."""
        if path in ("/", "/index.html", "/market.html"):
            rows = _pub_rows(q)
            realms = len({r["realm"] for r in rows})
            title = (f"Cubic Castles market — '{q}'" if q
                     else "Cubic Castles market")
            html = _MARKET_HTML.replace("__TITLE__", _hesc(title)) \
                .replace("__ROWS__", str(len(rows))) \
                .replace("__REALMS__", str(realms)) \
                .replace("__WHEN__", time.strftime("%Y-%m-%d %H:%M")) \
                .replace("__DATA__", json.dumps(rows, ensure_ascii=False))
            return html, "text/html; charset=utf-8"
        if path == "/market.json":
            return (json.dumps(_pub_rows(q, limit), ensure_ascii=False),
                    "application/json; charset=utf-8")
        if path == "/market.csv":
            buf = io.StringIO()
            w = csv.DictWriter(buf, fieldnames=MARKET_FIELDS)
            w.writeheader()
            w.writerows(_pub_rows(q, limit))
            return buf.getvalue(), "text/csv; charset=utf-8"
        # --- routes below need the SQLite history DB ---
        if path in ("/history.json", "/changes.json", "/stats.json"):
            if mdb is None:
                raise RuntimeError("history DB not open (running JSON-only)")
            if path == "/history.json":
                if not q:
                    raise ValueError("history.json needs ?item=<name>")
                out = mdb.item_history(q, days=days)
            elif path == "/changes.json":
                out = mdb.price_changes(hours=hours)
            else:
                out = public_stats()
            if limit and isinstance(out, list):
                out = out[:limit]
            return (json.dumps(out, ensure_ascii=False, default=str),
                    "application/json; charset=utf-8")
        if path == "/health":
            return (json.dumps({"ok": True, "listings": len(market_rows()),
                                "history_db": mdb is not None,
                                "generated": time.strftime("%Y-%m-%d %H:%M")}),
                    "application/json; charset=utf-8")
        raise KeyError(path)

    def _pub_cached(path, q, days, hours, limit):
        """_pub_build behind the TTL cache. /health is never cached."""
        ttl = max(0.0, float(args.public_cache))
        key = (path, q, days, hours, limit)
        if ttl and path != "/health":
            with pubcache_lock:
                hit = pubcache.get(key)
                if hit and (time.time() - hit[0]) < ttl:
                    return hit[1], hit[2]
        body, ctype = _pub_build(path, q, days, hours, limit)
        if ttl and path != "/health":
            with pubcache_lock:
                if len(pubcache) > 64:      # bound it: distinct ?q= are endless
                    pubcache.clear()
                pubcache[key] = (time.time(), body, ctype)
        return body, ctype

    def start_public_server(port, host):
        import http.server, urllib.parse

        class P_(http.server.BaseHTTPRequestHandler):
            server_version = "cc-market"
            sys_version = ""

            def log_message(self, *a):
                pass                       # don't spam the bot console

            def _send(self, code, body, ctype, cache=None):
                if isinstance(body, str):
                    body = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                # Public read-only data: let anyone embed/fetch it.
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control",
                                 f"public, max-age={int(cache)}" if cache
                                 else "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    try:
                        self.wfile.write(body)
                    except OSError:
                        pass

            def _err(self, code, msg):
                self._send(code, json.dumps({"ok": False, "msg": msg}),
                           "application/json; charset=utf-8")

            def do_GET(self):
                u = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(u.query)

                def one(name, default=""):
                    return qs.get(name, [default])[0]

                def num(name):
                    v = one(name)
                    try:
                        return int(v) if v else None
                    except ValueError:
                        return None

                # A search term is free text from the internet — cap it so a
                # huge query can't be used to make us build giant cache keys.
                q = (one("q") or one("item") or one("search"))[:80].strip()
                limit = num("limit") or 0
                limit = max(0, min(limit, 100000))
                try:
                    body, ctype = _pub_cached(u.path, q, num("days"),
                                              num("hours"), limit)
                except KeyError:
                    self._err(404, "unknown path — try /, /market.json, "
                                   "/market.csv, /history.json?item=, "
                                   "/changes.json, /stats.json, /health")
                except ValueError as e:
                    self._err(400, str(e))
                except RuntimeError as e:
                    self._err(503, str(e))
                except Exception as e:
                    self._err(500, f"{type(e).__name__}: {e}")
                else:
                    self._send(200, body, ctype,
                               cache=int(float(args.public_cache)))

            do_HEAD = do_GET

            def do_POST(self):             # read-only site: nothing to post to
                # Drain the body first. Scanners POST with one, and replying
                # without reading it makes the peer see a connection reset
                # instead of the 405. Cap it so a huge body isn't read into RAM.
                try:
                    n = min(int(self.headers.get("Content-Length") or 0),
                            1 << 20)
                    while n > 0:
                        chunk = self.rfile.read(min(n, 65536))
                        if not chunk:
                            break
                        n -= len(chunk)
                except (ValueError, OSError):
                    pass
                self._err(405, "read-only")

            do_PUT = do_DELETE = do_PATCH = do_POST

        try:
            httpd = http.server.ThreadingHTTPServer((host, port), P_)
        except OSError as e:
            show_line(f"  [public] can't start on {host}:{port} — {e}")
            return False
        pubweb.update(httpd=httpd, host=host, port=port)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        shown = "<this-PC-LAN-IP>" if host == "0.0.0.0" else host
        show_line(f"  [public] market site on http://{shown}:{port}/ — "
                  f"read-only prices + history, no bot control on this port")
        return True

    def stop_public_server():
        if not pubweb["httpd"]:
            return False
        try:
            pubweb["httpd"].shutdown()
        except Exception:
            pass
        pubweb["httpd"] = None
        return True

    if args.control_port:
        start_control_server(args.control_port, args.control_host,
                             args.control_token)
    if args.public_port:
        start_public_server(args.public_port, args.public_host)

    # PRIZE CRACKER (Stage 12, PRIZE.md): brute-force a Password Sentry's numeric
    # code by firing tx 0x0040 guesses while parked ON the machine. Runs in a
    # background thread so the console stays responsive; `prize stop` aborts.
    prize_ctl = {"active": False, "stop": False, "found": None, "found_at": 0}

    # PLOT BUMPER auto-renter (Stage 13, cubic-castles-plot-bumper). Poll a
    # bumper block on a tight interval; the instant its rental frees, confirm the
    # rent dialog (YES, spends 10 Cubits). Meant to be started inside the last few
    # minutes of someone else's rental, parked on the bumper. Runs in a background
    # thread so the console stays live; `plotbump stop` aborts.
    plotbump_ctl = {"active": False, "stop": False}

    # OUTLINE FILLER (Stage 22, cubic-castles-outline-filler). A player builds a
    # CLOSED border of blocks on one flat layer; the bot floods the enclosed
    # interior with whatever block it HOLDS (see `hold`), walking to each empty
    # cell and placing there. Reuses the passive `world` object burst (same source
    # as `blocks`) to see the outline — sends nothing to find it. Runs in a
    # background thread so the console stays live; `fill stop` aborts.
    fill_ctl = {"active": False, "stop": False}

    def outline_layer_cells(z):
        """(bx,by) of every PLACED (grid-aligned) block sitting on layer bz==z,
        read from the already-received realm object burst. Off-grid objects are
        loose/dropped items, not built blocks (same rule `blocks` uses), so they
        never count as part of the outline."""
        B = P.COORD_BASE
        occ = set()
        for o in world.values():
            if o.get("bz") != z:
                continue
            if o.get("x", 0) % B == 0 and o.get("y", 0) % B == 0:
                occ.add((o["bx"], o["by"]))
        return occ

    def flood_interior(z, seed, max_cells=6000):
        """Flood-fill the EMPTY cells enclosed by the outline on layer z, starting
        from `seed`=(bx,by). Returns (interior_set, reason). reason is None on
        success, else a string saying why NOTHING should be filled:
          'no-outline' too few border blocks on this layer
          'on-border'  the seed is a border block, or sits outside the outline
          'open'       the flood leaked past the outline (border isn't closed)
          'too-big'    more than max_cells empty cells (open, or just huge)
        The outline's bounding box grown by one ring is an escape fence: a truly
        CLOSED loop can never leak past it, so any leak proves the outline is open
        — and that is the safety that stops a fill from flooding the whole realm.
        Placement decisions live in the caller; this only decides WHERE."""
        occ = outline_layer_cells(z)
        if len(occ) < 4:
            return set(), "no-outline"
        if seed in occ:
            return set(), "on-border"
        xs = [c[0] for c in occ]
        ys = [c[1] for c in occ]
        x0, x1 = min(xs) - 1, max(xs) + 1        # fence = bbox + a 1-cell ring
        y0, y1 = min(ys) - 1, max(ys) + 1
        if not (x0 < seed[0] < x1 and y0 < seed[1] < y1):
            return set(), "on-border"            # seed isn't inside the outline
        seen = set()
        frontier = [seed]
        while frontier:
            c = frontier.pop()
            if c in seen or c in occ:
                continue
            cx, cy = c
            if cx <= x0 or cx >= x1 or cy <= y0 or cy >= y1:
                return set(), "open"             # reached the fence -> leaked out
            seen.add(c)
            if len(seen) > max_cells:
                return set(), "too-big"
            frontier.extend([(cx + 1, cy), (cx - 1, cy),
                             (cx, cy + 1), (cx, cy - 1)])
        return seen, None

    # VERIFIED BLUEPRINT BUILDER.  The reusable state machine lives outside this
    # monolithic client; these hooks are the narrow live boundary.  Every action
    # is locked to one exact realm and one rectangular test area, resolves the
    # desired catalogue item to its current inventory slot, waits for an own-
    # inventory decrement, then requires independent typed server terrain.
    # Live arming currently fails closed: the complete terrain decoder and
    # authoritative movement acknowledgements are not implemented (see research).
    build_query_gate = threading.Lock()
    build_audit_lock = threading.Lock()
    build_audit_path = os.path.join(_APP_DIR, "building-live.jsonl")

    def _own_inventory_snapshot():
        with player_inventory["lock"]:
            snap = player_inventory["snapshot"]
            if not snap:
                return None
            out = dict(snap)
            out["items"] = [dict(item) for item in snap.get("items", ())]
            return out

    def _wait_inventory_after(sequence, timeout):
        deadline = time.time() + max(0.0, timeout)
        while not stop.is_set() and time.time() <= deadline:
            with player_inventory["lock"]:
                snap = player_inventory["snapshot"]
                if snap and int(snap.get("seq", 0)) > sequence:
                    out = dict(snap)
                    out["items"] = [dict(item) for item in snap.get("items", ())]
                    return out
                player_inventory["event"].clear()
            left = deadline - time.time()
            if left <= 0:
                break
            player_inventory["event"].wait(min(0.25, left))
        return None

    def _building_world_health():
        if stop.is_set() or switching.is_set() or not pos.get("placed"):
            return False, "not stably placed in a realm"
        if not state.get("realm"):
            return False, "realm identity has not arrived"
        if world_diag["dropped"]:
            return False, (f"{world_diag['dropped']} malformed world frame(s) "
                           "were dropped")
        if world_diag["frames"] <= 0 or not world_rx["last"]:
            return False, "no complete server world-object frame received"
        quiet_for = time.time() - world_rx["last"]
        if quiet_for < max(0.5, args.settle_quiet):
            return False, f"world data is still arriving ({quiet_for:.2f}s quiet)"
        if time.time() - net["last_rx"] > 15.0:
            return False, "server connection is stale"
        # This describes only object-stream health, not the complete terrain.
        # _calibrate_ground can mutate local pos, so it must not run here.
        return True, "object stream settled; terrain coverage checked separately"

    def _building_world_objects():
        return list(world.values())

    def _building_query_one(coordinate, timeout):
        with build_query_gate:
            return query_block(*coordinate, timeout=timeout)

    def _building_query_many(coordinates):
        with build_query_gate:
            return query_many(coordinates, timeout=12.0,
                              quiet=max(0.6, args.settle_quiet))

    def _building_audit(event, fields):
        # Deliberately credential-free: realm, item id/name, coordinates, counts
        # and outcomes only.  Raw frames, player GUIDs and session material never
        # enter this file.
        record = {"time": time.strftime("%Y-%m-%d %H:%M:%S"),
                  "event": event}
        record.update(dict(fields))
        try:
            with build_audit_lock:
                with open(build_audit_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            show_line(f"[build] couldn't write audit log: {exc}")

    def _building_connected():
        ws = conn.get("ws")
        return bool(not stop.is_set() and not switching.is_set() and ws
                    and getattr(ws, "connected", True)
                    and time.time() - net["last_rx"] <= 15.0)

    def _building_position():
        return (pos["x"] // CB, pos["y"] // CB, pos["z"] // CB)

    def _building_area_verified(_area):
        return False, ("the current client decodes placed objects, not a complete "
                       "terrain grid with realm bounds and supporting ground; "
                       "query silence cannot establish buildable empty cells")

    def _building_path(start, goal, bounds, blocked):
        """Small 2-D BFS inside the authorized rectangle, avoiding known solids."""
        x0, y0, _z0, x1, y1, _z1 = bounds
        if not (x0 <= start[0] <= x1 and y0 <= start[1] <= y1
                and x0 <= goal[0] <= x1 and y0 <= goal[1] <= y1):
            return None
        blocked = set(blocked)
        blocked.discard(start)
        if goal in blocked:
            return None
        todo = collections.deque([start])
        prev = {start: None}
        while todo:
            cell = todo.popleft()
            if cell == goal:
                break
            x, y = cell
            for nxt in ((x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)):
                if (nxt in prev or nxt in blocked
                        or not (x0 <= nxt[0] <= x1 and y0 <= nxt[1] <= y1)):
                    continue
                prev[nxt] = cell
                todo.append(nxt)
        if goal not in prev:
            return None
        path, cur = [], goal
        while cur is not None:
            path.append(cur)
            cur = prev[cur]
        path.reverse()
        return path

    def _building_move_within_reach(target, reach, area):
        controller = build_runtime.get("controller")
        if not controller or state.get("realm") != controller.expected_realm:
            return False
        x0, y0, z0, x1, y1, z1 = area
        tx, ty, tz = target
        if not (x0 <= tx <= x1 and y0 <= ty <= y1 and z0 <= tz <= z1):
            return False

        solids = set(solid_set()) | set(controller.confirmed_types)
        here = _building_position()
        # Candidate routing only: live use is gated on authoritative terrain and
        # a matching server position acknowledgement. Neither is established by
        # walk_to's optimistic local coordinates. Keep Z fixed throughout.
        stand_z = controller.origin[2] - 1
        if here[2] != stand_z or abs(stand_z - tz) > reach:
            return False
        candidates = []
        for dx in range(-reach, reach + 1):
            for dy in range(-reach, reach + 1):
                if dx * dx + dy * dy + (stand_z - tz) ** 2 > reach * reach:
                    continue
                c = (tx + dx, ty + dy, stand_z)
                if not (x0 <= c[0] <= x1 and y0 <= c[1] <= y1):
                    continue
                if c in solids and c != target:
                    continue
                # An installed authoritative area hook must prove this floor.
                candidates.append((c == target,
                                   abs(c[0] - here[0]) + abs(c[1] - here[1]),
                                   abs(dx) + abs(dy), c))
        if not candidates:
            return False
        candidates.sort()
        stand = candidates[0][-1]

        # Route at the current body level and avoid every known solid on that
        # layer. The BFS never leaves the recorded test-area rectangle.
        start_xy, goal_xy = here[:2], stand[:2]
        blocked = {(x, y) for x, y, z in solids if z == here[2]}
        path = _building_path(start_xy, goal_xy, area, blocked)
        if path is None:
            return False
        # Compress the cell path to corners; walk_to handles each straight leg.
        waypoints = []
        last_dir = None
        for i in range(1, len(path)):
            direction = (path[i][0] - path[i - 1][0],
                         path[i][1] - path[i - 1][1])
            if last_dir is not None and direction != last_dir:
                waypoints.append(path[i - 1])
            last_dir = direction
        if path:
            waypoints.append(path[-1])

        began = time.time()
        was_frozen = movelock["frozen"]
        movelock["frozen"] = False
        try:
            for wx, wy in waypoints:
                keep = lambda: (time.time() - began < 20.0
                                and _building_connected()
                                and state.get("realm") == controller.expected_realm
                                and not controller._cancel_requested.is_set())
                walk_to(wx * CB, wy * CB, keep_going=keep)
                if not keep():
                    return False
        finally:
            movelock["frozen"] = was_frozen
        landed = _building_position()
        return (controller.hooks.position_verified()
                and sum((a - b) ** 2 for a, b in zip(landed, target)) <= reach ** 2)

    def _building_send_place(coordinate, item_id, inventory_seq,
                             inventory_slot):
        if not _building_connected():
            return False
        controller = build_runtime.get("controller")
        if not controller or state.get("realm") != controller.expected_realm:
            return False
        # Serialize the final snapshot check with the inventory reader.  Without
        # this, an rx 0x000e can reorder slots after the controller resolves one
        # but before tx 0x000b is encoded, selecting the wrong item on the wire.
        with build_action_lock:
            with player_inventory["lock"]:
                snap = player_inventory.get("snapshot")
                if (not snap or int(snap.get("seq", 0)) != inventory_seq
                        or P.inventory_slot_for_item(snap, item_id)
                        != inventory_slot):
                    return False
                if not _building_connected() or state.get("realm") \
                        != controller.expected_realm:
                    return False
                if (controller._cancel_requested.is_set()
                        or not controller._in_safe_area(coordinate)
                        or not controller._within_reach(coordinate, 3)
                        or controller.hooks.world_cell(coordinate) is not None):
                    return False
                return bool(send(P.build_place_block(
                    pos["x"], pos["y"], pos["z"], *coordinate,
                    inventory_slot=inventory_slot)))

    if cc_live_builder is not None:
        _build_hooks = cc_live_builder.LiveHooks(
            realm_name=lambda: state.get("realm"),
            connected=_building_connected,
            world_complete=_building_world_health,
            world_objects=_building_world_objects,
            position_block=_building_position,
            inventory_snapshot=_own_inventory_snapshot,
            wait_inventory_after=_wait_inventory_after,
            query_block=_building_query_one,
            query_many=_building_query_many,
            move_within_reach=_building_move_within_reach,
            send_place=_building_send_place,
            show=show_line,
            audit=_building_audit,
            area_verified=_building_area_verified,
            # world_cell defaults UNKNOWN and position_verified defaults False.
            # Supply independent, current server evidence before enabling live
            # building; local pos/world caches do not meet this contract.
        )
        build_runtime["controller"] = cc_live_builder.LiveBuilderController(
            _build_hooks, item_names)

    def find_dispenser_block(center=None, r=2, report=False):
        """Probe blocks around `center` (default = the bot's own block) and return
        the (bx,by,bz) of the Prize Dispenser (query-kind 0x13), or None. Queries
        are PACED (a burst gets throttled) and then a collection wait catches slow
        replies before scanning nearest-first. With report=True prints hits."""
        if center is None:
            if not pos["placed"]:
                if report:
                    print("  not placed in a realm yet")
                return None
            center = (pos["x"] // 100000, pos["y"] // 100000, pos["z"] // 100000)
        r = max(1, min(r, 6))
        cx, cy, cz = center
        blocks = [(x, y, z)
                  for x in range(cx - r, cx + r + 1)
                  for y in range(cy - r, cy + r + 1)
                  for z in range(cz - r, cz + r + 1)]
        blocks.sort(key=lambda b: abs(b[0] - cx) + abs(b[1] - cy)
                    + abs(b[2] - cz))
        if report:
            print(f"  probing {len(blocks)} blocks around {center} "
                  f"(radius {r})…")
        for b in blocks:                 # fire paced, clearing stale
            if prize_ctl["stop"] or stop.is_set():
                break
            qcache.pop(b, None)
            try:
                send(P.build_block_query(*b))
            except Exception:
                pass
            time.sleep(0.025)
        time.sleep(1.2)                  # let slow replies land
        disp = None
        hits = []
        for b in blocks:                 # nearest-first scan
            info = qcache.get(b)
            if not info:
                continue
            hits.append((b, info))
            if info.get("kind") == 0x13 and disp is None:
                disp = b
        if report:
            if hits:
                print(f"  {len(hits)} machine block(s) responded (nearest first):")
                for b, info in hits[:30]:
                    k = info.get("kind")
                    txt = info.get("text")
                    tag = "   <- DISPENSER (arm this)" if k == 0x13 else ""
                    tstr = f'  "{txt}"' if txt else ""
                    print(f"    {b[0]} {b[1]} {b[2]}  kind=0x{k:02x}{tstr}{tag}")
            else:
                print("  nothing responded — move closer to the machine")
        return disp

    def find_dispenser_near(bx, by, bz, reach=2, zdown=4, zup=2):
        """Query the blocks around (bx,by,bz) and return the nearest one that is a
        Prize Dispenser (kind 0x13) — so we don't have to guess where the machine
        sits relative to the player (below / in front / etc). z runs DOWNWARD, so
        we look a few blocks 'below' (bz+1..zdown) and a couple 'above'."""
        cands = []
        for dz in range(-zup, zdown + 1):
            for dx in range(-reach, reach + 1):
                for dy in range(-reach, reach + 1):
                    cands.append((bx + dx, by + dy, bz + dz))
        query_many(cands)
        hits = [c for c in cands
                if (qcache.get(c) or {}).get("kind") == 0x13]
        if not hits:
            return None
        return min(hits, key=lambda c: (c[0] - bx) ** 2 + (c[1] - by) ** 2
                   + (c[2] - bz) ** 2)

    def run_prize_crack(lo, hi, dblock, delay,
                        arm_wait=2.5, win_confirm=5.0, lock_aborts=6,
                        descending=False):
        # dblock = (bx,by,bz) of the Prize Dispenser. Per guess: (1) block-query
        # the dispenser to ARM it and wait for that ack (also gives the dispenser
        # guid+kind for the dispense); (2) submit the guess. WRONG -> rx 0x0036;
        # WIN -> a SECOND rx 0x0014 (the server accepting the password). Using the
        # positive win signal (not just "no 0x0036") keeps it correct under lag.
        prize_ctl["active"] = True
        prize_ctl["stop"] = False
        prize_ctl["found"] = None            # cleared for this run; set on a win
        prizewait["block"] = tuple(dblock)   # reader matches replies to this block
        tried = 0
        won_code = None
        silent = 0                       # consecutive no-contact guesses
        t0 = time.time()
        total = hi - lo + 1
        # direction: ascending from lo (default) or descending from hi (so a
        # second bot can sweep the SAME machine from the top down while the first
        # goes bottom-up — they meet in the middle, no overlap).
        step = -1 if descending else 1
        arrow = "down from" if descending else "up from"
        show_line(f"[prize] cracking {lo}-{hi} ({total} codes) {arrow} "
                  f"{hi if descending else lo}, arming dispenser "
                  f"{dblock} each guess. 'prize stop' to abort.")
        set_sticky_status("")

        def isleep(dur):                 # interruptible sleep
            end = time.time() + dur
            while time.time() < end:
                if prize_ctl["stop"] or stop.is_set():
                    return
                time.sleep(min(0.05, max(0.0, end - time.time())))

        def reset():
            prizewait["result"] = None
            prizewait["text"] = None
            prizewait["dispenser_guid"] = None
            prizewait["arm_kind"] = None
            prizewait["saw_accept"] = False
            prizewait["arm_event"].clear()
            prizewait["event"].clear()

        def try_code(code):
            # One arm+guess cycle. Returns "wrong" | "accept" | "silent" | "noarm".
            reset()
            prizewait["phase"] = "armed"
            prizewait["active"] = True
            try:
                send(P.build_block_query(*dblock))            # ARM
            except Exception:
                prizewait["active"] = False
                return "noarm"
            if not prizewait["arm_event"].wait(timeout=arm_wait):
                prizewait["active"] = False
                return "noarm"
            prizewait["phase"] = "guessed"                    # a 0x0014 now = accept
            try:
                send(P.build_password_guess(code))            # GUESS
            except Exception:
                prizewait["active"] = False
                return "silent"
            # the event fires ONLY on rx 0x0036 (wrong); a win is the ABSENCE of it
            # plus an acknowledgement (saw_accept). Waiting the window out on a
            # non-wrong guess is what lets us trust "no 0x0036 = not wrong".
            prizewait["event"].wait(timeout=win_confirm)
            res = prizewait["result"]
            accepted = prizewait["saw_accept"]
            prizewait["active"] = False
            if res == "wrong":
                return "wrong"
            if accepted:
                return "accept"
            return "silent"

        def win_banner(code):
            bar = "*" * 54
            for ln in ("", bar, bar,
                       f"***     PASSWORD FOUND:  {code}     ***",
                       f"***     block {dblock[0]} {dblock[1]} {dblock[2]}  ·  "
                       f"{tried} tries  ·  {time.time()-t0:.0f}s",
                       bar, bar, ""):
                show_line(ln)

        def _resume_hint(at):
            # the command that resumes the REMAINING range in the same direction
            tail = " down" if descending else ""
            lo_, hi_ = (lo, at) if descending else (at, hi)
            return (f"prize {lo_} {hi_} {dblock[0]} {dblock[1]} {dblock[2]}{tail}")

        try:
            n = hi if descending else lo
            while (n >= lo) if descending else (n <= hi):
                if prize_ctl["stop"] or stop.is_set():
                    show_line(f"[prize] stopped at {n} ({tried} tried). Resume with "
                              f"'{_resume_hint(n)}'.")
                    break
                code = str(n)
                v = try_code(code)
                tried += 1

                if v == "noarm":
                    silent += 1
                    show_line(f"[prize] block {dblock} did not respond "
                              f"({silent}/{lock_aborts}) — right block? verify: "
                              f"prize test {dblock[0]} {dblock[1]} {dblock[2]} <code>")
                    if silent >= lock_aborts:
                        show_line("[prize] aborting — block unresponsive.")
                        break
                    isleep(delay)
                    continue

                if v == "wrong":
                    silent = 0
                    if n % 100 == 0:
                        show_line(f"[prize] progress: reached {n} "
                                  f"({tried} guesses, {time.time()-t0:.0f}s)")
                    isleep(delay)
                    n += step
                    continue

                if v == "silent":
                    silent += 1
                    show_line(f"[prize] no verdict on '{code}' — retrying "
                              f"({silent}/{lock_aborts})")
                    if silent >= lock_aborts:
                        show_line("[prize] aborting — no verdicts (lag/rate-limit?). "
                                  f"Resume: {_resume_hint(n)}")
                        break
                    isleep(delay)
                    continue

                # v == "accept": report it without claiming or touching the
                # prize. try_code already waited the full extended rejection
                # window, so a delayed 0x0036 gets authority over the 0x0014.
                won_code = code
                prize_ctl["found"] = code
                prize_ctl["found_at"] = time.time()
                win_banner(code)
                set_sticky_status(f"*** PRIZE PASSWORD FOUND: {code} ***")
                show_line(f"[prize] >>> password: {code} <<<  (prize left untouched)")
                _realm = state.get("realm")
                if not _realm:
                    _owner = state.get("realm_owner")
                    _realm = f"{_owner}'s realm" if _owner else "an unknown realm"
                discord_notify(
                    "\U0001F389 Prize machine cracked!",
                    "The prize was left untouched — claim it in-game.",
                    event="prize", color=0xFFD24A,
                    fields=[("Password", f"`{code}`", True),
                            ("Realm", _realm, True),
                            ("Block", f"{dblock[0]}, {dblock[1]}, {dblock[2]}",
                             True)])
                break
            else:
                if won_code is None:
                    show_line(f"[prize] exhausted {lo}-{hi}, no code matched "
                              f"({tried} tried).")
        finally:
            prizewait["active"] = False
            prize_ctl["active"] = False

    # SIMPLE build: the only command verbs this bot will run. Enforced below on
    # EVERY command path (interactive stdin, /cmd, /runcmd, FIFO, remote worker)
    # because they all funnel through this one loop. Full build / from-source
    # ignore this (args.simple is False).
    SIMPLE_ALLOWED = {
        # Teleport / navigation
        "tp", "goto", "move", "jump", "portal", "joinname", "joinrealm",
        "searchrealm", "search", "parkrealm", "park", "where", "offmap",
        "wander",
        # GUID
        "guid", "find",
        # Vend / market scanning
        "scan", "rescan", "vends", "market", "deals", "history", "changes",
        "scans", "scanstatus", "stale", "machines", "machinehistory",
        "watch", "unwatch", "watchlist", "crawl", "crawlfile",
        "dbstats", "dbexport", "dbbackup",
        # Discord / remote control
        "webhook", "link", "links", "control",
        # essentials (kept so the build stays usable)
        "help", "commands", "?", "reconnect", "quit", "exit",
    }
    try:
        while True:
            line = read_command().strip()
            if not line:
                continue
            if getattr(args, "simple", False):
                _verb = line.split(" ", 1)[0].lower()
                if _verb not in SIMPLE_ALLOWED:
                    print("  [simple build] '" + _verb + "' is disabled. This "
                          "build only does teleport/nav, guid, vend/market "
                          "scanning and Discord. Type 'help' for the list.")
                    continue
            if line in ("quit", "exit"):
                break
            elif line == "friends":
                if not friends:
                    print("  (friends list not received yet)")
                for nm, g in sorted(friends.items()):
                    print(f"    {nm:<22} {g}")
                for nm, g in sorted(requests.items()):
                    print(f"    {nm:<22} {g}  (pending request)")
                listed = {k.lower() for k in list(friends) + list(requests)}
                for nm, g in sorted(known.items()):
                    if nm not in listed:
                        print(f"    {nm:<22} {g}  (looked up)")
            elif line == "players":
                if not players:
                    print("  no players seen yet — their GUIDs are learned as "
                          "they move/appear in the realm")
                else:
                    print(f"  players seen this session ({len(players)}):")
                    for g, nm in sorted(players.items(), key=lambda kv: kv[1].lower()):
                        print(f"    {nm:<24} {g}")
            elif line.startswith("guid ") or line.startswith("find "):
                who = line[5:].strip()
                if not who:
                    print("  usage: guid <player name>   (find <name> = "
                          "resolve only, no teleport)")
                else:
                    g = lookup_guid(who)
                    # 'guid' goes on to teleport with what it found; 'find' stops
                    # at the GUID.
                    if g and line.startswith("guid "):
                        queue_move("guid", g, f"guid {who}", autoscan=True)
                        print(f"  teleporting to {who} ({g}) — scanning their "
                              f"realm once we land ...")
            elif line.startswith("tp "):
                target = line[3:].strip()
                guid = find_guid(target)
                if guid is None:
                    print(f"  no known GUID for '{target}' — try 'guid {target}' "
                          f"first, or give a 32-hex GUID")
                else:
                    queue_move("guid", guid, f"tp {target}")
                    print(f"  teleporting to {target} ...")
            elif line == "queue" or line.startswith("queue "):
                arg = line[6:].strip().lower()
                if arg in ("clear", "flush", "drop"):
                    with cmdq_lock:
                        n = len(cmdq)
                        cmdq.clear()
                    print(f"  queue cleared ({n} command(s) dropped)")
                else:
                    with cmdq_lock:
                        items = list(cmdq)
                    busy = bot_busy()
                    print(f"  bot is {'BUSY' if busy else 'idle'}; "
                          f"{len(items)} command(s) waiting"
                          + (" (they run when it's free):" if items and busy
                             else ":" if items else "."))
                    for i, it in enumerate(items, 1):
                        print(f"    {i}. {it['label']}")
                    if not items:
                        print("    (nothing queued — 'queue clear' empties it)")
            elif line in ("where", "pos", "coords"):
                if not pos["placed"]:
                    print("  not placed in a realm yet")
                else:
                    home = (f"  home ({pos['home'][0]},{pos['home'][1]})"
                            if pos["home"] else "")
                    cb = P.COORD_BASE
                    bx, by, bz = (pos['x'] // cb, pos['y'] // cb, pos['z'] // cb)
                    # Block XYZ is what 'objects'/'fossils region' use — read it
                    # here, stand on each corner of the fossil square, and feed
                    # the two BLOCK triples to 'fossils region'.
                    print(f"  block ({bx},{by},{bz})   <- use these for "
                          f"'fossils region'")
                    print(f"  raw   ({pos['x']},{pos['y']},{pos['z']})  "
                          f"1 step = {STEP}{home}")
            elif line == "jump" or (line.split()[0] == "jump"):
                # fire N hops (default 1), a beat apart, to eyeball the animation
                n = 1
                p = line.split()
                if len(p) == 2 and p[1].isdigit():
                    n = max(1, min(10, int(p[1])))
                if not pos["placed"]:
                    print("  not placed in a realm yet")
                else:
                    for i in range(n):
                        do_jump()
                        print(f"  jump {i + 1}/{n}")
                        if i + 1 < n:
                            time.sleep(1.0)
            elif line.split()[0] in ("n", "s", "e", "w", "north", "south",
                                     "east", "west", "u", "d", "up", "down"):
                # n/s/e/w = walk one step (n 3 = three steps); u/d = up/down (z).
                parts = line.split()
                d = parts[0]
                cnt = (int(parts[1]) if len(parts) == 2
                       and parts[1].lstrip("-").isdigit() else 1)
                step = STEP * cnt
                dx = dy = dz = 0
                if d in ("e", "east"):
                    dx = step
                elif d in ("w", "west"):
                    dx = -step
                elif d in ("n", "north"):
                    dy = -step
                elif d in ("s", "south"):
                    dy = step
                elif d in ("u", "up"):
                    dz = step
                elif d in ("d", "down"):
                    dz = -step
                apply_move(pos["x"] + dx, pos["y"] + dy, pos["z"] + dz,
                           f"{d}" + (f" x{cnt}" if cnt != 1 else ""))
            elif line.startswith("goto "):
                nums = line[5:].split()
                if len(nums) in (2, 3) and all(n.lstrip("-").isdigit()
                                               for n in nums):
                    z = int(nums[2]) if len(nums) == 3 else pos["z"]
                    apply_move(int(nums[0]), int(nums[1]), z, "goto")
                else:
                    print("  usage: goto <x> <y> [z]   (absolute coordinates; "
                          "'where' shows current)")
            elif line.startswith("move "):
                nums = line[5:].split()
                if len(nums) in (2, 3) and all(n.lstrip("-").isdigit()
                                               for n in nums):
                    dz = int(nums[2]) if len(nums) == 3 else 0
                    apply_move(pos["x"] + int(nums[0]), pos["y"] + int(nums[1]),
                               pos["z"] + dz, "move")
                else:
                    print(f"  usage: move <dx> <dy> [dz]   (relative units; one "
                          f"step = {STEP})")
            elif line == "portal":
                if pos["home"]:
                    h = pos["home"]
                    apply_move(h[0], h[1], h[2] if len(h) > 2 else pos["z"],
                               "walked back to portal")
                else:
                    print("  no portal spawn remembered for this realm yet")
            elif line == "sign" or line.startswith("sign "):
                arg = line[5:].strip() if line.startswith("sign ") else ""
                nums = arg.split()
                if arg and len(nums) == 3 and all(n.lstrip("-").isdigit()
                                                  for n in nums):
                    bx, by, bz = (int(n) for n in nums)
                    rep = query_block(bx, by, bz)
                    if rep and rep.get("text"):
                        print(f"  ({bx},{by},{bz}): {rep['text']}")
                    elif rep:
                        print(f"  ({bx},{by},{bz}): (block has no text — not a sign)")
                    else:
                        print(f"  ({bx},{by},{bz}): no reply (empty block?)")
                elif not arg:
                    # probe a small cube around where the bot is standing
                    read_signs_here(r=2)
                else:
                    print("  usage: sign <bx> <by> <bz>   (block coords), or "
                          "bare 'sign' for right where you're standing, or "
                          "'signs here' for a wider box around you")
            elif line.startswith("writesign "):
                # writesign <bx> <by> <bz> <text...> — set the text on a sign you
                # OWN. Reads the block to get its GUID, then sends tx 0x00c8.
                parts = line[10:].strip().split(None, 3)
                if len(parts) >= 4 and all(parts[i].lstrip("-").isdigit()
                                           for i in range(3)):
                    bx, by, bz = int(parts[0]), int(parts[1]), int(parts[2])
                    text = parts[3]
                    rep = query_block(bx, by, bz)
                    if not rep or not rep.get("guid"):
                        print(f"  ({bx},{by},{bz}): no block there to write to "
                              f"(query got no reply)")
                    else:
                        g = rep["guid"]
                        # Editing an EXISTING sign needs its editor opened first
                        # (a fresh placement auto-opens it). Open it like any
                        # object (tx 0x010f), let the 'Enter Sign Text' prompt
                        # come back, THEN send the text (tx 0x00c8 + guid).
                        send(P.build_use_object(g))
                        time.sleep(0.4)
                        send(P.build_write_sign(g, text))
                        print(f"  opened + wrote to ({bx},{by},{bz}): {text!r} — "
                              f"re-reading ...")
                        time.sleep(0.5)
                        rep2 = query_block(bx, by, bz)
                        if rep2 and rep2.get("text") == text:
                            print(f"  ✓ now reads: {rep2['text']!r}")
                        elif rep2 and rep2.get("text") is not None:
                            print(f"  still reads {rep2['text']!r} — the open step "
                                  f"(0x010f) may not be how a sign editor opens. "
                                  f"Tell me and I'll have you capture an edit.")
                        else:
                            print("  (no text came back on re-read)")
                else:
                    print("  usage: writesign <bx> <by> <bz> <text>   (edits a "
                          "sign you own; 'sign <bx> <by> <bz>' to find one)")
            elif line.startswith("hold "):
                g = line[5:].strip()
                own = conn.get("own")
                if len(g) == 32 and own:
                    send(P.build_select_item(own, g))
                    print("  legacy selection frame sent; this does not select "
                          "the inventory slot used by verified placement")
                else:
                    print("  usage: hold <32-hex item guid> (legacy selection; "
                          "verified placement resolves inventory slots directly)")
            elif line.startswith("placesign "):
                # The old helper silently chose historical slot 3 (currently a
                # cash register), bypassed occupancy checks, and reported sends
                # as success. Preserve an explicit refusal instead of that path.
                print("  legacy placesign is disabled: its fixed inventory slot "
                      "could select the wrong item. Once an area is verified, "
                      "use 'place <sign item id> <x> <y> <z>', wait for typed "
                      "confirmation, then use 'writesign <x> <y> <z> <text>'.")
            elif line == "signs" or line.startswith("signs "):
                arg = line[6:].strip().strip('"') if line.startswith("signs ") \
                    else ""
                # 'signs here [r]'  -> probe a cube around the BOT (works with an
                #   empty object list); 'signs' / 'signs wide' / 'signs <reach>'
                #   -> probe around occupied blocks; 'signs <file>' -> also dump.
                parts = arg.split()
                if parts and parts[0] == "here":
                    r = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() \
                        else 3
                    dump = parts[2] if len(parts) == 3 else None
                    read_signs_here(r=max(1, min(8, r)), dump_path=dump)
                else:
                    reach, dump = 1, None
                    if arg == "wide":
                        reach = 2
                    elif arg.isdigit():
                        reach = max(1, min(3, int(arg)))
                    elif arg:
                        dump = arg
                    read_signs_bulk(dump, reach=reach)
            elif line.startswith("use ") or line.startswith("open "):
                # DEBUG PROBE: fire tx 0x010f at ANY object GUID and print the
                # server's reply. Uses open_and_cancel, so it ALWAYS sends the
                # cancel byte (0) — it can never spend currency or confirm a
                # trade. Purpose: test whether the server range-gates a cash
                # register (or any object) when opened from out of range.
                arg = line.split(None, 1)[1].strip() if " " in line else ""
                g = arg.lower().replace("0x", "")
                if len(g) != 32 or any(c not in "0123456789abcdef" for c in g):
                    print("  use <guid>: need a 32-hex-char object GUID "
                          "(get one from 'machines', 'glass', or 'inventory')")
                else:
                    print(f"  tx 0x010f -> {g}  (open; will auto-cancel, "
                          f"nothing is spent)")
                    d = open_and_cancel(g)
                    if d is None:
                        print("  no dialog reply within timeout — server sent "
                              "nothing back (possible range/ownership gate, or "
                              "this object doesn't open with 0x010f)")
                    else:
                        print(f"  rx 0x00ca dialog:")
                        print(f"    guid : {d.get('guid')}")
                        print(f"    title: {d.get('title')!r}")
                        print(f"    text : {d.get('text')!r}")
            elif line in ("objects", "obj"):
                # No id -> histogram of EVERYTHING in the realm, grouped by
                # (src, type_id). Passive. A functional object (0x0021) carries a
                # small enum id, NOT its catalogue id, so a Cash Register won't
                # appear as 376 in that stream — this shows its real id so you
                # can then run 'objects <that id>' to get its GUID.
                from collections import Counter
                c = Counter((o.get("src"), o.get("type_id")) for o in world.values())
                print(f"  {len(world)} object(s) in realm, "
                      f"{len(c)} distinct (src, type_id)  (passive):")
                for (src, tid), n in sorted(c.items(),
                                            key=lambda kv: (-kv[1], kv[0])):
                    tag = "0x000f build" if src == 0x000f else \
                          "0x0021 func " if src == 0x0021 else f"src={src}"
                    print(f"    x{n:<4} [{tag}] id={tid:<5} {item_label(tid)}")
                print("  -> pick the register's id, then 'objects <id>' for GUIDs")
            elif line.startswith("objects ") or line.startswith("obj "):
                # List every world object of a given item/type id, with its GUID
                # and block coords. Passive — reads the already-received object
                # stream, sends nothing. Use it to find non-vending objects that
                # 'machines'/'scan' ignore, e.g. a Cash Register (type id 376):
                #   objects 376   -> its GUID, to feed to 'use <guid>'.
                arg = line.split(None, 1)[1].strip() if " " in line else ""
                try:
                    want = int(arg)
                except ValueError:
                    print("  usage: objects <type_id>   (or bare 'objects' for a "
                          "histogram of what's here; Cash Register catalogue id = 376)")
                else:
                    hits = [o for o in world.values() if o.get("type_id") == want]
                    print(f"  {len(hits)} object(s) of type {want} "
                          f"({item_label(want)})  (passive — nothing sent)")
                    for o in sorted(hits, key=lambda o: (o["bx"], o["by"], o["bz"])):
                        src = o.get("src")
                        tag = "0x000f" if src == 0x000f else "0x0021" if src == 0x0021 else str(src)
                        print(f"    ({o['bx']:>3},{o['by']:>3},{o['bz']:>3})  "
                              f"[{tag}]  {o['guid']}")
            elif line == "blocks" or line.startswith("blocks "):
                # Scan the CURRENT realm and list EVERY placed block: what it is
                # (catalogue name via item_label) and its XYZ. Passive — reads
                # the already-received 0x000f/0x0021 object burst that arrives on
                # realm entry; sends NOTHING, touches nothing. Just enter a realm
                # and run `blocks`.
                #
                #   blocks              -> list PLACED blocks, nearest-first from
                #                          the bot. Prints a capped preview AND
                #                          writes the full list to a text file
                #                          (a realm can hold thousands of blocks).
                #   blocks all          -> print every placed block (no cap)
                #   blocks count        -> tally: each block type + how many of it
                #                          (most-common first), saved to
                #                          blocks-<realm>-count.txt
                #   blocks diag         -> frame accounting: how many 0x000f/0x0021
                #                          bursts arrived vs were DROPPED WHOLE for
                #                          not dividing evenly (the partial-read bug)
                #   blocks scan         -> ACTIVE: reuse the vend packet method
                #                          (tx 0x0014) to enumerate every coord the
                #                          server ANSWERS for. 'blocks scan wide'
                #                          (z±2); 'blocks scan box [pad] [cap]'
                #                          sweeps the object bbox; 'blocks scan grid
                #                          <W> <H> [zpad]' sweeps the FULL realm
                #                          footprint uncapped (99x99 -> grid 99 99)
                #   blocks dropped      -> the OFF-GRID objects only (loose items
                #                          lying on the floor — NOT built blocks)
                #   blocks <text>       -> only blocks whose name (or type id)
                #                          contains <text>, e.g. 'blocks gold'
                #   blocks json [file]  -> write the full list as JSON instead
                #
                # A placed block sits EXACTLY on the grid (its fine x/y are exact
                # multiples of COORD_BASE). An object off the grid is a dropped
                # item lying on the floor, not a block someone built — so it does
                # NOT correspond to a block you'll see at that coordinate. Those
                # are split out (and hidden by default) so `blocks` never claims a
                # block is somewhere one was never placed. (Same rule the
                # 'inventory'/'glass' readers already use.)
                parts = line.split()
                sub = parts[1].lower() if len(parts) > 1 else ""
                if sub == "scan":
                    # ACTIVE finder — reuse the vend packet method (tx 0x0014) to
                    # enumerate blocks, not just machines. 'blocks scan' probes
                    # occupied blocks + z-neighbours (the vend set); 'blocks scan
                    # wide' reaches z±2; 'blocks scan box [pad] [cap]' sweeps the
                    # whole object bounding box to catch coords with NO burst
                    # object (blocks the passive list misses).
                    rest = parts[2:]
                    if rest and rest[0].lower() == "grid":
                        # blocks scan grid <W> <H> [zpad] — sweep the FULL realm
                        # footprint (0..W, 0..H), uncapped. For a 99x99 realm:
                        # 'blocks scan grid 99 99'. zpad extends the Z range.
                        nums = [r for r in rest[1:] if r.lstrip("-").isdigit()]
                        if len(nums) >= 2:
                            W, H = int(nums[0]), int(nums[1])
                            zpad = int(nums[2]) if len(nums) > 2 else 0
                            scan_all_blocks(grid=(W, H), zpad=zpad)
                        else:
                            print("  usage: blocks scan grid <W> <H> [zpad]   "
                                  "(e.g. 'blocks scan grid 99 99' for a 99x99 "
                                  "realm)")
                    elif rest and rest[0].lower() == "wide":
                        scan_all_blocks(reach=2)
                    elif rest and rest[0].lower() == "box":
                        pad = int(rest[1]) if len(rest) > 1 and \
                            rest[1].lstrip("-").isdigit() else 1
                        cap = int(rest[2]) if len(rest) > 2 and \
                            rest[2].isdigit() else 60000
                        scan_all_blocks(box=True, pad=pad, cap=cap)
                    else:
                        scan_all_blocks(reach=1)
                elif sub == "diag":
                    # Why is the block reading partial? Show frame accounting:
                    # how many 0x000f/0x0021 frames arrived, how many were kept,
                    # and how many were DROPPED WHOLE for not dividing evenly by
                    # the record size (the burst-loss bug). Non-zero 'dropped'
                    # means built blocks are missing from this reading.
                    d = world_diag
                    print(f"  world frames received: {d['frames']}  "
                          f"(objects kept: {d['objs']}, now in world: {len(world)})")
                    print(f"  frames DROPPED whole (payload not a multiple of the "
                          f"record size): {d['dropped']}")
                    if d["remainders"]:
                        print("  leftover bytes on dropped frames "
                              "(src -> remainder: how often):")
                        for (src, rem), n in d["remainders"].most_common():
                            print(f"    0x{src:04x}  +{rem}B leftover   x{n}")
                        print("  -> a consistent remainder = the real record layout "
                              "differs from our 70/44B assumption; paste this and "
                              "I'll fix parse_world_objects to keep those frames.")
                    elif d["dropped"] == 0 and d["frames"]:
                        print("  no frames dropped — the burst parsed cleanly, so a "
                              "short reading is missing data, not a parse bug.")
                    elif not d["frames"]:
                        print("  no world frames seen yet — enter/re-enter a realm.")
                elif not world:
                    print("  no realm objects loaded yet — enter a realm first "
                          "(the block list arrives on entry).")
                else:
                    as_json = (sub == "json")
                    show_all = (sub == "all")
                    only_dropped = (sub == "dropped")
                    want_count = (sub == "count")
                    want_diag = False
                    name_filter = ""
                    if (not as_json and not show_all and not only_dropped
                            and not want_count and not want_diag
                            and len(parts) > 1):
                        name_filter = line.split(None, 1)[1].strip().lower()
                    outfile = " ".join(parts[2:]).strip() if (as_json and
                                                              len(parts) > 2) else None

                    B = P.COORD_BASE
                    def placed(o):
                        # on the grid on BOTH horizontal axes = a built block;
                        # off-grid = a loose/dropped item on the floor.
                        return (o.get("x", 0) % B == 0) and (o.get("y", 0) % B == 0)

                    all_objs = list(world.values())
                    if name_filter:
                        all_objs = [o for o in all_objs
                                    if name_filter in (item_names.get(o.get("type_id"))
                                                       or "").lower()
                                    or name_filter == str(o.get("type_id"))]
                    grid = [o for o in all_objs if placed(o)]
                    drop = [o for o in all_objs if not placed(o)]
                    objs = drop if only_dropped else grid

                    # nearest-first from the bot, if we know where it's standing
                    me = player_block.get(conn.get("own"))
                    def bdist(o):
                        if not me:
                            return None
                        return (abs(o["bx"] - me[0]) + abs(o["by"] - me[1])
                                + abs(o["bz"] - me[2]))
                    objs.sort(key=lambda o: (bdist(o) if me else 0,
                                             o["bx"], o["by"], o["bz"]))

                    realm = state.get("realm") or "unknown-realm"
                    safe = re.sub(r"[^0-9A-Za-z._-]+", "_", realm).strip("_") or "realm"
                    here = _APP_DIR
                    kind_word = "dropped item" if only_dropped else "placed block"

                    if not objs:
                        if name_filter:
                            print(f"  0 block(s) match {name_filter!r} "
                                  f"(of {len(world)} in realm {realm!r}).")
                        else:
                            print(f"  0 {kind_word}(s) in realm {realm!r}.")
                    elif as_json:
                        path = outfile or os.path.join(here, f"blocks-{safe}.json")
                        rows = [{"name": item_names.get(o.get("type_id"), ""),
                                 "type_id": o.get("type_id"),
                                 "x": o["bx"], "y": o["by"], "z": o["bz"],
                                 "placed": placed(o),
                                 "kind": o.get("kind"), "src": o.get("src"),
                                 "guid": o.get("guid")} for o in objs]
                        try:
                            with open(path, "w", encoding="utf-8") as fh:
                                json.dump({"realm": realm, "count": len(rows),
                                           "blocks": rows}, fh, indent=1,
                                          ensure_ascii=False)
                            print(f"  wrote {len(rows)} {kind_word}(s) to {path}")
                        except OSError as e:
                            print(f"  couldn't write {path}: {e}")
                    elif want_count:
                        # TALLY: which block types are in the realm and how many
                        # of each — one line per distinct type, most-common first.
                        from collections import Counter
                        tally = Counter(o.get("type_id") for o in objs)
                        print(f"  {len(objs)} {kind_word}(s) in realm {realm!r}, "
                              f"{len(tally)} distinct type(s):")
                        for tid, n in tally.most_common():
                            print(f"    {n:>6} x  {item_label(tid)}")
                        # Full tally to a file too (name-sorted, tab-separated).
                        path = os.path.join(here, f"blocks-{safe}-count.txt")
                        try:
                            with open(path, "w", encoding="utf-8") as fh:
                                fh.write(f"# {len(objs)} {kind_word}(s), "
                                         f"{len(tally)} distinct type(s) in realm "
                                         f"{realm!r}\n")
                                fh.write("# count\ttype_id\tname\n")
                                for tid, n in tally.most_common():
                                    fh.write(f"{n}\t{tid}\t"
                                             f"{item_names.get(tid, '')}\n")
                            print(f"  full tally written to {path}")
                        except OSError as e:
                            print(f"  (couldn't write {path}: {e})")
                        if drop:
                            print(f"  ({len(drop)} off-grid object(s) not counted "
                                  f"— loose floor items; 'blocks dropped' to see)")
                        if world_diag["dropped"]:
                            print(f"  ⚠ {world_diag['dropped']} world frame(s) were "
                                  f"DROPPED on arrival (parse remainder) — this tally "
                                  f"is INCOMPLETE. Run 'blocks diag' to see why.")
                    else:
                        from collections import Counter
                        distinct = Counter(o.get("type_id") for o in objs)
                        scope = f" matching {name_filter!r}" if name_filter else ""
                        where = f", nearest-first from {me}" if me else ""
                        print(f"  {len(objs)} {kind_word}(s){scope} in realm "
                              f"{realm!r}, {len(distinct)} distinct type(s){where}:")
                        CAP = 200
                        for o in (objs if (show_all or only_dropped) else objs[:CAP]):
                            d = bdist(o)
                            dtag = f"  ~{d} away" if d is not None else ""
                            stag = "func" if o.get("src") == 0x0021 else "build"
                            print(f"    XYZ ({o['bx']}, {o['by']}, {o['bz']})  "
                                  f"{item_label(o.get('type_id'))}  [{stag}]{dtag}")
                        # Always drop the FULL list to a file so the console cap
                        # never loses anything (tab-separated: easy to load). The
                        # 'placed' column marks built blocks vs dropped items.
                        path = os.path.join(here, f"blocks-{safe}.txt")
                        try:
                            with open(path, "w", encoding="utf-8") as fh:
                                fh.write(f"# {len(objs)} {kind_word}(s) in realm "
                                         f"{realm!r}\n")
                                fh.write("# x\ty\tz\ttype_id\tname\tplaced\t"
                                         "kind\tsrc\n")
                                for o in objs:
                                    fh.write(
                                        f"{o['bx']}\t{o['by']}\t{o['bz']}\t"
                                        f"{o.get('type_id')}\t"
                                        f"{item_names.get(o.get('type_id'), '')}\t"
                                        f"{placed(o)}\t"
                                        f"{o.get('kind')}\t{o.get('src')}\n")
                            if not (show_all or only_dropped) and len(objs) > CAP:
                                print(f"  (showed first {CAP}; full {len(objs)} "
                                      f"written to {path})")
                            else:
                                print(f"  full list also written to {path}")
                        except OSError as e:
                            print(f"  (couldn't write {path}: {e})")
                        if drop and not only_dropped:
                            print(f"  ({len(drop)} off-grid object(s) hidden — "
                                  f"loose items on the floor, NOT built blocks; "
                                  f"'blocks dropped' to see them)")
                        if not me:
                            print("  (move once in-game to sort by distance "
                                  "from you)")
                        if not item_names:
                            print("  (no names.json loaded — blocks show as "
                                  "'id N'; names.json fills in real names)")
                        print("  -> to VERIFY a coord live, aim at it and run "
                              "'blockguid <bx> <by> <bz>' (empty = nothing there).")
            elif line == "fossils" or line.startswith("fossils "):
                # Find every fossil in the CURRENT realm and print its XYZ.
                # Passive: reads the already-received 0x000f/0x0021 object burst
                # that arrives on realm entry — sends NOTHING, digs nothing,
                # touches nothing. Just enter the mine and run `fossils`.
                #
                #   fossils                          -> list each fossil's XYZ
                #   fossils region x1 y1 [z1] x2 y2 [z2] -> mark a BOX of blocks
                #   fossils region off               -> clear the box
                #   fossils learn <id>               -> tag a type_id (saved)
                #   fossils forget <id>              -> untag it
                #   fossils ids                      -> show what counts
                #
                # A fossil is any block that is (a) inside the drawn region box,
                # (b) a type_id tagged with `learn`, or (c) named "...fossil...".
                # The region is the easy one: give two opposite corners of the
                # square the fossils sit in and every block inside is reported,
                # whatever its kind. z is optional — leave it out (4 numbers) to
                # match every depth, or include it (6 numbers) for a full 3D box.
                # A box only applies in the realm it was drawn in.
                parts = line.split()
                sub = parts[1].lower() if len(parts) > 1 else ""
                if sub == "region":
                    rest = parts[2:]
                    if len(rest) == 1 and rest[0].lower() in ("off", "clear", "none"):
                        fossil_region["box"] = None
                        fossil_region["realm"] = None
                        print("  fossil region cleared.")
                    elif len(rest) in (4, 6) and all(
                            v.lstrip("-").isdigit() for v in rest):
                        n = [int(v) for v in rest]
                        if len(n) == 4:
                            (ax, ay), (bx_, by_) = (n[0], n[1]), (n[2], n[3])
                            x1, x2 = sorted((ax, bx_))
                            y1, y2 = sorted((ay, by_))
                            fossil_region["box"] = (x1, y1, None, x2, y2, None)
                            zmsg = "any depth (z)"
                        else:
                            x1, x2 = sorted((n[0], n[3]))
                            y1, y2 = sorted((n[1], n[4]))
                            z1, z2 = sorted((n[2], n[5]))
                            fossil_region["box"] = (x1, y1, z1, x2, y2, z2)
                            zmsg = f"z {z1}..{z2}"
                        fossil_region["realm"] = state["realm"]
                        h = region_hist()
                        inside = sum(h.values())
                        print(f"  fossil region set: x {x1}..{x2}, y {y1}..{y2}, "
                              f"{zmsg}  (realm {state['realm']!r}).")
                        print(f"  {inside} block(s) inside, "
                              f"{len(h)} distinct type(s):")
                        for tid, c in h.most_common():
                            print(f"    x{c:<4} {item_label(tid)}")
                        dom = region_dominant()
                        if dom is not None:
                            print(f"  -> assuming {item_label(dom)} is the "
                                  f"wall/dirt; 'fossils' will report the other "
                                  f"{inside - h[dom]} block(s) as fossils.")
                            print(f"     (if the fossil is a specific type, "
                                  f"'fossils learn <id>' to lock onto just it.)")
                        else:
                            print("  -> run 'fossils' to list them.")
                    else:
                        print("  usage: fossils region <x1> <y1> [z1] <x2> <y2> "
                              "[z2]   (two opposite corners; give z on both or "
                              "neither) — or 'fossils region off'")
                elif sub in ("learn", "forget", "add", "remove", "rm"):
                    if len(parts) < 3 or not parts[2].lstrip("-").isdigit():
                        print(f"  usage: fossils {sub} <type_id>")
                    else:
                        tid = int(parts[2])
                        if sub in ("learn", "add"):
                            fossil_ids.add(tid)
                            save_fossil_ids()
                            print(f"  tagged id {tid} ({item_label(tid)}) as a "
                                  f"fossil — saved. Now 'fossils' will find it "
                                  f"in every mine.")
                        else:
                            fossil_ids.discard(tid)
                            save_fossil_ids()
                            print(f"  id {tid} is no longer treated as a fossil.")
                elif sub == "ids":
                    if fossil_ids:
                        print("  fossil type_ids: " + ", ".join(
                            f"{i} ({item_label(i)})" for i in sorted(fossil_ids)))
                    else:
                        print("  no fossil ids tagged yet. In a mine, run "
                              "'objects' to see what's here, then "
                              "'fossils learn <id>'.")
                    if item_names:
                        named = sorted(t for t in set(item_names)
                                       if "fossil" in item_names[t].lower())
                        if named:
                            print("  also matched by name: " + ", ".join(
                                f"{item_label(t)}" for t in named))
                    if region_active():
                        x1, y1, z1, x2, y2, z2 = fossil_region["box"]
                        zmsg = "any z" if z1 is None else f"z {z1}..{z2}"
                        print(f"  region box: x {x1}..{x2}, y {y1}..{y2}, {zmsg}")
                    elif fossil_region["box"] is not None:
                        print("  a region box is set but for a different realm — "
                              "it's ignored here.")
                else:
                    # Matching priority:
                    #   1. If a region box is drawn, IT WINS — only blocks inside
                    #      it are reported (minus the dominant dirt, or the exact
                    #      tagged id if one is set). This keeps shop fossils in
                    #      vending machines OUTSIDE the box from leaking in.
                    #   2. Otherwise fall back to id/name matching realm-wide.
                    if region_active():
                        inside = [o for o in world.values() if in_region(o)]
                        if fossil_ids:
                            hits = [o for o in inside
                                    if o.get("type_id") in fossil_ids]
                        else:
                            dom = region_dominant()
                            hits = [o for o in inside
                                    if dom is None or o.get("type_id") != dom]
                    else:
                        hits = [o for o in world.values()
                                if is_fossil(o.get("type_id"))]
                    if not hits:
                        if not world:
                            print("  no realm objects loaded yet — enter a mine "
                                  "first (the block list arrives on entry).")
                        elif region_active():
                            print(f"  0 fossils inside the region box "
                                  f"(x {fossil_region['box'][0]}.."
                                  f"{fossil_region['box'][3]}, "
                                  f"y {fossil_region['box'][1]}.."
                                  f"{fossil_region['box'][4]}).\n"
                                  f"  -> nothing placed there, or the corners are "
                                  f"off. 'objects' shows every block if you want "
                                  f"to check coords.")
                        elif (not fossil_ids and not any(
                                "fossil" in (item_names.get(o.get("type_id")) or "").lower()
                                for o in world.values())):
                            print(f"  0 fossils found, but {len(world)} objects "
                                  f"are loaded and no fossil id or region is set "
                                  f"yet.\n  -> draw the square with 'fossils "
                                  f"region <x1> <y1> <x2> <y2>', or run 'objects' "
                                  f"and 'fossils learn <id>'.")
                        else:
                            print("  0 fossils in this realm "
                                  "(nothing matched the id/name).")
                    else:
                        # Distance from where the bot is standing, if known, so
                        # the closest fossil is obvious.
                        me = player_block.get(conn.get("own"))
                        def dist(o):
                            if not me:
                                return None
                            return (abs(o["bx"] - me[0]) + abs(o["by"] - me[1])
                                    + abs(o["bz"] - me[2]))
                        hits.sort(key=lambda o: (dist(o) if me else 0,
                                                 o["bx"], o["by"], o["bz"]))
                        where = f" (nearest first, from {me})" if me else ""
                        scope = "the region box" if region_active() else "this realm"
                        print(f"  {len(hits)} fossil(s) in {scope}{where}:")
                        for o in hits:
                            d = dist(o)
                            dtag = f"  ~{d} blocks away" if d is not None else ""
                            print(f"    XYZ ({o['bx']}, {o['by']}, {o['bz']})  "
                                  f"{item_label(o.get('type_id'))}{dtag}")
                        if not me:
                            print("  (move once in-game to show distance from you)")
            elif line.startswith("blockguid ") or line.startswith("bguid "):
                # Get the GUID of a placed BLOCK by its coords (tx 0x0014). Use
                # for functional objects that AREN'T in the object stream — a
                # Cash Register placed as a block won't show under 'objects 376',
                # so aim at it in-game, read your target block, then:
                #   blockguid <bx> <by> <bz>  -> its block GUID (feed to 'use').
                # Read-only: no dialog, nothing spent, nobody notified.
                parts = line.split()
                if len(parts) != 4:
                    print("  usage: blockguid <bx> <by> <bz>")
                else:
                    try:
                        bx, by, bz = (int(v) for v in parts[1:4])
                    except ValueError:
                        print("  usage: blockguid <bx> <by> <bz>  (integers)")
                    else:
                        print(f"  tx 0x0014 -> ({bx},{by},{bz})  (query; nothing "
                              f"spent)")
                        rep = query_block(bx, by, bz)
                        if not rep:
                            print("  no reply — no block there, or out of query "
                                  "range (walk closer and retry)")
                        elif not rep.get("guid"):
                            print(f"  block found (kind={rep.get('kind')}) but the "
                                  f"reply carried no GUID: {rep}")
                        else:
                            print(f"    kind: {rep.get('kind')}")
                            print(f"    guid: {rep.get('guid')}")
                            print(f"  -> try:  use {rep.get('guid')}")
            elif line == "blockhere" or line.startswith("blockhere "):
                # Query the column of blocks directly under/around the bot, using
                # its current position. Stand ON TOP of the target (e.g. a cash
                # register) and run this — no coordinate math, no off-by-one. It
                # scans a few z-levels because a block's exact reported coord
                # rarely answers; its z-neighbours do. Read-only 0x0014 queries.
                if not pos.get("placed"):
                    print("  not placed in a realm yet")
                else:
                    parts = line.split()
                    reach = 3
                    wide = False
                    for p in parts[1:]:
                        if p == "wide":
                            wide = True
                        elif p.lstrip("-").isdigit():
                            reach = max(1, min(8, int(p)))
                    bx = pos["x"] // P.COORD_BASE
                    by = pos["y"] // P.COORD_BASE
                    bz = pos["z"] // P.COORD_BASE
                    # horizontal footprint: just the bot's block, or a 3x3 around
                    # it when 'wide' (covers an x/y off-by-one on which block the
                    # bot is judged to stand on). Shorter timeout so the sweep of
                    # up to 9 columns doesn't crawl on non-answers.
                    dxy = [-1, 0, 1] if wide else [0]
                    xs = [(bx + dx, by + dy) for dx in dxy for dy in dxy]
                    print(f"  bot at block ({bx},{by},{bz}); querying "
                          f"{len(xs)} column(s) x z {bz - reach}..{bz + 1}"
                          f"  (passive 0x0014):")
                    found = 0
                    for cx, cy in xs:
                        for dz in range(1, -reach - 1, -1):   # top-down
                            z = bz + dz
                            if z < 0:
                                continue
                            rep = query_block(cx, cy, z, timeout=1.2)
                            if rep and rep.get("guid"):
                                found += 1
                                here = (" <- bot's own block"
                                        if (cx, cy, dz) == (bx, by, 0) else "")
                                txt = (f"  text={rep.get('text')!r}"
                                       if rep.get("text") else "")
                                print(f"    ({cx},{cy},{z})  "
                                      f"kind={rep.get('kind'):<3} "
                                      f"{rep.get('guid')}{here}{txt}")
                    if not found:
                        if wide:
                            print("  still nothing in the 3x3 column. The "
                                  "register block may not answer 0x0014 by "
                                  "coordinate at all — tell me and we'll try a "
                                  "different route (0x000a interact, or capture "
                                  "the official client opening it).")
                        else:
                            print("  nothing on the bot's exact column. Run "
                                  "'blockhere wide' to sweep the 3x3 neighbours "
                                  "(handles an x/y off-by-one), or 'blockhere 6' "
                                  "to widen the z-scan.")
                    else:
                        print("  -> pick the register's line and:  use <guid>")
            elif line.startswith("openreg ") or line.startswith("opencash "):
                # OPEN a cash register at block (bx,by,bz): tx 0x00a4. The server
                # answers with a trade request (rx 0x00a8) from the shop owner —
                # the register menu IS a trade. We ALWAYS cancel it immediately
                # (tx 0x00ab), so nothing is ever staked or confirmed. Use this to
                # test whether the server range-gates the open: run it on the
                # register, then again from far away.
                parts = line.split()
                if len(parts) != 4:
                    print("  usage: openreg <bx> <by> <bz>   (block indices; the "
                          "register we found was 48 18 94)")
                else:
                    try:
                        bx, by, bz = (int(v) for v in parts[1:4])
                    except ValueError:
                        print("  usage: openreg <bx> <by> <bz>  (integers)")
                    else:
                        print(f"  tx 0x00a4 -> open register at ({bx},{by},{bz}) "
                              f"— will auto-cancel; nothing staked")
                        regwait["active"] = True
                        regwait["req"] = None
                        regwait["event"].clear()
                        try:
                            send(P.build_open_register(bx, by, bz))
                            got = regwait["event"].wait(4.0)
                            req = regwait["req"]
                        finally:
                            regwait["active"] = False
                        if not req:
                            print("  no trade request came back within 4s. Either "
                                  "the server RANGE-GATED the open (you're too far, "
                                  "or must be adjacent), or these coords aren't the "
                                  "register. This is the 'server-enforced' answer if "
                                  "it worked up close but not from afar.")
                        else:
                            print(f"  rx 0x00a8 TRADE REQUEST — the register opened!")
                            print(f"    owner     : {req.get('name')!r}")
                            print(f"    trade_guid: {req.get('trade_guid')}")
                            # close it right away — never proceed to a real trade
                            send(P.build_trade_cancel(req["trade_guid"]))
                            print(f"  tx 0x00ab -> cancelled the trade "
                                  f"(nothing staked, nothing spent)")
            elif line.startswith("bumphit "):
                # TEST a plot bumper: hit the block, read the rent dialog, and
                # ALWAYS cancel (never rents). Confirms the 0x00d9+0x00d7 trigger
                # reproduces live, and shows how the server classifies the plot,
                # before the auto-renting 'plotbump' loop is trusted to spend.
                parts = line.split()
                far = len(parts) >= 5 and parts[4].lower() in ("far", "remote", "block")
                if len(parts) not in (4, 5):
                    print("  usage: bumphit <bx> <by> <bz> [far]   (the bumper's "
                          "block indices; probe only — never rents. Add 'far' to "
                          "claim you're standing ON the block, so you can test "
                          "interacting from a DISTANCE instead of parking on it.)")
                else:
                    try:
                        bx, by, bz = (int(v) for v in parts[1:4])
                    except ValueError:
                        print("  usage: bumphit <bx> <by> <bz> [far]  (integers)")
                    else:
                        how = ("claiming presence AT the block (remote)" if far
                               else "from the bot's CURRENT position")
                        print(f"  tx 0x00d9+0x00d7 -> hit bumper ({bx},{by},{bz}) "
                              f"{how}; watching 2.5s for the rent dialog (probe — "
                              f"will cancel, nothing spent)")
                        info = bump_hit(bx, by, bz, answer=None, at_block=far)
                        if not info:
                            print("  no rx 0x00ca within 2.5s. Either the trigger "
                                  "needs a different form, the server range-gated "
                                  "it (move onto the bumper), or these aren't the "
                                  "bumper's block coords.")
                        else:
                            d = info["dialog"]
                            print(f"  rx 0x00ca <{d['title']}>: {d['text']}")
                            print(f"    -> kind = {info['kind']}"
                                  + (f", time left {info['seconds_left']}s"
                                     if info.get('seconds_left') else "")
                                  + (f", owner {info['owner']!r}"
                                     if info.get('owner') else ""))
                            if info["kind"] == "available":
                                print("    -> AVAILABLE — 'plotbump' here would "
                                      "rent it now (10 Cubits). This probe cancelled.")
                            elif info["kind"] == "occupied_other":
                                print("    -> still rented by someone else; "
                                      "'plotbump' would keep polling until it frees.")
                            elif info["kind"] == "occupied_self":
                                print("    -> already YOUR rental; 'plotbump' "
                                      "leaves it alone (won't re-rent your own).")
                            else:
                                print("    -> not a rent dialog; check the coords.")
            elif line == "plotbump" or line.startswith("plotbump "):
                arg = line[9:].strip() if line.startswith("plotbump ") else ""
                if arg == "stop":
                    if plotbump_ctl["active"]:
                        plotbump_ctl["stop"] = True
                        print("  stopping plotbump…")
                    else:
                        print("  no plotbump running")
                elif plotbump_ctl["active"]:
                    print("  a plotbump is already running — 'plotbump stop' first")
                else:
                    parts = arg.split()
                    bx = by = bz = None
                    delay = 0.1                    # poll interval; user starts this
                                                   # near expiry and wants it snappy
                    try:
                        bx, by, bz = int(parts[0]), int(parts[1]), int(parts[2])
                        if len(parts) >= 4:
                            delay = max(0.0, float(parts[3]))
                    except (IndexError, ValueError):
                        bx = None
                    if bx is None:
                        print("  usage: plotbump <bx> <by> <bz> [delay]   "
                              "(poll a bumper and auto-rent the moment it frees; "
                              "delay defaults to 0.1s. Park ON the bumper first, "
                              "and RUN bumphit ONCE to confirm the coords. YES "
                              "spends 10 Cubits. 'plotbump stop' aborts.)")
                    else:
                        if wallet["cubits"] is not None and wallet["cubits"] < 10:
                            print(f"  heads up: wallet shows {wallet['cubits']} "
                                  f"Cubits — a rent costs 10; it may fail.")

                        def _plotbump(bx=bx, by=by, bz=bz, delay=delay):
                            plotbump_ctl["active"] = True
                            plotbump_ctl["stop"] = False
                            polls = 0
                            last_report = 0.0
                            t0 = time.time()
                            show_line(f"[plotbump] watching bumper ({bx},{by},{bz}) "
                                      f"every {delay}s — will rent the instant it "
                                      f"frees. 'plotbump stop' to abort.")

                            def _isleep(dur):        # stop-aware sleep
                                end = time.time() + dur
                                while time.time() < end:
                                    if plotbump_ctl["stop"] or stop.is_set():
                                        return
                                    time.sleep(min(0.05, max(0.0,
                                                             end - time.time())))
                            try:
                                while not plotbump_ctl["stop"] and not stop.is_set():
                                    if not pos["placed"]:
                                        time.sleep(0.2); continue
                                    info = bump_hit(bx, by, bz, answer=True,
                                                    timeout=1.0)
                                    polls += 1
                                    if info and info.get("rented"):
                                        show_line(f"[plotbump] RENTED ({bx},{by},"
                                                  f"{bz}) after {polls} poll(s), "
                                                  f"{time.time()-t0:.1f}s. Sent YES "
                                                  f"(10 Cubits).")
                                        break
                                    if info and info["kind"] == "occupied_self":
                                        show_line("[plotbump] this plot is already "
                                                  "YOURS — nothing to do. Stopping.")
                                        break
                                    # progress line, throttled to ~once every 5s so a
                                    # 0.1s loop doesn't flood the console
                                    now = time.time()
                                    if now - last_report >= 5.0:
                                        last_report = now
                                        if info is None:
                                            msg = "no dialog (range? coords? on the bumper?)"
                                        elif info["kind"] == "occupied_other":
                                            sl = info.get("seconds_left")
                                            msg = (f"held by {info.get('owner')!r}"
                                                   + (f", {sl}s left" if sl else ""))
                                        elif info["kind"] == "available":
                                            msg = "AVAILABLE but rent not confirmed — retrying"
                                        else:
                                            msg = f"kind={info['kind']}"
                                        show_line(f"[plotbump] {polls} polls, {msg}")
                                    _isleep(delay)
                            finally:
                                if plotbump_ctl["stop"]:
                                    show_line(f"[plotbump] stopped after {polls} "
                                              f"poll(s).")
                                plotbump_ctl["active"] = False
                                plotbump_ctl["stop"] = False

                        threading.Thread(target=_plotbump, daemon=True).start()
            elif line == "build" or line.startswith("build "):
                controller = build_runtime.get("controller")
                if controller is None:
                    print("  verified builder unavailable (cc_live_builder import failed)")
                    continue
                arg = line[5:].strip()
                sub = arg.split(None, 1)[0].lower() if arg else "status"
                rest = arg[len(sub):].strip() if arg else ""
                if sub == "status":
                    print(f"  builder: {controller.status_line()}")
                    if controller.expected_realm:
                        print(f"  realm lock: {controller.expected_realm!r}")
                        print(f"  origin: {controller.origin}; safety area: "
                              f"{controller.area}")
                elif sub == "pause":
                    print("  build paused" if controller.pause()
                          else "  no running build to pause")
                elif sub == "resume":
                    print("  build resumed" if controller.resume()
                          else "  no paused build to resume")
                elif sub in ("cancel", "stop"):
                    print("  build cancellation requested" if controller.cancel()
                          else "  no running build to cancel")
                elif sub in ("inventory", "inv"):
                    snap = _own_inventory_snapshot()
                    if not snap:
                        print("  own inventory has not been received — building is "
                              "disabled")
                    else:
                        rows = sorted(snap["items"],
                                      key=lambda item: (-item.get("qty", 0),
                                                        item.get("item_id", 0)))
                        print(f"  own inventory: {len(rows)} stack(s), snapshot "
                              f"#{snap['seq']} (ordered slots used for placement)")
                        for item in rows[:20]:
                            slot = item.get("slot")
                            item_id = item.get("item_id")
                            print(f"    slot {slot:>3}: {item_label(item_id):<35} "
                                  f"x {item.get('qty', 0)}")
                elif sub == "arm":
                    # Syntax deliberately takes the final three fields as coords,
                    # leaving the exact realm name free to contain spaces/apostrophes.
                    fields = rest.rsplit(None, 3)
                    if (len(fields) != 4
                            or not all(v.lstrip("-").isdigit()
                                       for v in fields[1:])):
                        print("  usage: build arm <exact realm name> <x> <y> <z>\n"
                              "  x/y/z is the lower/front/bottom origin of the "
                              "fixed staged test layout")
                        continue
                    requested = fields[0]
                    current = state.get("realm") or ""
                    if current != requested:
                        print(f"  refusing: server realm is {current!r}, not the "
                              f"requested exact name {requested!r}")
                        continue
                    if (scanning.is_set() or autoscan_active.is_set()
                            or crawl["active"] or hollow["driver"]
                            or switching.is_set()):
                        print("  refusing to arm while a scan/warp/realm switch is "
                              "active")
                        continue
                    with cmdq_lock:
                        queued = len(cmdq)
                    if queued:
                        print(f"  refusing to arm with {queued} queued realm/movement "
                              "command(s); use 'queue clear' first")
                        continue
                    if (pending.get("guid") or pending.get("join")
                            or pending.get("autoscan")
                            or realm_search["then_join"]
                            or realm_search["then_scan"]):
                        print("  refusing to arm while a realm handoff/search "
                              "or automatic scan is pending")
                        continue
                    if (trades or prize_ctl["active"] or plotbump_ctl["active"]
                            or fill_ctl["active"] or buy_orders
                            or autosnipe["on"]):
                        print("  refusing to arm while a trade/purchase/build "
                              "automation is enabled or active; stop it first "
                              "('snipe off' disables the default auto-snipe)")
                        continue
                    # A Hollawarp arriving during a build must never pull the bot
                    # out of the authorized realm. Leave it off after the test.
                    hollow["auto"] = False
                    origin = tuple(int(v) for v in fields[1:])
                    ok, message = controller.arm(current, origin)
                    print("  " + ("OK: " if ok else "REFUSED: ") + message)
                    if ok:
                        print(f"  credential-free audit: {build_audit_path}")
                elif sub in ("suite", "go"):
                    hollow["auto"] = False
                    ok, message = controller.start_suite()
                    print("  " + ("OK: " if ok else "REFUSED: ") + message)
                else:
                    print("  build status | build inventory | build arm <exact "
                          "realm> <x> <y> <z> | build suite | build pause | "
                          "build resume | build cancel")
            elif line.startswith("place ") or line.startswith("copy "):
                # SINGLE-BLOCK place / copy — the "copy-paste one block" tool.
                #
                #   place <id> <x> <y> <z>
                #       -> place block type <id> at grid cell (x,y,z). <id> is
                #          the same numeric type id the 'blocks' list shows
                #          and own inventory uses. The verified builder resolves
                #          it to the current inventory slot before each send.
                #   copy <fx> <fy> <fz>
                #       -> read the block type sitting at SOURCE cell (fx,fy,fz)
                #          and paste a copy of it AT THE BOT'S CURRENT SPOT.
                #          Stand where you want it, then run this — the simplest
                #          form: "find the block, give its coords, copied to me".
                #   copy <fx> <fy> <fz> <tx> <ty> <tz>
                #       -> same, but paste at an explicit TARGET cell (tx,ty,tz)
                #          instead of where the bot stands.
                #          All coords are the same XYZ that 'blocks' prints. The
                #          read sends NOTHING — it uses the world objects already
                #          received on realm entry, so run 'blocks' first if the
                #          list looks empty.
                #
                # The command is routed through the realm-locked verified builder:
                # empty-cell/inventory/reach checks, one PLACE frame, inventory
                # decrement, and a server block query are all required.
                if not pos["placed"]:
                    print("  not placed in a realm yet — enter a realm first.")
                    continue
                parts = line.split()
                is_copy = parts[0].lower() == "copy"
                nums = parts[1:]
                # copy takes 3 (paste at the bot) OR 6 (explicit target); place 4.
                need_ok = (len(nums) in (3, 6)) if is_copy else (len(nums) == 4)
                if not need_ok or not all(n.lstrip("-").isdigit() for n in nums):
                    if is_copy:
                        print("  usage: copy <fromX> <fromY> <fromZ>            "
                              "  (paste at the bot's current spot)\n"
                              "         copy <fromX> <fromY> <fromZ> <toX> <toY> "
                              "<toZ>   (paste at an explicit cell)\n"
                              "  coords are the grid cells 'blocks' shows.")
                    else:
                        print("  usage: place <block_id> <x> <y> <z>   "
                              "(block_id is the catalogue id 'build inventory' "
                              "shows)")
                    continue
                nums = [int(n) for n in nums]
                if is_copy:
                    fx, fy, fz = nums[:3]
                    if len(nums) == 6:
                        tx, ty, tz = nums[3:]
                    else:
                        # paste where the bot is standing (its own grid cell)
                        B = P.COORD_BASE
                        me = player_block.get(conn.get("own"))
                        if me:
                            tx, ty, tz = me
                        else:
                            tx, ty, tz = (pos["x"] // B, pos["y"] // B,
                                          pos["z"] // B)
                    # What's the copyable TYPE at the source? Only the passive
                    # object burst carries the paint/type id, so read it there.
                    item_id = None
                    for o in world.values():
                        if (o.get("bx") == fx and o.get("by") == fy
                                and o.get("bz") == fz):
                            item_id = o.get("type_id")
                            break
                    # ACTIVELY confirm a block is really at the source right now
                    # (tx 0x0014 — read-only, opens no dialog, spends nothing).
                    print(f"  querying source ({fx},{fy},{fz}) ...")
                    rep = query_block(fx, fy, fz)
                    if not rep and item_id is None:
                        print(f"  no block found at source ({fx},{fy},{fz}) — the "
                              f"server didn't answer for that cell. Check the coords "
                              f"('blocks' lists them) and that you're in the right "
                              f"realm.")
                        continue
                    if item_id is None:
                        # A block IS there, but 0x0014 doesn't carry the type id,
                        # so we can't know WHAT to paste. The burst is the only
                        # source of the paint id.
                        k = rep.get("kind") if rep else None
                        print(f"  a block IS at ({fx},{fy},{fz}) (kind {k}) but its "
                              f"type id isn't in the object burst, so I can't tell "
                              f"what block it is to copy it. Run 'blocks' (or "
                              f"'blocks scan box') to load type ids, then retry.")
                        continue
                    if not rep:
                        print(f"  note: ({fx},{fy},{fz}) is in the object list but "
                              f"the server didn't confirm a block there just now — "
                              f"copying the listed type anyway.")
                    print(f"  found {item_label(item_id)} at ({fx},{fy},{fz}); "
                          f"copying -> ({tx},{ty},{tz})")
                else:
                    item_id, tx, ty, tz = nums
                    print(f"  placing {item_label(item_id)} at ({tx},{ty},{tz})")

                controller = build_runtime.get("controller")
                if not controller or not controller.expected_realm:
                    print("  raw unconfirmed placement is disabled. First run "
                          "'build arm <exact realm> <x> <y> <z>' to establish a "
                          "verified empty safety area.")
                    continue
                ok, message = controller.start_block((tx, ty, tz), item_id)
                print("  " + ("OK: " if ok else "REFUSED: ") + message)
            elif line == "fill" or line.startswith("fill "):
                # OUTLINE FILLER. Stand INSIDE a closed border of blocks you built
                # on one flat layer, then:
                #
                #   fill                 -> PREVIEW at your layer (dry run — places
                #                           nothing; shows the interior + any leak)
                #   fill preview [z]     -> preview, optionally naming the layer z
                #   fill go <block_id> [z] [gap] [delay]
                #                        -> actually place block type <block_id> in
                #                           every enclosed empty cell. block_id is
                #                           the catalogue item id shown by
                #                           `build inventory`
                #                           z defaults to your layer. Legacy gap
                #                           and delay arguments are accepted, but
                #                           cannot override the verified builder's
                #                           reach and conservative action delays.
                #   fill stop            -> abort a running fill
                #
                # The numeric id is resolved against the current ordered inventory
                # snapshot before every PLACE; the wire field is a slot index.
                # Safety: the interior is found by flooding OUT from where you
                # stand, fenced by the outline's bounding box — if the border has
                # a gap the flood leaks to the fence and the fill REFUSES rather
                # than spilling into the realm. Bare `fill` never places anything.
                arg = line[5:].strip() if line.startswith("fill ") else ""
                parts = arg.split()
                sub = parts[0].lower() if parts else "preview"
                if sub == "stop":
                    controller = build_runtime.get("controller")
                    if controller and controller.cancel():
                        print("  verified fill cancellation requested")
                    elif fill_ctl["active"]:
                        fill_ctl["stop"] = True
                        print("  stopping fill…")
                    else:
                        print("  no fill running")
                elif fill_ctl["active"]:
                    print("  a fill is already running — 'fill stop' first")
                elif not pos["placed"]:
                    print("  not placed in a realm yet — enter a realm and stand "
                          "inside your outline first")
                else:
                    B = P.COORD_BASE
                    seed = (pos["x"] // B, pos["y"] // B)
                    botz = pos["z"] // B
                    go = (sub == "go")
                    rest = parts[1:] if sub in ("go", "preview") else parts
                    z = botz
                    gap = 0
                    delay = 0.25
                    item_id = None
                    if go:
                        # `fill go <block_id> [z] [gap] [delay]` — id is required so
                        # a fill can never place the wrong (default) block by accident
                        if not rest or not rest[0].lstrip("-").isdigit():
                            print("  usage: fill go <block_id> [z] [gap] [delay]   "
                                  "— block_id is the catalogue id shown by 'build "
                                  "inventory'. Run bare 'fill' first to preview "
                                  "the area.")
                            continue
                        try:
                            item_id = int(rest[0])
                            if len(rest) >= 2 and rest[1].lstrip("-").isdigit():
                                z = int(rest[1])
                            if len(rest) >= 3:
                                gap = max(0, min(3, int(rest[2])))
                            if len(rest) >= 4:
                                delay = max(0.0, float(rest[3]))
                        except ValueError:
                            print("  bad number in 'fill go' — usage: fill go "
                                  "<block_id> [z] [gap] [delay]")
                            continue
                    else:
                        try:
                            if rest and rest[0].lstrip("-").isdigit():
                                z = int(rest[0])
                        except ValueError:
                            pass
                    interior, reason = flood_interior(z, seed)
                    if reason == "no-outline":
                        print(f"  no outline on layer z={z} — build a CLOSED border "
                              f"of blocks around where you stand (only "
                              f"{len(outline_layer_cells(z))} block(s) there).")
                    elif reason == "on-border":
                        print(f"  you're standing ON a border block (or outside the "
                              f"outline) at z={z}. Stand on an EMPTY cell INSIDE "
                              f"the loop, then run fill again.")
                    elif reason == "open":
                        print(f"  the outline on z={z} isn't closed — the fill "
                              f"leaked out through a gap, so I won't place anything. "
                              f"Seal the border (no diagonal-only corners) and retry. "
                              f"('blocks' lists what's placed here.)")
                    elif reason == "too-big":
                        print(f"  the enclosed area on z={z} is over the safety cap "
                              f"(6000 cells) — likely open or huge. Not filling.")
                    elif not interior:
                        print(f"  nothing to fill on z={z} (the interior is already "
                              f"full).")
                    else:
                        # nearest-first from the bot, so it fills outward from feet
                        cells = sorted(interior,
                                       key=lambda c: (abs(c[0] - seed[0])
                                                      + abs(c[1] - seed[1]),
                                                      c[0], c[1]))
                        if z != botz:
                            print(f"  note: you're on layer {botz} but filling "
                                  f"z={z}; the bot places from where it stands, so "
                                  f"stand on the SAME layer as the outline or the "
                                  f"far cells may be out of reach.")
                        if not go:
                            xs = [c[0] for c in cells]
                            ys = [c[1] for c in cells]
                            print(f"  PREVIEW (dry run — nothing placed): {len(cells)} "
                                  f"empty cell(s) enclosed on z={z}, "
                                  f"x {min(xs)}..{max(xs)}, y {min(ys)}..{max(ys)}.")
                            for (bx, by) in cells[:20]:
                                print(f"    ({bx},{by},{z})")
                            if len(cells) > 20:
                                print(f"    … and {len(cells) - 20} more")
                            print(f"  run 'fill go <block_id>' to place all "
                                  f"{len(cells)}; get the catalogue id from "
                                  "'build inventory'.")
                        else:
                            controller = build_runtime.get("controller")
                            if not controller or not controller.expected_realm:
                                print("  live fill requires an armed exact-realm "
                                      "safety area; run 'build arm …' first")
                                continue
                            absolute = [(bx, by, z) for bx, by in cells]
                            if len(rest) >= 3:
                                print("  legacy gap/delay overrides ignored; using "
                                      "verified reach and safe builder delays")
                            ok, message = controller.start_cells(
                                absolute, item_id,
                                label=f"outline fill on z={z}")
                            print("  " + ("OK: " if ok else "REFUSED: ") + message)
            elif line == "machines":
                by_block = occupied_blocks()
                probes = probe_blocks(by_block)
                print(f"  {len(world)} world object(s) on {len(by_block)} "
                      f"grid-aligned block(s); {len(probes)} blocks a scan "
                      f"would query  (passive — nothing sent)")
                if offers:
                    print(f"  {len(offers)} confirmed machine(s):")
                    for rec in sorted(offers.values(), key=lambda r: r["block"]):
                        bx, by, bz = rec["block"]
                        o = rec["offer"]
                        print(f"    ({bx:>3},{by:>3},{bz:>3}) x"
                              f"{len(rec['objs']):<3} {describe_offer(o)}"
                              f"   [{rec['how']}]")
                else:
                    print("  no machines confirmed yet — a machine is only known "
                          "to be one once the server says so, so run 'scan' "
                          "(queries every block; dialogs are always cancelled, "
                          "never bought)")
            elif (line in ("inventory", "inv")
                  or line.startswith("inventory ") or line.startswith("inv ")):
                # A realm's whole on-display inventory: everything shown in glass,
                # on mannequins, pedestals or shelves rides the wire as placed
                # objects, so we just aggregate the object stream by item id.
                # Passive — nothing is sent.
                arg = line.split(None, 1)[1].strip() if " " in line else ""
                inv = P.realm_inventory(world.values())
                named = " (named)" if item_names else " (ids only — run cc_items.py for names)"
                print(f"  {state.get('realm') or '?'} "
                      f"(owner {state.get('realm_owner') or '?'}): "
                      f"{inv['total']} item(s) on display, "
                      f"{inv['distinct']} distinct{named}  (passive — nothing sent)")
                n_mann = sum(1 for o in world.values()
                             if o["type_id"] == P.MANNEQUIN_TYPE_ID)
                if not inv["total"]:
                    print("  nothing yet — the realm's object list may still be "
                          "loading; give it a few seconds after entering")
                else:
                    ordered = sorted(inv["counts"].items(),
                                     key=lambda kv: (-kv[1], kv[0]))
                    # one item per line when named (names are wide), else pack
                    if item_names:
                        for tid, c in ordered:
                            print(f"    {c:>3} x  {item_label(tid)}")
                    else:
                        row = []
                        for tid, c in ordered:
                            row.append(f"id {tid} x{c}" if c > 1 else f"id {tid}")
                            if len(row) == 6:
                                print("    " + "   ".join(row)); row = []
                        if row:
                            print("    " + "   ".join(row))
                if n_mann:
                    print(f"  + {n_mann} mannequin(s) here — their worn clothes are "
                          f"NOT in this list; run 'mannequins' to read them")
                if arg:                       # inventory <path> -> write a file
                    path = arg or f"inventory-{time.strftime('%Y%m%d-%H%M%S')}.csv"
                    rows = [{"realm": state.get("realm"),
                             "owner": state.get("realm_owner"),
                             "type_id": tid, "name": item_names.get(tid, ""),
                             "count": c}
                            for tid, c in sorted(inv["counts"].items(),
                                                 key=lambda kv: (-kv[1], kv[0]))]
                    if path.endswith(".json"):
                        with open(path, "w", encoding="utf-8") as fh:
                            json.dump(rows, fh, indent=1, default=str)
                    else:
                        import csv as _csv
                        with open(path, "w", newline="", encoding="utf-8") as fh:
                            w = _csv.DictWriter(fh, fieldnames=["realm", "owner",
                                "type_id", "name", "count"])
                            w.writeheader(); w.writerows(rows)
                    print(f"  wrote {len(rows)} distinct item(s) to {path}")
            elif line == "glass" or line.startswith("glass "):
                # Narrower view: only items literally inside a GLASS CASE container
                # object (a second object stacked on a type_id-1113 block). Most
                # realms display on open shelves, so this is usually a subset of
                # 'inventory' — use 'inventory' for the full collection.
                displays = P.find_glass_displays(world.values())
                stocked = [d for d in displays if d["stocked"]]
                print(f"  {len(displays)} glass case(s): {len(stocked)} stocked, "
                      f"{len(displays) - len(stocked)} empty  (passive; most "
                      f"realms display on open shelves — try 'inventory')")
                for d in stocked:
                    bx, by, bz = d["block"]
                    ids = ", ".join(item_label(i["type_id"]) for i in d["items"])
                    print(f"    ({bx:>3},{by:>3},{bz:>3})  {ids}")
            elif line.startswith("mannequin ") and len(line.split()) == 4:
                # read ONE mannequin by exact block coords (aim at it in-game and
                # read where you're standing/looking). Works for mannequins that
                # are BLOCKS, which aren't in the object stream at all (like signs).
                try:
                    bx, by, bz = (int(v) for v in line.split()[1:4])
                except ValueError:
                    print("  usage: mannequin <bx> <by> <bz>")
                else:
                    inv, used = read_mannequin_at(bx, by, bz, reach=2)
                    worn = P.worn_items(inv)
                    if worn:
                        print(f"  ({bx},{by},{bz}): " + ", ".join(
                            item_label(i) + (f" x{q}" if q > 1 else "")
                            for i, q in worn))
                    elif inv is not None:
                        print(f"  ({bx},{by},{bz}): mannequin is empty (no outfit)")
                    else:
                        print(f"  ({bx},{by},{bz}): no mannequin found there "
                              f"(aim right at it; try the exact block)")
            elif (line in ("mannequins", "mann", "outfits")
                  or line.startswith("mannequins ") or line.startswith("mann ")):
                # Mannequin clothes aren't objects — they're outfit state, read via
                # 0x0014 (block guid) then 0x000e. Auto-enumerate finds mannequins
                # that appear as 438 objects; some are placed as BLOCKS (not in the
                # object stream) — for those use `mannequin <bx> <by> <bz>`.
                arg = line.split(None, 1)[1].strip() if " " in line else ""
                # candidate mannequin blocks: entities seen via 0x0005 (the ones
                # you walked past) PLUS any 438 objects in the stream.
                blocks = set(mannequin_seen.keys())
                blocks |= {(o["bx"], o["by"], o["bz"]) for o in world.values()
                           if o["type_id"] == P.MANNEQUIN_TYPE_ID}
                if not blocks:
                    print("  no mannequins seen yet — WALK PAST them so they load "
                          "(they broadcast as you approach), then run 'mannequins' "
                          "again. Or aim at one: 'mannequin <bx> <by> <bz>'.")
                else:
                    print(f"  reading {len(blocks)} mannequin(s) seen in this realm "
                          f"— 0x0014 then 0x000e each, read-only, nothing spent ...")
                    rows = []
                    read_ok = 0
                    for (bx, by, bz) in sorted(blocks):
                        inv, used = read_mannequin_at(bx, by, bz)
                        worn = P.worn_items(inv)
                        if worn:
                            read_ok += 1
                            lbl = ", ".join(item_label(i) + (f" x{q}" if q > 1 else "")
                                            for i, q in worn)
                        elif inv is not None:
                            lbl = "(empty)"
                        else:
                            lbl = "(no outfit / not a mannequin)"
                        print(f"    ({bx:>3},{by:>3},{bz:>3})  {lbl}")
                        for i, q in worn:
                            rows.append({"realm": state.get("realm"),
                                         "owner": state.get("realm_owner"),
                                         "x": bx, "y": by, "z": bz,
                                         "item_id": i, "name": item_names.get(i, ""),
                                         "qty": q})
                        time.sleep(0.12)     # gentle pacing
                    print(f"  {len(rows)} worn item(s) across {read_ok}/{len(blocks)} "
                          f"readable mannequin(s)")
                    if arg and rows:
                        path = arg or f"mannequins-{time.strftime('%Y%m%d-%H%M%S')}.csv"
                        if path.endswith(".json"):
                            with open(path, "w", encoding="utf-8") as fh:
                                json.dump(rows, fh, indent=1, default=str)
                        else:
                            import csv as _csv
                            with open(path, "w", newline="", encoding="utf-8") as fh:
                                w = _csv.DictWriter(fh, fieldnames=["realm", "owner",
                                    "x", "y", "z", "item_id", "name", "qty"])
                                w.writeheader(); w.writerows(rows)
                        print(f"  wrote {len(rows)} worn item(s) to {path}")
            elif line == "dump" or line.startswith("dump "):
                arg = line[5:].strip() if line.startswith("dump ") else ""
                stamp = time.strftime("%Y%m%d-%H%M%S")
                if arg.split()[:1] == ["raw"]:
                    # the whole object list — only useful for working out why a
                    # machine was missed
                    path = arg[3:].strip() or f"world-{stamp}.json"
                    with open(path, "w", encoding="utf-8") as fh:
                        json.dump({"realm": state["realm"],
                                   "owner": state["realm_owner"],
                                   "objects": list(world.values())},
                                  fh, indent=1, default=str)
                    print(f"  wrote {len(world)} raw object(s) to {path}")
                elif not offers:
                    print("  nothing to dump — no machines found yet, run 'scan'")
                else:
                    path = arg or f"machines-{stamp}.csv"
                    n = dump_machines(path)
                    print(f"  wrote {n} machine(s) to {path}   "
                          f"(.csv/.txt/.json by extension; 'dump raw' writes "
                          f"the object list instead)")
            elif line == "prize" or line.startswith("prize "):
                arg = line[6:].strip() if line.startswith("prize ") else ""
                if arg == "stop":
                    if prize_ctl["active"]:
                        prize_ctl["stop"] = True
                        print("  stopping prize crack…")
                    else:
                        print("  no prize crack running")
                elif arg.split()[:1] == ["test"]:
                    rest = arg[4:].strip().split()
                    qblock, code = None, None
                    if len(rest) == 1:                 # prize test <code>
                        code = rest[0]
                    elif len(rest) == 4:               # prize test <bx> <by> <bz> <code>
                        try:
                            qblock = (int(rest[0]), int(rest[1]), int(rest[2]))
                            code = rest[3]
                        except ValueError:
                            code = None
                    if not code:
                        print("  usage: prize test <code>            (auto-finds + "
                              "arms the dispenser, then guesses)")
                        print("     or: prize test <bx> <by> <bz> <code>   "
                              "(arm THIS block explicitly)")
                    elif prize_ctl["active"]:
                        print("  a prize crack is running — 'prize stop' first")
                    else:
                        # ARM the sentry the way the real client does: block-query
                        # the Prize Dispenser (type_id 179) before guessing. Without
                        # this the server rejects even the correct password.
                        if qblock is None:
                            disp = [o for o in world.values()
                                    if o.get("type_id") == 179]
                            if disp and pos["placed"]:
                                pb = (pos["x"] // 100000, pos["y"] // 100000,
                                      pos["z"] // 100000)
                                disp.sort(key=lambda o: abs(o["bx"] - pb[0])
                                          + abs(o["by"] - pb[1])
                                          + abs(o["bz"] - pb[2]))
                            if disp:
                                o = disp[0]
                                qblock = (o["bx"], o["by"], o["bz"])
                        prize_probe["frames"] = []
                        prize_probe["active"] = True
                        if qblock:
                            print(f"  [test] arming dispenser block {qblock}, then "
                                  f"guessing '{code}', watching 3s…")
                            try:
                                send(P.build_block_query(*qblock))
                            except Exception as e:
                                print(f"  arm query failed: {e}")
                            time.sleep(0.4)
                        else:
                            print(f"  [test] no Prize Dispenser (type_id 179) in "
                                  f"world — guessing '{code}' un-armed, watching 3s…")
                        try:
                            send(P.build_password_guess(code))
                        except Exception as e:
                            print(f"  send failed: {e}")
                        time.sleep(3.0)
                        prize_probe["active"] = False
                        frames = list(prize_probe["frames"])
                        skip = {0x0006, 0x0007, 0x0008, 0x0101, 0x005a, 0x000b}
                        shown = 0
                        for tt, ty, hx in frames:
                            if ty in skip:
                                continue
                            b = bytes.fromhex(hx)
                            note = ""
                            if ty == 0x0036:
                                wp = P.parse_wrong_password(b)
                                note = (f"  <- WRONG: {wp['text']!r}" if wp
                                        else "  <- 0x0036 dialog (not wrong-pw)")
                            elif ty == 0x0014:
                                inf = P.parse_block_query_reply(b)
                                note = (f"  <- 0x0014 reply, guid={(inf.get('guid') or '<none>')[:12]} "
                                        f"kind={inf['kind']}" if inf else "")
                            elif ty == 0x000f:
                                o = P.parse_world_objects(b)
                                if o:
                                    note = f"  <- world obj kind={o[0]['kind']}"
                            elif ty == 0x0037:
                                note = "  <- INVENTORY_CHANGED"
                            elif ty == 0x00de:
                                note = f"  <- notice {P.parse_notice_00de(b)!r}"
                            print(f"    rx 0x{ty:04x} {len(b):3}B  {hx[:48]}{note}")
                            shown += 1
                        if not shown:
                            print("    (no non-noise reply in 3s — the guess may "
                                  "not have registered; is the bot ON the machine?)")
                elif arg.split()[:1] == ["find"]:
                    try:
                        r = int(arg.split()[1])
                    except (IndexError, ValueError):
                        r = 3
                    b = find_dispenser_block(r=r, report=True)
                    if b:
                        print(f"  -> crack it with:  prize <lo> <hi> "
                              f"{b[0]} {b[1]} {b[2]} 0.2")
                        print("  -> or just:  prize <lo> <hi>   (auto-finds it "
                              "each run, since you park by the machine)")
                    else:
                        print("  no dispenser (kind 0x13) found nearby — move "
                              "closer and/or widen: prize find 5")
                elif prize_ctl["active"]:
                    print("  a prize crack is already running — 'prize stop' first")
                else:
                    parts = arg.split()
                    # optional trailing 'down'/'desc'/'top' -> crack hi..lo
                    descending = False
                    if parts and parts[-1].lower() in ("down", "desc", "top"):
                        descending = True
                        parts = parts[:-1]
                    lo = hi = None
                    block = None
                    delay = 0.1                       # inter-guess pause; pass 0 to
                                                      # go as fast as the round-trips
                                                      # allow (watch for 'silent' aborts)
                    try:
                        lo, hi = int(parts[0]), int(parts[1])
                        if len(parts) >= 5:                # explicit dispenser block
                            block = (int(parts[2]), int(parts[3]), int(parts[4]))
                            if len(parts) >= 6:
                                delay = max(0.0, float(parts[5]))
                        elif len(parts) >= 3:              # prize <lo> <hi> <delay>
                            delay = max(0.0, float(parts[2]))
                    except (IndexError, ValueError):
                        lo = None
                    if lo is None or hi is None:
                        print("  usage: prize <lo> <hi> [delay]                "
                              "(auto-finds the dispenser — just park by it)")
                        print("     or: prize <lo> <hi> <bx> <by> <bz> [delay]  "
                              "(explicit dispenser block)")
                        print("  e.g.:  prize 1 9999 0.2      "
                              "('prize find' locates it; 'prize stop' aborts)")
                    elif lo < 0 or hi < lo:
                        print("  bad range: need 0 <= lo <= hi")
                    else:
                        if block is None:                  # auto-find near the bot
                            print("  finding the dispenser…")
                            block = find_dispenser_block(report=True)
                        # given block: use it directly (pick it from 'prize find')
                        if block is None:
                            print("  no dispenser found — park the bot right next "
                                  "to the machine, or widen: prize find 4")
                        else:
                            threading.Thread(
                                target=run_prize_crack,
                                args=(lo, hi, block, delay),
                                kwargs={"descending": descending},
                                daemon=True).start()
            elif line == "scan" or line.startswith("scan "):
                arg = line[5:].strip().lower() if line.startswith("scan ") else ""
                limit, include_all, reach = None, False, 1
                for part in arg.split():
                    if part == "all":
                        include_all = True
                    elif part == "wide":
                        reach = 2
                    elif part == "near":
                        reach = 0        # object coordinates only — rarely works
                    else:
                        try:
                            limit = int(part)
                        except ValueError:
                            pass
                scan_machines(limit=limit, include_all=include_all, reach=reach)
            elif line == "buy" or line.startswith("buy "):
                # Owner-only by construction: a CONSOLE command only, never wired
                # into the in-game chat handlers. Adding an order buys immediately
                # off the already-scanned list; there is no arm step. Guards
                # (price ceiling, optional budget/max, per-machine dedup, wallet
                # pre-check) are the safety.
                arg = line[4:].strip() if line.startswith("buy ") else ""
                sub = arg.lower()      # NB: not 'low' — that name is a live closure var
                if not arg:
                    bal = wallet["cubits"]
                    print(f"  buy: wallet {bal if bal is not None else '?'} "
                          f"Cubits; {len(buy_orders)} order(s). Orders buy off "
                          f"the scanned list as soon as they match.")
                    if not buy_orders:
                        print("  no orders. Add one: "
                              "buy <item> under <price> [max N] [budget C]")
                    for o in buy_orders:
                        stt = "active" if o.get("active", True) else "done"
                        print(f"    [{stt}] '{o['item']}' <= {o['max_price']} "
                              f"Cubits"
                              + (f", max {o['qty']}x" if o.get("qty") else "")
                              + (f", budget {o['budget']}" if o.get("budget")
                                 else "")
                              + f"  (bought {o.get('bought', 0)}, "
                              f"spent {o.get('spent', 0)})")
                elif sub in ("now", "try", "go"):
                    # Re-run active orders against the machines already known in
                    # this realm (e.g. after moving realms, or to retry). Both
                    # owner orders and player (deposited-balance) orders.
                    fill_orders_here(report=True)
                    fill_player_orders_here(report=True)
                elif sub in ("travel", "catalogue", "cat", "all"):
                    # Catalogue-wide: crawl every saved realm that has a matching
                    # listing and buy on arrival.
                    buy_travel()
                elif sub in ("off", "clear"):
                    buy_orders.clear()
                    save_buy_orders()
                    print("  all buy orders removed.")
                elif sub.startswith("cancel "):
                    needle = arg[7:].strip().lower()
                    before = len(buy_orders)
                    buy_orders[:] = [o for o in buy_orders
                                     if needle not in o["item"].lower()]
                    save_buy_orders()
                    print(f"  removed {before - len(buy_orders)} order(s) "
                          f"matching '{needle}'.")
                elif " under " in sub:
                    head, _, rest = arg.partition(" under ")
                    item = head.strip()
                    toks = rest.split()
                    max_price = None
                    if toks:
                        try:
                            max_price = int(toks[0].replace(",", ""))
                        except ValueError:
                            max_price = None
                    if not item or max_price is None:
                        print("  usage: buy <item> under <price> "
                              "[max N] [budget C]")
                    else:
                        qty = bud = None
                        i = 1
                        while i < len(toks) - 1:
                            key, val = toks[i].lower(), toks[i + 1]
                            if key == "max":
                                try:
                                    qty = int(val)
                                except ValueError:
                                    pass
                                i += 2
                            elif key == "budget":
                                try:
                                    bud = int(val.replace(",", ""))
                                except ValueError:
                                    pass
                                i += 2
                            else:
                                i += 1
                        buy_orders.append({"item": item, "max_price": max_price,
                                           "qty": qty, "budget": bud,
                                           "spent": 0, "bought": 0,
                                           "active": True, "dedup": set()})
                        save_buy_orders()
                        print(f"  order added: buy '{item}' at <= {max_price} "
                              f"Cubits"
                              + (f", up to {qty}x" if qty else "")
                              + (f", budget {bud}" if bud else "")
                              + ". Buying off the scanned list now ...")
                        # Buy immediately from whatever is already scanned here.
                        fill_orders_here(report=True)
                else:
                    print("  usage: buy <item> under <price> [max N] [budget C] "
                          "| buy travel | buy now | buy cancel <item> | buy off")
            elif line == "snipe" or line.startswith("snipe "):
                # Always-on giveaway sniper. `snipe` shows status; `snipe on|off`
                # toggles it; `snipe avg <N>` sets the min community value (default
                # 2,000c) an item must be worth; `snipe max <N>` sets the ceiling
                # listing price that counts as a giveaway (default 1c). Nothing is
                # bought unless BOTH hold: listed <= max AND community avg >= avg.
                arg = line[6:].strip() if line.startswith("snipe ") else ""
                sub = arg.lower()
                if sub in ("on", "off"):
                    autosnipe["on"] = (sub == "on")
                    if autosnipe["on"]:
                        _ensure_prices()
                    print(f"  auto-snipe {'ON' if autosnipe['on'] else 'OFF'}.")
                elif sub.startswith("avg "):
                    try:
                        autosnipe["min_avg"] = float(arg[4:].replace(",", ""))
                        print(f"  auto-snipe min value = "
                              f"{autosnipe['min_avg']:.0f}c.")
                    except ValueError:
                        print("  usage: snipe avg <cubits>")
                elif sub.startswith("max "):
                    try:
                        v = int(arg[4:].replace(",", ""))
                        autosnipe["steal_max"] = v
                        autosnipe["order"]["max_price"] = v
                        print(f"  auto-snipe giveaway ceiling = {v}c.")
                    except ValueError:
                        print("  usage: snipe max <cubits>")
                elif sub in ("", "status"):
                    o = autosnipe["order"]
                    have = len(pricebot["map"])
                    print(f"  auto-snipe {'ON' if autosnipe['on'] else 'OFF'}: "
                          f"buy any item listed <= {autosnipe['steal_max']}c whose "
                          f"community value >= {autosnipe['min_avg']:.0f}c "
                          f"(bought {o.get('bought', 0)} this session; "
                          f"{have} community prices loaded).")
                    print("  tune: snipe on|off | snipe avg <cubits> | "
                          "snipe max <cubits>")
                else:
                    print("  usage: snipe [on|off] | snipe avg <cubits> | "
                          "snipe max <cubits>")
            elif line == "webhook" or line.startswith("webhook "):
                # Discord alert wiring. `webhook` shows status; `webhook set
                # <url>` saves a Discord webhook URL (alerts on prize cracks +
                # snipe snags); `webhook test` fires a test ping; `webhook off`
                # clears it. Persisted to webhook.json so it survives restarts.
                arg = line[8:].strip() if line.startswith("webhook ") else ""
                sub = arg.lower()
                if sub.startswith("set "):
                    new = arg[4:].strip()
                    if not _webhook_looks_valid(new):
                        print("  that doesn't look like a Discord webhook URL "
                              "(expected https://discord.com/api/webhooks/...).")
                    else:
                        webhook["url"] = new
                        save_webhook()
                        print("  webhook saved. alerts ON for prize cracks + "
                              "snipe snags. 'webhook test' to try it.")
                elif sub in ("off", "clear", "remove"):
                    webhook["url"] = ""
                    save_webhook()
                    print("  webhook cleared — Discord alerts OFF.")
                elif sub == "test":
                    if not (webhook.get("url") or "").strip():
                        print("  no webhook set. 'webhook set <url>' first.")
                    else:
                        discord_notify("✅ CubicBot test",
                                       "Your Discord alerts are wired up.")
                        print("  test ping sent (check your Discord channel).")
                elif sub in ("prize on", "prize off", "snipe on", "snipe off"):
                    which, onoff = sub.split()
                    webhook[which] = (onoff == "on")
                    save_webhook()
                    label = "prize-crack" if which == "prize" else "snipe-snag"
                    print(f"  {label} alerts {'ON' if webhook[which] else 'OFF'}.")
                elif sub in ("", "status"):
                    if (webhook.get("url") or "").strip():
                        u = webhook["url"]
                        tail = u[-6:] if len(u) > 6 else u
                        p = "ON" if webhook.get("prize", True) else "OFF"
                        s = "ON" if webhook.get("snipe", True) else "OFF"
                        print(f"  Discord webhook SET (...{tail}).  "
                              f"prize-crack alerts {p} | snipe-snag alerts {s}")
                    else:
                        print("  Discord alerts OFF. 'webhook set <url>' with a "
                              "Discord channel webhook to turn them on.")
                    print("  tune: webhook set <url> | webhook test | "
                          "webhook prize on|off | webhook snipe on|off | "
                          "webhook off")
                else:
                    print("  usage: webhook [status] | webhook set <url> | "
                          "webhook test | webhook prize on|off | "
                          "webhook snipe on|off | webhook off")
            elif line.startswith("deposit ") or line.startswith("payout "):
                # Operator ledger commands. Until the in-game trade window is
                # decoded, the operator does the physical trade BY HAND, then
                # records it here so the player's balance is right and the bot
                # will buy for them. 'deposit' credits (cubits received from the
                # player); 'payout' debits (cubits handed back).
                is_dep = line.startswith("deposit ")
                verb = "deposit" if is_dep else "payout"
                if odb is None:
                    print("  buy-order ledger is off (--no-orders-db).")
                else:
                    rest = line[len(verb) + 1:].rsplit(None, 1)
                    if len(rest) != 2:
                        print(f"  usage: {verb} <player name> <amount>")
                    else:
                        pname = rest[0].strip()
                        try:
                            amt = int(rest[1].replace(",", ""))
                            fn = odb.deposit if is_dep else odb.payout
                            bal = fn(pname, amt)
                            print(f"  {verb}: {pname} balance now {bal} cubits.")
                        except (ValueError, cc_orders.OrderError) as ex:
                            print(f"  {verb} failed: {ex}")
            elif line == "balances":
                if odb is None:
                    print("  buy-order ledger is off (--no-orders-db).")
                else:
                    rows = odb.all_balances()
                    if not rows:
                        print("  no player balances yet.")
                    for name, bal, res in rows:
                        extra = f" ({res} reserved)" if res else ""
                        print(f"    {bal:>10}  {name}{extra}")
            elif line == "orders" or line.startswith("orders "):
                if odb is None:
                    print("  buy-order ledger is off (--no-orders-db).")
                else:
                    who = line[7:].strip() if line.startswith("orders ") else ""
                    rows = odb.orders_for(who) if who else odb.open_orders()
                    if not rows:
                        print(f"  no {'orders for ' + who if who else 'open orders'}.")
                    for o in rows:
                        print(f"    #{o['id']} [{o['status']}] {o['account']}: "
                              f"{o['qty_bought']}/{o['qty_requested']} x "
                              f"'{o['item_query']}' @<= {o['max_unit_price']}")
            elif line == "autotrade" or line.startswith("autotrade "):
                arg = line[10:].strip().lower() if line.startswith("autotrade ") \
                    else ""
                if arg.startswith("probe"):
                    parg = arg[5:].strip()
                    ncand = len(P.trade_accept_candidates("00" * 16))
                    if parg == "on":
                        probe["on"] = True
                        print(f"  trade-state PROBE ON. Each incoming trade tries "
                              f"the NEXT of {ncand} ACCEPT+YES profiles; only a "
                              f"final 'Trade Pending' ack is saved as the winner. "
                              f"Have your main open a trade + stake a "
                              f"few cubits, repeat until you see '✅ ACCEPT "
                              f"WORKED'. Bot stakes nothing, so wrong tries cost 0.")
                    elif parg == "off":
                        probe["on"] = False
                        print("  trade-state PROBE OFF.")
                    elif parg == "reset":
                        probe["idx"] = 0
                        probe["winner"] = None
                        probe["last"] = None
                        probe["on"] = True
                        save_trade_accept()
                        print("  probe reset: index 0, winner cleared, probe ON.")
                    else:  # status
                        w = probe["winner"] or "(none yet)"
                        nx = probe["idx"] % ncand
                        nxl = P.trade_accept_candidates("00" * 16)[nx][0]
                        print(f"  probe {'ON' if probe['on'] else 'OFF'} | "
                              f"winner: {w} | next candidate #{nx + 1} '{nxl}' | "
                              f"{ncand} candidates total.")
                        print("  usage: autotrade probe on|off|reset|status")
                    continue
                if arg in ("on", "off"):
                    autotrade["on"] = (arg == "on")
                st = "ON" if autotrade["on"] else "OFF"
                win = probe["winner"] or ("PROBING" if probe["on"]
                                          else "unverified guess")
                print(f"  auto-trade deposits: {st}. When ON, the bot accepts a "
                      f"player's trade, reads the cubits they stake, confirms "
                      f"(only if its own side is empty), and credits their "
                      f"balance. {len(trades)} trade(s) in flight. State profile: "
                      f"{win}.  ('autotrade probe on' to find/verify the shape.)")
            elif line == "tradedebug" or line.startswith("tradedebug "):
                arg = line[11:].strip().lower() if line.startswith("tradedebug ") \
                    else ""
                if arg in ("on", "off"):
                    tradedebug["on"] = (arg == "on")
                st = "ON" if tradedebug["on"] else "OFF"
                print(f"  trade-frame debug: {st}. When ON, every rx frame in the "
                      f"trade range (0x30-0x40, 0xa0-0xb0, 0x11) is dumped with hex "
                      f"+ decoded fields, so we can see what the server sends back "
                      f"after each candidate accept.")
            elif line == "links":
                # the whole catalogue of realm links logged across sessions
                if not realms_log:
                    print("  no realms logged yet — enter/teleport into a realm "
                          "and its link is saved")
                else:
                    print(f"  {len(realms_log)} realm(s) logged in "
                          f"{args.realms_file}:")
                    for nm, rec in sorted(realms_log.items()):
                        here = " *" if nm == state["realm"] else ""
                        park = "" if state.get("after") != nm else "  <- park"
                        print(f"    {nm[:24]:<24} {rec.get('link','')}{here}"
                              f"{park}")
                    print("  'after <name|link>' to park at one; 'link' shows "
                          "this realm's")
            elif line == "link" or line.startswith("link "):
                arg = line[5:].strip() if line.startswith("link ") else ""
                realm = state["realm"]
                if arg.lower() in ("off", "none", "-"):
                    if realm_links.pop(realm, None) is not None:
                        save_links()
                        print(f"  override cleared — {realm} back to its built "
                              f"link {link_for(realm)}")
                    else:
                        print("  no override set for this realm")
                elif arg:
                    # hand-typed override for a realm whose link isn't its GUID
                    realm_links[realm] = arg
                    save_links()
                    print(f"  override saved for {realm}")
                else:
                    print(f"  {realm or '?'}: {link_for(realm) or '(no GUID yet)'}")
            elif line == "after" or line.startswith("after "):
                who = line[6:].strip() if line.startswith("after ") else ""
                if who in ("off", "none", "-"):
                    state["after"] = state["after_guid"] = None
                    state["after_realm"] = None
                    save_park()
                    print("  waiting realm cleared — scans stay where they are")
                elif who:
                    rg = realm_ref(who)
                    if rg:
                        state["after_guid"] = rg
                        state["after"] = None
                        save_park()
                        print(f"  after every autoscan, park in realm {rg}  "
                              f"(saved)")
                    else:
                        state["after"] = who
                        state["after_guid"] = None
                        save_park()
                        g = find_guid(who)
                        print(f"  after every autoscan, park in {who}'s realm "
                              f"(saved)"
                              + ("" if g else f"  — GUID unknown, run "
                                              f"'find {who}' first, they must "
                                              f"be online"))
                else:
                    cur = (f"realm '{state['after_realm']}' (by name)"
                           if state.get("after_realm") else
                           f"realm {state['after_guid']}" if state["after_guid"]
                           else state["after"] or "(none)")
                    print(f"  waiting realm: {cur}   usage: parkrealm <name> | "
                          f"after <link|guid|player> | after off")
            elif line.startswith("parkrealm "):
                nm = line[10:].strip()
                if nm:
                    state["after_realm"] = nm
                    state["after"] = state["after_guid"] = None
                    save_park()
                    print(f"  after every autoscan, look up realm '{nm}' by name "
                          f"and park in it (saved) — survives GUID changes")
                else:
                    print("  usage: parkrealm <realm name>   (exact name)")
            elif line == "park":
                if crawl["active"]:
                    print("  a crawl is running — 'crawl stop' first")
                elif not (state.get("after_realm") or state.get("after_guid")
                          or state.get("after")):
                    print("  no park target set — 'parkrealm <name>' or "
                          "'after <link|guid|player>' first")
                else:
                    print("  parking now ...")
                    go_to_waiting(lead="")
            elif line.startswith("joinname "):
                nm = line[9:].strip()
                if nm:
                    print(f"  searching for realm '{nm}' to join ...")
                    search_realm(nm, then_join=True)
                else:
                    print("  usage: joinname <realm name>   (search + join)")
            elif line.startswith("searchrealm ") or line.startswith("search "):
                nm = line.split(" ", 1)[1].strip()
                if not nm:
                    print("  usage: searchrealm <name>")
                else:
                    res = do_search(nm)
                    if res is None:
                        print("  no reply from the realm browser (reopened + "
                              "retried once) — likely rate-limited, wait a bit")
                    elif not res:
                        print(f"  no results for '{nm}'")
                    else:
                        print(f"  {len(res)} result(s) for '{nm}':")
                        seen = set()
                        for rn, g in res:
                            if rn.lower() in seen:
                                continue
                            seen.add(rn.lower())
                            mark = "  <- exact" if rn.lower() == nm.lower() else ""
                            print(f"    {rn[:34]:<34} {g}{mark}")
                        print("  'joinname <name>' or 'parkrealm <name>'")
            elif line.startswith("joinrealm "):
                ref = realm_ref(line[10:])
                if ref:
                    print(f"  joining realm {ref[:8]}… (0x00d3 + handoff) ...")
                    queue_move("join", ref, f"joinrealm {ref[:8]}…")
                else:
                    print("  usage: joinrealm <castles.cc realm link | 32-hex "
                          "GUID>")
            elif line == "crawl" or line.startswith("crawl "):
                arg = line[5:].strip()
                if arg in ("status", "eta", "progress", "how long", "howlong"):
                    def _hms(s):
                        s = int(max(0, s))
                        h, s = divmod(s, 3600)
                        m, s = divmod(s, 60)
                        return (f"{h}h{m:02d}m" if h
                                else (f"{m}m{s:02d}s" if m else f"{s}s"))
                    staged = len(crawl.get("pending_targets") or [])
                    queued = len(hollow["q"]) if hollow.get("auto") else 0
                    if not crawl["active"]:
                        if staged:
                            print(f"  crawl: idle — {staged} realm(s) staged, "
                                  f"'crawl go' to start")
                        elif queued:
                            print(f"  crawl: idle — {queued} Hollowarp realm(s) "
                                  f"queued to scan")
                        else:
                            print("  crawl: nothing running or staged")
                    else:
                        i = crawl.get("i", 0)
                        total = crawl.get("total", 0)
                        done = crawl.get("done", 0)
                        elapsed = time.monotonic() - crawl.get("run_started",
                                                               time.monotonic())
                        # Realms left = rest of this batch + realms still staged
                        # for later batches. The Hollowarp queue is scanned after
                        # the crawl, so it's called out separately, not in the ETA.
                        remaining = max(0, total - done) + staged
                        print(f"  crawl: on realm {i}/{total} this batch"
                              + (f", {staged} more staged" if staged else "")
                              + f" — {elapsed and _hms(elapsed) or '0s'} elapsed")
                        if done > 0:
                            per = elapsed / done
                            print(f"    ~{_hms(per)}/realm so far → ETA "
                                  f"~{_hms(remaining * per)} for {remaining} "
                                  f"realm(s) left")
                        else:
                            print(f"    still timing the first realm — pacing "
                                  f"floor is {args.crawl_delay:.0f}s/realm, so "
                                  f"≳{_hms(remaining * args.crawl_delay)} for "
                                  f"{remaining} left")
                        if queued:
                            print(f"    (+{queued} Hollowarp realm(s) queued, "
                                  f"scanned after the crawl — not in the ETA)")
                elif arg in ("stop", "off"):
                    crawl["pending_targets"] = None
                    if crawl["active"]:
                        crawl["stop"] = True
                        print("  crawl: stopping after the current realm ...")
                    else:
                        print("  crawl cancelled (nothing running)")
                elif arg == "go" or arg.startswith("go "):
                    # 'crawl go' does all staged realms; 'crawl go N' does only
                    # the first N and leaves the rest staged for another 'go'.
                    rest_arg = arg[2:].strip()
                    n = int(rest_arg) if rest_arg.isdigit() else None
                    if rest_arg and n is None:
                        print("  usage: crawl go   (all staged)   or   "
                              "crawl go <N>   (just the first N)")
                    else:
                        start_staged_crawl(n)
                elif not arg or arg == "auto" or arg.startswith("auto "):
                    # no term = find realms on its own (auto-discovery)
                    if crawl["active"]:
                        print("  a crawl is running — 'crawl stop' to end it")
                    else:
                        mx = args.crawl_max
                        rest = arg[4:].strip() if arg.startswith("auto") else ""
                        if rest.isdigit():
                            mx = int(rest)
                        threading.Thread(target=discover_and_stage,
                                         args=(mx, DISCOVERY_SEEDS),
                                         daemon=True).start()
                elif crawl["active"]:
                    print("  a crawl is running — 'crawl stop' to end it")
                else:
                    parts = arg.rsplit(" ", 1)
                    term, mx = arg, args.crawl_max
                    if len(parts) == 2 and parts[1].isdigit():
                        term, mx = parts[0], int(parts[1])
                    results = do_search(term)
                    if results is not None:
                        seen, targets = set(), []
                        for nm, g in results:
                            if g not in seen:
                                seen.add(g)
                                targets.append((g, nm))
                        targets = targets[:mx]
                        if not targets:
                            print(f"  no realms matched '{term}'")
                        else:
                            crawl_prepare(targets, f"search '{term}'")
                    else:
                        print(f"  no reply from the realm browser for '{term}' "
                              f"(reopened + retried once). The server may be "
                              f"rate-limiting searches — wait a bit and retry.")
            elif line.startswith("crawlfile "):
                path = line[10:].strip().strip('"')
                if crawl["active"]:
                    print("  a crawl is running — 'crawl stop' first")
                elif not path:
                    print("  usage: crawlfile <path>   (one realm NAME per "
                          "line; a realm link or 32-hex GUID also works; "
                          "# comments ok)")
                else:
                    # Look for the file as given (relative to wherever the bot
                    # was launched) AND next to this script, so 'crawlfile
                    # mycrawl.txt' works no matter the current directory.
                    here = _APP_DIR
                    tries = [path, os.path.join(here, path)]
                    found = next((p for p in tries if os.path.isfile(p)), None)
                    try:
                        if not found:
                            raise FileNotFoundError(path)
                        raw = open(found, encoding="utf-8").read().splitlines()
                    except OSError:
                        raw = None
                        print(f"  can't find '{path}' — looked in {tries[0]} and "
                              f"{tries[1]}. Put the file in {here} or give a full "
                              f"path.")
                    if raw is not None:
                        # Two kinds of line: a realm link/GUID (resolved right
                        # here) or a realm NAME (resolved via the browser in a
                        # thread, since that needs live search queries).
                        seen, direct, names = set(), [], []
                        for ln in raw:
                            ln = ln.strip()
                            if not ln or ln.startswith("#"):
                                continue
                            ref_part, name = ln, ""
                            for sep in (",", "\t"):
                                if sep in ln:
                                    ref_part, name = ln.split(sep, 1)
                                    break
                            g = realm_ref(ref_part.strip())
                            if g:
                                if g not in seen:
                                    seen.add(g)
                                    direct.append((g, name.strip() or g[:8]))
                            else:
                                names.append(ln)      # whole line is a realm name
                        if not direct and not names:
                            print(f"  no realm names, links, or GUIDs in {path}")
                        elif not names:
                            crawl_prepare(direct[:args.crawl_max], path)
                        else:
                            print(f"  resolving {len(names)} realm name(s) via "
                                  f"the browser — nothing connects until "
                                  f"'crawl go' ...")
                            threading.Thread(
                                target=resolve_file_crawl,
                                args=(direct, names, path),
                                daemon=True).start()
            elif line in ("watchlist", "watched"):
                if not watchlist:
                    print("  rescan list is empty — stand in a realm and type "
                          "'watch', or 'watch <link|guid>'")
                else:
                    print(f"  rescan list ({len(watchlist)} realm(s)) "
                          f"— {watchlist_path}:")
                    for g, r in watchlist.items():
                        print(f"    {(r.get('name') or '?')[:32]:<32} "
                              f"{g[:8]}…  {r.get('link') or ''}")
            elif line.startswith("unwatch"):
                ref = line[7:].strip().strip('"')
                if not ref:
                    print("  usage: unwatch <name|link|guid>")
                else:
                    g = realm_ref(ref)
                    target = g if (g and g in watchlist) else None
                    if not target:
                        for gg, r in watchlist.items():
                            if (r.get("name") or "").lower() == ref.lower():
                                target = gg
                                break
                    if target:
                        nm = watchlist[target].get("name", target[:8])
                        del watchlist[target]
                        save_watchlist()
                        print(f"  removed '{nm}' — {len(watchlist)} left")
                    else:
                        print(f"  '{ref}' isn't on the rescan list")
            elif line == "watch" or line.startswith("watch "):
                ref = line[6:].strip().strip('"') if line != "watch" else ""
                if not ref:
                    # bookmark the realm we're standing in right now
                    realm, g = state["realm"], reg["guid"]
                    if not g:
                        print("  no realm GUID yet — enter a realm first, or use "
                              "'watch <link|guid>'")
                    elif add_watch(g, realm, state["realm_owner"]):
                        print(f"  watching '{realm or g[:8]}' ({g[:8]}…) — "
                              f"{len(watchlist)} realm(s) on the rescan list")
                else:
                    g = realm_ref(ref)
                    if not g:
                        print(f"  '{ref}' isn't a realm link/GUID — nothing added")
                    else:
                        nm = next((n for n, gg in realm_guids.items()
                                   if gg == g), None)
                        if add_watch(g, nm):
                            print(f"  watching {nm or (g[:8] + '…')} — "
                                  f"{len(watchlist)} realm(s) on the rescan list")
            elif line == "rescan" or line.startswith("rescan "):
                arg = line[7:].strip() if line != "rescan" else ""
                # 'rescan fast [N]' skips the up-front batch resolution and
                # starts crawling immediately: each realm's name is resolved to
                # its CURRENT GUID just before that realm is joined (join -> scan
                # -> next), instead of resolving all 15 names first. No long
                # wait before anything happens, and GUIDs are always fresh at
                # join time so re-hosted realms still hand off. Auto-prune is off
                # (it keys off the up-front resolve pass). Aliases:
                # fast/skip/raw/now.
                toks = arg.split()
                fast = bool(toks) and toks[0].lower() in (
                    "fast", "skip", "raw", "now")
                if fast:
                    toks = toks[1:]
                capstr = toks[0] if toks else ""
                if crawl["active"] or crawl.get("resolving"):
                    print("  a crawl/resolve is already running — 'crawl stop' "
                          "first")
                elif not watchlist:
                    print("  rescan list is empty — 'watch' to add realms first")
                else:
                    cap = int(capstr) if capstr.isdigit() else 0  # 0 = whole list
                    scope = (f"first {cap}" if cap else "all")
                    if fast:
                        # Stage every watchlist entry as (saved GUID, name) with
                        # an empty resolve list, so resolve_file_crawl does zero
                        # up-front lookups and starts the crawl right away. The
                        # crawl itself then resolves each name to its current
                        # GUID just before joining it (resolve_each=True).
                        seen, direct = set(), []
                        for g, r in watchlist.items():
                            nm = r.get("name")
                            if g and g not in seen:
                                seen.add(g)
                                direct.append((g, nm or g[:8]))
                        print(f"  rescan (fast): no up-front resolution — "
                              f"crawling {scope} of {len(direct)} watchlisted "
                              f"realm(s), resolving each realm's name to its "
                              f"current GUID just before it's joined. Starts "
                              f"immediately; auto-prune is off.")
                        threading.Thread(
                            target=resolve_file_crawl,
                            args=(direct, [], "rescan list"),
                            kwargs={"cap": cap, "prune": False,
                                    "auto_start": True,
                                    "batch": args.rescan_batch,
                                    "resolve_each": True},
                            daemon=True).start()
                    else:
                        # A realm's GUID changes every time it's re-hosted, so
                        # the GUIDs saved on the watchlist go stale and a direct
                        # join gets no handoff. Resolve each realm by NAME to its
                        # CURRENT GUID via the browser first (same path
                        # 'crawlfile' uses); entries with no saved name fall back
                        # to their stored GUID.
                        seen, direct, names = set(), [], []
                        for g, r in watchlist.items():
                            nm = r.get("name")
                            if nm:
                                names.append(nm)
                            elif g and g not in seen:
                                seen.add(g)
                                direct.append((g, g[:8]))
                        print(f"  rescan: resolving {scope} of {len(names)} "
                              f"watchlisted realm(s) by name to their current "
                              f"GUIDs (saved GUIDs go stale on re-host) — paced "
                              f"to avoid throttling; the crawl starts "
                              f"automatically when resolution finishes ...")
                        threading.Thread(
                            target=resolve_file_crawl,
                            args=(direct, names, "rescan list"),
                            kwargs={"cap": cap, "prune": True,
                                    "auto_start": True,
                                    "batch": args.rescan_batch},
                            daemon=True).start()
            elif line in ("hwarp", "hwarp on", "hwarp off", "autowarp",
                          "autowarp on", "autowarp off"):
                if line.endswith("off"):
                    hollow["auto"] = False
                    print("  auto-Hollowarp OFF")
                else:
                    hollow["auto"] = True
                    print("  auto-Hollowarp ON — every Hollowarp broadcast will "
                          "be joined, scanned, and watchlisted if it has vends.")
                    print(f"  {len(hollow['seen'])} realm(s) already handled this "
                          f"session; {len(hollow['q'])} queued. 'hwarp off' stops.")
                    if hollow["q"] and not hollow["driver"]:
                        threading.Thread(target=warp_driver, daemon=True).start()
            elif line.startswith("hwarp cooldown"):
                arg = line[len("hwarp cooldown"):].strip()
                if arg:
                    try:
                        hollow["cooldown"] = max(0.0, float(arg))
                    except ValueError:
                        print("  usage: hwarp cooldown <seconds>")
                        continue
                print(f"  Hollawarp per-realm cooldown = "
                      f"{hollow['cooldown']:.0f}s (same realm won't be re-joined "
                      f"until it lapses).")
            elif line in ("wander", "wander on", "wander off",
                          "wander yes", "wander no"):
                if line.endswith(("off", "no")):
                    wander["on"] = False
                    wander["active"] = False
                    print("  hide OFF — the avatar stays put on any scan-join "
                          "(no off-map hide, no idle glancing).")
                else:
                    wander["on"] = True
                    print("  hide ON — on ANY scan-join (holla, guid, "
                          "joinname/joinrealm-scan, crawl) the avatar jumps to "
                          f"block ({wander['offmap_x']},{wander['offmap_y']},"
                          f"{wander['offmap_z']}), off the map. 'offmap <x> <y> "
                          "<z>' moves that spot; 'wander off' disables it.")
            elif line == "offmap" or line.startswith("offmap "):
                arg = line[6:].split()
                if len(arg) == 3:
                    try:
                        wander["offmap_x"] = int(arg[0])
                        wander["offmap_y"] = int(arg[1])
                        wander["offmap_z"] = int(arg[2])
                    except ValueError:
                        print("  usage: offmap <x block> <y block> <z block>")
                        continue
                elif arg:
                    print("  usage: offmap <x block> <y block> <z block>")
                    continue
                print(f"  off-map hide spot = block ({wander['offmap_x']},"
                      f"{wander['offmap_y']},{wander['offmap_z']}) "
                      f"(on any scan-join; 'wander off' to disable).")
            elif line in ("freeze", "unfreeze", "freeze on", "freeze off"):
                on = not line.endswith(("unfreeze", "off"))
                movelock["frozen"] = on
                if on:
                    wander["active"] = False
                print("  movement " + ("FROZEN — the bot won't move at all "
                      "(no wander/idle/jump/walk) until 'unfreeze'." if on
                      else "UNFROZEN — autonomous movement allowed again."))
            elif line == "quiz" or line.startswith("quiz "):
                qb = quizbot
                arg2 = line[5:].strip() if line != "quiz" else ""
                low2 = arg2.lower()
                if qb["brain"] is None:
                    print("  quiz brain unavailable (cc_quiz.py failed to "
                          "import) — nothing to run.")
                elif arg2 == "" or low2 == "status":
                    b = qb["brain"]
                    print(f"  QUIZ bot: {'ON' if qb['on'] else 'OFF'} | "
                          f"host: {qb['host'] or '(none set)'} | "
                          f"gate: {'ON' if qb['gate'] else 'OFF'} | "
                          f"min-conf: {qb['min_conf']:.2f}")
                    print(f"    brain: {len(b)} facts "
                          f"({len(b.learned)} learned) | "
                          f"answered this run: {qb['answered']} | "
                          f"learned this run: {qb['learned']}")
                    if qb["pending"]:
                        print(f"    HOLDING answer '{qb['pending']['a']}' — "
                              f"waiting for realm unmute / go-ahead.")
                    rnd = qb["round"]
                    if rnd and rnd.get("q"):
                        state2 = ("collecting %d crowd answer(s)"
                                  % len(rnd["answers"])) if rnd.get("collecting") \
                                 else "awaiting unmute"
                        print(f"    round: {rnd['q']!r} — {state2}")
                    print(f"    crowd-learn: on unmute I watch the crowd and learn "
                          f"the answer >= {qb['min_agree']} players agree on.")
                    if not qb["host"]:
                        print("    set the question-giver with: quiz host <name>")
                elif low2 == "on":
                    if not qb["host"]:
                        print("  set a host first: quiz host <name>  (the bot only "
                              "reacts to that one person).")
                    qb["on"] = True
                    own = prof["identity"]["display_name"] or "me"
                    print(f"  QUIZ bot ON. I watch {qb['host'] or '(no host yet)'} "
                          f"in public chat, answer INSTANTLY from my offline brain, "
                          f"and — with gate {'ON' if qb['gate'] else 'OFF'} — "
                          + ("raise my hand ('question'), then HOLD the answer "
                             "until the realm is UNMUTED ('This realm has been "
                             "unmuted!') — or the host says a go-ahead phrase."
                             if qb["gate"] else
                             "reply the moment the host asks."))
                elif low2 == "off":
                    qb["on"] = False
                    qb["pending"] = None
                    print("  QUIZ bot OFF.")
                elif low2.startswith("host"):
                    nm = arg2[4:].strip().lstrip("@")
                    if not nm:
                        print(f"  host is {qb['host'] or '(none set)'}. "
                              f"Set with: quiz host <name>")
                    else:
                        qb["host"] = nm.lower()
                        print(f"  quiz host set to '{nm}'. Only questions from "
                              f"'{nm}' will be answered.")
                elif low2 in ("gate on", "gate off"):
                    qb["gate"] = low2.endswith("on")
                    print(f"  turn-taking gate {'ON' if qb['gate'] else 'OFF'} — "
                          + ("HOLD the answer until the realm unmutes."
                             if qb["gate"] else "answer immediately."))
                elif low2 in ("raise on", "raise off"):
                    qb["raise_hand"] = low2.endswith("on")
                    print(f"  hand-raise {'ON' if qb['raise_hand'] else 'OFF'} — "
                          + (f"type '{qb['raise_word']}' when a question is seen."
                             if qb["raise_hand"] else
                             "stay silent until unmute, then say only the answer."))
                elif low2 in ("learn on", "learn off"):
                    qb["auto_learn"] = low2.endswith("on")
                    print(f"  auto-learn {'ON' if qb['auto_learn'] else 'OFF'} "
                          f"(learn the answer when the host reveals it).")
                elif low2.startswith("conf"):
                    try:
                        qb["min_conf"] = max(0.0, min(1.0, float(arg2[4:].strip())))
                        print(f"  min confidence set to {qb['min_conf']:.2f}")
                    except ValueError:
                        print("  usage: quiz conf 0.9   (0..1; fuzzy answers must "
                              "clear this to be spoken)")
                elif low2.startswith("test "):
                    q = arg2[5:].strip()
                    r = qb["brain"].answer(q)
                    if r["source"]:
                        extra = (f"  (~{r.get('matched')})" if r.get("matched")
                                 else "")
                        print(f"  would answer [{r['source']}, "
                              f"conf {r['confidence']:.2f}]: {r['answer']}{extra}")
                        if r["confidence"] < qb["min_conf"]:
                            print(f"    ...but below min-conf {qb['min_conf']:.2f}, "
                                  f"so it would STAY SILENT.")
                    else:
                        print("  no offline answer — would stay silent.")
                elif low2.startswith("learn ") and ("=" in arg2 or "|" in arg2):
                    body = arg2[6:]
                    sep = "=" if "=" in body else "|"
                    q, a = (body.split(sep, 1) + [""])[:2]
                    if qb["brain"].learn(q.strip(), a.strip()):
                        print(f"  learned: {q.strip()!r} -> {a.strip()!r} (saved)")
                    else:
                        print("  nothing learned (need: quiz learn <question> = "
                              "<answer>)")
                elif low2.startswith("unlearn "):
                    q = arg2[8:].strip()
                    if qb["brain"].unlearn(q):
                        print(f"  forgot the learned answer for {q!r} (saved). "
                              f"Re-teach with: quiz learn {q} = <answer>")
                    else:
                        print(f"  nothing learned for {q!r} to forget.")
                elif low2.startswith("agree"):
                    try:
                        qb["min_agree"] = max(1, int(arg2[5:].strip()))
                        print(f"  crowd min-agree set to {qb['min_agree']} "
                              f"(that many players must give the same answer).")
                    except ValueError:
                        print("  usage: quiz agree 3")
                elif low2.startswith("margin"):
                    try:
                        qb["min_margin"] = max(0, int(arg2[6:].strip()))
                        print(f"  crowd min-margin set to {qb['min_margin']} "
                              f"(top answer must beat runner-up by this much).")
                    except ValueError:
                        print("  usage: quiz margin 2")
                elif low2 in ("say", "go", "release"):
                    if qb["pending"]:
                        ans = qb["pending"]["a"]
                        qb["pending"] = None
                        qb["answered"] += 1
                        pub_say(ans)
                        print(f"  released held answer: {ans}")
                    else:
                        print("  nothing held right now.")
                elif low2 in ("forget", "clear"):
                    qb["pending"] = None
                    qb["last_q"] = None
                    print("  cleared any held answer / last question.")
                else:
                    print("  quiz commands: quiz [status] | quiz on|off | "
                          "quiz host <name> | quiz gate on|off | quiz learn on|off")
                    print("                 quiz conf <0..1> | quiz test <question> "
                          "| quiz learn <q> = <a> | quiz say | quiz forget")
            elif line in ("pricebot", "pricebot on", "pricebot off",
                          "prices on", "prices off"):
                if line.endswith("off"):
                    pricebot["on"] = False
                    print("  price bot OFF")
                else:
                    pricebot["on"] = True
                    own = prof["identity"]["display_name"]
                    print(f"  price bot ON — I'll reply in chat when someone "
                          f"addresses me by name and asks for a price, e.g. "
                          f"'{own} price of <item>', 'pc <item>', 'how much is "
                          f"<item>'.")
                    print(f"    anti-spam: {pricebot['cooldown']:.0f}s global "
                          f"cooldown, {pricebot['per_user']:.0f}s per-player "
                          f"cooldown; all replies spaced {args.chat_gap:.1f}s "
                          f"apart (--chat-gap) after a {args.chat_delay:.1f}s "
                          f"delay (--chat-delay).")
                    print(f"    keyword commands also live: '{own} help', "
                          f"'{own} realm [name]', and a bare '{own}' gets a "
                          f"greeting. Approved-only: summon, scan realm "
                          f"('approved' lists them).")
                    if not pricebot["map"] or \
                            time.time() - pricebot["fetched"] > 900:
                        print("  fetching latest prices ...")
                        threading.Thread(target=load_prices, daemon=True).start()
                    else:
                        print(f"  ({len(pricebot['map'])} prices loaded)")
            elif line == "control" or line.startswith("control "):
                arg2 = line[8:].strip() if line != "control" else ""
                if arg2 in ("off", "stop"):
                    print("  console stopped" if stop_control_server()
                          else "  console isn't running")
                elif webctl["httpd"]:
                    print(f"  console already on http://{webctl['host']}:"
                          f"{webctl['port']}/   ('control off' to stop)")
                else:
                    port = int(arg2) if arg2.isdigit() else (args.control_port
                                                             or 8777)
                    start_control_server(port, args.control_host,
                                         args.control_token)
            elif line == "public" or line.startswith("public "):
                arg2 = line[7:].strip() if line != "public" else ""
                if arg2 in ("off", "stop"):
                    print("  public market site stopped" if stop_public_server()
                          else "  public market site isn't running")
                elif pubweb["httpd"]:
                    print(f"  public market site already on "
                          f"http://{pubweb['host']}:{pubweb['port']}/   "
                          f"('public off' to stop)")
                else:
                    port = int(arg2) if arg2.isdigit() else (args.public_port
                                                             or 8778)
                    start_public_server(port, args.public_host)
            elif line in ("summon", "summon on", "summon off"):
                if line == "summon off":
                    summon["on"] = False
                    print("  summon OFF")
                else:
                    summon["on"] = True
                    own = prof["identity"]["display_name"]
                    print(f"  summon ON — anyone in my realm can type 'summon "
                          f"{own}' in chat and I'll teleport to them (same realm "
                          f"only). 'summon off' to stop.")
            elif line in ("scanbot", "scanbot on", "scanbot off"):
                if line == "scanbot off":
                    scanbot["on"] = False
                    print("  scan-on-command OFF")
                else:
                    scanbot["on"] = True
                    own = prof["identity"]["display_name"]
                    print(f"  scan-on-command ON — anyone in my realm can type "
                          f"'{own} scan realm <exact name>' in chat and I'll "
                          f"join that realm and scan it into the market DB "
                          f"(same-realm requester only, 30s cooldown). "
                          f"'scanbot off' to stop.")
            elif line in ("commands on", "commands off", "chatcommands",
                          "chatcommands on", "chatcommands off"):
                if line.endswith("off"):
                    cmdbot["on"] = False
                    print("  keyword chat commands OFF")
                else:
                    cmdbot["on"] = True
                    own = prof["identity"]["display_name"] or "me"
                    pub = [c["usage"] for c in CHAT_COMMANDS
                           if not c["admin"] and c["usage"]]
                    print(f"  keyword chat commands ON — say '{own} <cmd>': "
                          + ", ".join(pub) + f"; a bare '{own}' greets. "
                          f"'commands off' to stop.")
            elif line in ("whisper", "whisper on", "whisper off",
                          "whisperbot", "whisperbot on", "whisperbot off"):
                if line.endswith("off"):
                    whisperbot["on"] = False
                    print("  whisper bot OFF — not answering private messages.")
                else:
                    whisperbot["on"] = True
                    mode = ("(also still answering public chat)"
                            if whisperbot["public"] else
                            "(this REPLACES public chat — public commands ignored)")
                    print(f"  whisper bot ON — a whisper is treated like an "
                          f"addressed command and answered privately by whispering "
                          f"back {mode}. 'whisper off' to stop, 'public on' to also "
                          f"answer public chat.")
            elif line == "translate" or line == "translator" \
                    or line.startswith("translate ") \
                    or line.startswith("translator "):
                # Live chat translator (Stage 27). Detects non-English chat and
                # re-posts an English version publicly or by whisper. Backends
                # (builtin/libre/deepl/google) live in cc_translate; API keys come
                # from the environment. Settings persist to translate.json.
                if line in ("translate", "translator"):
                    arg = ""
                else:
                    arg = line.split(None, 1)[1].strip()
                sub_parts = arg.split(None, 1)
                sub = sub_parts[0].lower() if sub_parts else ""
                rest = sub_parts[1] if len(sub_parts) > 1 else ""
                if sub == "test":
                    # Offline smoke test: translate the given text right now and
                    # print the result (no game / no chat send needed).
                    if cc_translate is None:
                        print("  translator module not installed (cc_translate.py).")
                    elif not rest:
                        print("  usage: translate test <foreign text>")
                    elif translatebot.get("engine") is None:
                        print(f"  provider '{translatebot['provider']}' not ready "
                              "— 'translate provider <name>' / check keys.")
                    else:
                        try:
                            r = translatebot["engine"].translate(rest)
                            if r is None:
                                print("  -> looks English / nothing to translate.")
                            else:
                                print(f"  -> said in {r.lang_name} ({r.lang_code}):"
                                      f" {r.text}")
                        except Exception as e:
                            print(f"  translation FAILED: {type(e).__name__}: {e}")
                elif sub == "models":
                    # List the LOCAL (Argos) language models installed on disk.
                    if cc_translate is None or not cc_translate.argos_available():
                        print("  local Argos engine not installed "
                              "(pip install argostranslate langdetect).")
                    else:
                        eng = translatebot.get("engine")
                        codes = eng.installed_source_codes() \
                            if isinstance(eng, cc_translate.ArgosTranslator) \
                            else set()
                        if not codes:
                            # Fall back to a direct query if the engine isn't Argos.
                            try:
                                import argostranslate.translate as _at
                                langs = {l.code for l in
                                         _at.get_installed_languages()}
                                codes = langs - {"en"} if "en" in langs else set()
                            except Exception:
                                codes = set()
                        if codes:
                            named = ", ".join(f"{cc_translate.language_name(c)}"
                                              f" ({c})" for c in sorted(codes))
                            print(f"  local models installed ({len(codes)}): "
                                  f"{named}")
                        else:
                            print("  no local language models installed yet — "
                                  "'translate install <code>' (e.g. es, fr, de, "
                                  "pt, ja, ru) or they auto-download on first use.")
                elif sub == "install":
                    # Download+install a LOCAL model (code->en). One-time network;
                    # offline forever after. e.g. 'translate install fr'.
                    if cc_translate is None or not cc_translate.argos_available():
                        print("  local Argos engine not installed "
                              "(pip install argostranslate langdetect).")
                    elif not rest:
                        print("  usage: translate install <code>  (es fr de pt ja "
                              "ru zh ko ar ...). 'all6' installs the common six.")
                    else:
                        if rest.strip().lower() in ("all6", "common"):
                            want = ["es", "fr", "de", "pt", "ja", "ru"]
                        else:
                            # accept one or MANY space-separated codes
                            want = [tok.split("-")[0]
                                    for tok in rest.lower().split()]
                        for code in want:
                            try:
                                print(f"  installing {cc_translate.language_name(code)}"
                                      f" ({code}) -> English … (one-time download)")
                                cc_translate.install_argos_model(code, "en")
                                print(f"  installed {code}.")
                            except Exception as e:
                                print(f"  FAILED {code}: {e}")
                        # Rebuild so the engine sees the new models immediately.
                        _build_translator()
                else:
                    print("  " + translate_control(sub, rest))
            elif line in ("public", "public on", "public off"):
                if line == "public off":
                    whisperbot["public"] = False
                    print("  public chat commands OFF — serving whispers only.")
                else:
                    whisperbot["public"] = True
                    print("  public chat commands ON — answering both public chat "
                          "and whispers.")
            elif line.startswith("whisper "):
                # manual test: whisper <name> <message>
                rest = line[len("whisper "):].strip()
                parts = rest.split(None, 1)
                if len(parts) < 2:
                    print("  usage: whisper <name> <message>")
                else:
                    name, msg = parts[0], parts[1]
                    want = _alnum(name)
                    guid = friends.get(name)
                    if not guid:
                        guid = next((g for g, nm in players.items()
                                     if _alnum(nm) == want), None)
                    if not guid:
                        guid = next((g for nm, g in friends.items()
                                     if _alnum(nm) == want), None)
                    if not guid:
                        print(f"  don't know a GUID for '{name}' yet (not a friend "
                              f"and not seen in-realm) — can't pick them in the "
                              f"whisper menu.")
                    else:
                        whisper_say(guid, msg)
                        print(f"  queued whisper to {name}.")
            elif line == "approved" or line == "approve" or line == "unapprove":
                if approved:
                    print(f"  approved users ({len(approved)}): "
                          + ", ".join(sorted(approved)))
                else:
                    print("  no approved users yet — 'approve <username>' adds "
                          "one. Public commands (price, help, realm) stay open "
                          "to everyone; summon and scan realm are approved-only.")
            elif line.startswith("approve "):
                nm = line[8:].strip().lstrip("@").lower()
                if not nm:
                    print("  usage: approve <username>")
                elif nm in approved:
                    print(f"  {nm} is already approved")
                else:
                    approved.add(nm)
                    save_approved()
                    print(f"  approved {nm} — they can now use privileged chat "
                          f"commands (summon, scan realm)")
            elif line.startswith("unapprove "):
                nm = line[10:].strip().lstrip("@").lower()
                if nm in approved:
                    approved.discard(nm)
                    save_approved()
                    print(f"  removed {nm} from the approved list")
                else:
                    print(f"  {nm} isn't on the approved list")
            elif line == "vends" or line.startswith("vends "):
                arg2 = line[6:].strip().strip('"') if line != "vends" else ""
                if not vends:
                    print("  vending catalogue is empty — scan or rescan a realm "
                          "first (writes vends.json)")
                elif arg2:
                    match = next((r for r in vends
                                  if r.lower() == arg2.lower()), None)
                    if not match:
                        print(f"  '{arg2}' not in the catalogue — 'vends' lists "
                              f"the realms")
                    else:
                        e = vends[match]
                        print(f"  {match} — {len(e.get('machines', []))} "
                              f"machine(s), updated {e.get('updated', '?')}:")
                        for m in e.get("machines", []):
                            item = m.get("item") or "(item not named)"
                            qty = f"{m.get('qty')} x " if m.get("qty") else ""
                            print(f"    {qty}{item} "
                                  f"for {m.get('price')} {m.get('currency') or ''}")
                else:
                    total = sum(len(e.get("machines", []))
                                for e in vends.values())
                    print(f"  vending catalogue: {len(vends)} realm(s), "
                          f"{total} machine(s) — {vends_path}")
                    for r, e in sorted(vends.items()):
                        print(f"    {r[:36]:<36} "
                              f"{len(e.get('machines', [])):>3} machine(s)  "
                              f"updated {e.get('updated', '?')}")
            elif line == "market" or line.startswith("market "):
                # cross-realm item search over the whole catalogue, cheapest
                # first, with realm links — plus a shareable export. ('find' is
                # already the player-GUID lookup, so this is 'market'.)
                arg2 = line[7:].strip() if line != "market" else ""
                if not vends:
                    print("  catalogue empty — scan/crawl some realms first "
                          "(writes vends.json)")
                elif arg2.split(" ")[0].lower() == "export":
                    # market export [path]  — whole catalogue, or add a term:
                    #   market export prices.csv
                    #   market export halo halo.html   (search 'halo' -> HTML)
                    rest = arg2[6:].strip()
                    parts = rest.rsplit(" ", 1)
                    if len(parts) == 2 and ("." in parts[1]):
                        term, path = parts[0].strip().strip('"'), parts[1]
                    else:
                        term, path = "", (rest.strip().strip('"') or "")
                    if not path:
                        path = f"market-{time.strftime('%Y%m%d-%H%M%S')}.html"
                    try:
                        n = export_market(path, term or None)
                        kind = "CSV" if path.lower().endswith(".csv") else \
                            "browsable HTML"
                        print(f"  exported {n} listing(s) -> {path}  ({kind}"
                              + (f", search '{term}'" if term else "") + ")")
                    except Exception as e:
                        print(f"  export failed: {e}")
                elif arg2.split(" ")[0].lower() == "publish":
                    # market publish [dir] — write the static price site into a
                    # folder a file server hosts. Only derived files are
                    # written (see publish_market), never profiles or captures.
                    outdir = (arg2[7:].strip().strip('"')
                              or args.publish_dir or "published")
                    try:
                        files = publish_market(outdir)
                    except Exception as e:
                        print(f"  publish failed: {e}")
                    else:
                        print(f"  published {len(files)} file(s) -> {outdir}")
                        for n, sz in files:
                            print(f"    {n:<16} {sz:>10,} bytes")
                        print("  safe to host: every file is derived from the "
                              "catalogue — no tokens, keys or account ids")
                elif not arg2:
                    total = sum(len(e.get("machines", []))
                                for e in vends.values())
                    print(f"  market: {total} machine(s) across {len(vends)} "
                          f"realm(s). Usage:")
                    print("    market <item>            search all realms, "
                          "cheapest first")
                    print("    market export [file]     whole catalogue -> "
                          ".html (browsable) or .csv")
                    print("    market export <item> <file>   export just that "
                          "search")
                    print("    market publish [dir]     static site -> a folder "
                          "your file server hosts")
                else:
                    term = arg2.strip('"')
                    rows = market_rows(term)
                    if not rows:
                        print(f"  no machine sells '{term}' in the "
                              f"{len(vends)} realm(s) scanned")
                    else:
                        cap = 30
                        cheapest = rows[0]
                        print(f"  '{term}': {len(rows)} listing(s), cheapest "
                              f"first (best: {cheapest['price']} "
                              f"{cheapest['currency']} in {cheapest['realm']}):")
                        for r in rows[:cap]:
                            qty = f"{r['qty']}x " if r.get("qty") else ""
                            link = f"  {r['link']}" if r.get("link") else ""
                            print(f"    {str(r['price']):>7} {r['currency']:<6} "
                                  f"{qty}{r['item'][:30]:<30} "
                                  f"@ {r['realm'][:24]}{link}")
                        if len(rows) > cap:
                            print(f"    … and {len(rows) - cap} more — "
                                  f"'market export {term} {term}.html' for all")
            elif line == "dbstats":
                if mdb is None:
                    print("  market history DB is not open (--no-market-db, or "
                          "it failed to load)")
                else:
                    s = mdb.stats()
                    print(f"  market history DB — {s['db_path']}")
                    print(f"    realms {s['realms']}   machines "
                          f"{s['machines']}   current listings "
                          f"{s['current_offers']}")
                    print(f"    observations {s['observations']}   events "
                          f"{s['events']}")
                    print(f"    scans {s['scans']} ({s['failed_scans']} "
                          f"failed/incomplete)")
                    print(f"    items {s['items']}   aliases {s['aliases']}   "
                          f"watchlist {s['watchlist']}")
                    print(f"    db size {s['db_size_bytes']:,} bytes")
                    print(f"    observations from {s['oldest_observation']} "
                          f"to {s['newest_observation']}")
            elif line == "history" or line.startswith("history "):
                arg = line[8:].strip() if line.startswith("history ") else ""
                if mdb is None:
                    print("  market history DB is not open")
                elif not arg:
                    print("  usage: history <item> [days]")
                else:
                    parts = arg.rsplit(" ", 1)
                    days = None
                    term = arg.strip('"')
                    if len(parts) == 2 and parts[1].isdigit():
                        term, days = parts[0].strip().strip('"'), int(parts[1])
                    _print_history(term, days)
            elif line == "changes" or line.startswith("changes "):
                arg = line[8:].strip() if line.startswith("changes ") else ""
                hours = int(arg) if arg.isdigit() else 24
                _print_changes(hours)
            elif line == "deals" or line.startswith("deals "):
                arg = line[6:].strip() if line.startswith("deals ") else ""
                if mdb is None:
                    print("  market history DB is not open")
                elif not arg:
                    print("  usage: deals <item> [max-price]")
                else:
                    parts = arg.rsplit(" ", 1)
                    max_price, term = None, arg.strip('"')
                    if len(parts) == 2 and parts[1].replace(",", "").isdigit():
                        term = parts[0].strip().strip('"')
                        max_price = int(parts[1].replace(",", ""))
                    _print_deals(term, max_price)
            elif line == "scans" or line.startswith("scans "):
                arg = line[6:].strip() if line.startswith("scans ") else ""
                n = int(arg) if arg.isdigit() else 10
                _print_scans(n)
            elif line == "scanstatus":
                _print_scanstatus()
            elif line == "stale" or line.startswith("stale "):
                arg = line[6:].strip() if line.startswith("stale ") else ""
                hours = int(arg) if arg.isdigit() else 24
                _print_stale(hours)
            elif line == "machinehistory" or line.startswith("machinehistory "):
                arg = line[15:].strip() if line != "machinehistory" else ""
                if mdb is None:
                    print("  market history DB is not open")
                elif not arg:
                    print("  usage: machinehistory <machine-guid>")
                else:
                    _print_machine_history(arg)
            elif line == "dbexport" or line.startswith("dbexport "):
                arg = line[9:].strip() if line.startswith("dbexport ") else ""
                if mdb is None:
                    print("  market history DB is not open")
                else:
                    path = arg or "vends-current.json"
                    try:
                        realms, machines = mdb.export_current(path)
                        print(f"  exported {machines} CURRENT listing(s) across "
                              f"{realms} realm(s) -> {path}  (current only, no "
                              f"history/removed)")
                    except Exception as e:
                        print(f"  export failed: {e}")
            elif line == "dbbackup" or line.startswith("dbbackup "):
                arg = line[9:].strip() if line.startswith("dbbackup ") else ""
                if mdb is None:
                    print("  market history DB is not open")
                else:
                    path = arg or (f"backups/cubic-market-"
                                   f"{time.strftime('%Y%m%d-%H%M%S')}.db")
                    try:
                        size = mdb.backup(path)
                        print(f"  backup written -> {path}  ({size:,} bytes)")
                    except FileExistsError:
                        print(f"  {path} already exists — choose another name "
                              f"(backups are never overwritten)")
                    except Exception as e:
                        print(f"  backup failed: {e}")
            elif line in ("disable", "offline"):
                ok, msg = go_offline("console")
                print(f"  {msg}")
            elif line in ("enable", "online"):
                ok, msg = go_online()
                print(f"  {msg}")
            elif line == "reconnect" or line.startswith("reconnect "):
                arg = line[10:].strip().lower() if line != "reconnect" else ""
                if arg in ("off", "no", "0"):
                    args.auto_reconnect = False
                    print("  auto-reconnect OFF — a server kick will end the "
                          "session")
                elif arg in ("on", "yes", "1"):
                    args.auto_reconnect = True
                    print(f"  auto-reconnect ON — will re-login on a drop "
                          f"(backoff {args.reconnect_delay:.0f}s.."
                          f"{args.reconnect_max:.0f}s)")
                else:
                    st = "ON" if args.auto_reconnect else "OFF"
                    busy = " (reconnecting now…)" if reconnecting.is_set() else ""
                    wd = (f"silent-kick watchdog fires after "
                          f"{args.idle_timeout:.0f}s of no data"
                          if args.idle_timeout > 0 else "watchdog off")
                    idle = time.time() - net["last_rx"]
                    print(f"  auto-reconnect is {st}{busy}. {wd}; "
                          f"last frame {idle:.0f}s ago. 'reconnect on|off'.")
            elif line in ("log", "logmode", "verbose") or \
                    line.startswith("log "):
                arg = line.split(" ", 1)[1].strip().lower() if " " in line else ""
                if arg in ("on", "full", "1"):
                    disp["verbose"] = True
                elif arg in ("off", "min", "regular", "0"):
                    disp["verbose"] = False
                else:
                    disp["verbose"] = not disp["verbose"]   # bare 'log' toggles
                print(f"  {'LOG' if disp['verbose'] else 'REGULAR'} mode — "
                      + ("full play-by-play (chat, blocks, scan progress)"
                         if disp["verbose"] else
                         "essentials only (status, results, errors, replies)"))
            elif line == "stats":
                total = sum(supp.values())
                print(f"  hidden background frames: {total}")
                for t, c in supp.most_common(8):
                    print(f"    {P.msg_name(t):<20} 0x{t:04x}  {c}")
            elif line.startswith("say "):
                send_public_chat(P.build_chat(line[4:]))
                print("  (sent)")
            elif line == "sayc" or line.startswith("sayc "):
                # EXPERIMENTAL coloured chat. Syntax: a {colour} marker switches
                # the colour of the text that follows it, e.g.
                #   sayc {red}5 {white}- {blue}1
                # {r,g,b} also works: sayc {255,0,0}hi. The builder converts byte
                # RGB into the captured normalized wire form c(1,0,0). Whether the
                # SERVER keeps client-supplied markup is unproven — this is the test.
                import re
                spec = line[5:] if line.startswith("sayc ") else ""
                segs = []
                at, col = 0, None       # NB: not 'pos'/'cur' — those are live
                for m in re.finditer(r"\{([a-zA-Z]+|\d{1,3},\d{1,3},\d{1,3})\}",
                                     spec):
                    if m.start() > at:
                        segs.append((spec[at:m.start()], col))
                    tok = m.group(1)
                    col = (tuple(int(x) for x in tok.split(","))
                           if "," in tok else tok)
                    at = m.end()
                if at < len(spec):
                    segs.append((spec[at:], col))
                if not segs or all(not s[0] for s in segs):
                    print("  usage: sayc {red}5 {white}- {blue}1   (or {r,g,b}). "
                          "colours: " + ", ".join(sorted(P.COLOURS)))
                else:
                    try:
                        send_public_chat(P.build_chat_colored(segs))
                        print("  (sent — EXPERIMENTAL. If it appears as literal "
                              "markup instead of colour, the server rejects "
                              "client-side colour; check another player's view or "
                              "a capture to confirm.)")
                    except ValueError as e:
                        print(f"  {e}")
            elif line == "emoji" or line.startswith("emoji "):
                value = line[5:].strip().lower()
                if value.startswith("0x"):
                    value = value[2:]
                try:
                    code = int(value, 16)
                    send_public_chat(P.build_chat_emoji(code))
                    print(f"  (sent captured emoji 0x{code:02x})")
                except (TypeError, ValueError):
                    print("  usage: emoji <c9|e5>  (the two codes proven by "
                          "capture-20260807-154729)")
            elif line.startswith("friend "):
                who = line[7:].strip()
                if who:
                    send(P.build_friend_request(who))
                    send(P.build_refresh_friends())
                    print(f"  friend request sent to {who}")
                else:
                    print("  usage: friend <name>")
            elif line.startswith("unfriend "):
                who = line[9:].strip()
                if who:
                    send(P.build_unfriend(who))
                    send(P.build_refresh_friends())
                    known.pop(who.lower(), None)
                    print(f"  removed / cancelled request for {who}")
                else:
                    print("  usage: unfriend <name>")
            elif line in ("help", "?", "commands"):
                print_help()
            else:
                print(f"  unknown command '{line.split()[0]}' — type 'help'")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        stop.set()
        try: conn["ws"].close()
        except Exception: pass
        if mdb is not None:
            try: mdb.close()
            except Exception: pass
        if odb is not None:
            try: odb.close()
            except Exception: pass
    print("\n  disconnected.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Cubic Castles terminal client")
    sub = ap.add_subparsers(dest="mode", required=True)

    rp = sub.add_parser("replay", help="offline: drive the stack against a capture")
    rp.add_argument("capture")
    rp.add_argument("--key", required=True)

    lv = sub.add_parser("live", help="GATED: connect to the real server")
    lv.add_argument("--host", default="live.castles.cc")
    lv.add_argument("--port", type=int, default=80)
    lv.add_argument("--path", default="/11000")
    lv.add_argument("--login-from", default="profile.json",
                    help="login profile from cc_login.py (default "
                         "profile.json — login_profile.json is the "
                         "Example account and is not used)")
    lv.add_argument("--role", choices=("front", "worker"), default="front",
                    help="team role. 'front' (default) = full behaviour "
                         "(chat, register, trades, prize). 'worker' = a silent "
                         "second account for the team console: warps, hollas, "
                         "movement, prize crack, but NO chat/whisper/trades.")
    lv.add_argument("--x", type=int, default=None,
                    help="override the spawn X (default: use the portal position "
                         "the server places us at)")
    lv.add_argument("--y", type=int, default=None, help="override the spawn Y")
    lv.add_argument("--z", type=int, default=0, help="initial Z position")
    lv.add_argument("--no-avatar", action="store_true", dest="no_avatar",
                    help="experimental: omit own-player registration and all "
                         "movement announcements to try to prevent avatar "
                         "creation (may leave the session partially initialized)")
    lv.add_argument("--settle-quiet", type=float, default=0.5,
                    dest="settle_quiet",
                    help="on realm entry, start reading once no new world object "
                         "has arrived for this many seconds (default 0.5, was "
                         "1.2 — lower = start analysing sooner, but a slow "
                         "trickle of objects could be cut off)")
    lv.add_argument("--settle-max", type=float, default=5.0, dest="settle_max",
                    help="ceiling on the realm-entry settle wait (default 5.0, "
                         "was 8.0); an empty realm bails at this")
    lv.add_argument("--scan-delay", type=float, default=0.05, dest="scan_delay",
                    help="seconds between dialog opens during 'scan' "
                         "(default 0.05; raise it if the backend pushes back)")
    lv.add_argument("--query-gap", type=float, default=0.01, dest="query_gap",
                    help="seconds between the batched block queries "
                         "(default 0.01 — these open no dialog and the replies "
                         "stream back while we are still sending)")
    lv.add_argument("--dialog-timeout", type=float, default=0.6,
                    dest="dialog_timeout",
                    help="ceiling on how long to wait for a dialog before "
                         "deciding a block isn't a machine (default 0.6; the "
                         "scan tightens this to ~4x the server's measured "
                         "latency, which is about 40ms)")
    lv.add_argument("--links-file", default="realm_links.json", dest="links_file",
                    help="JSON store of manual realm-link overrides ('link "
                         "<url>')")
    lv.add_argument("--realms-file", default="realms.json", dest="realms_file",
                    help="JSON catalogue of every realm entered -> its GUID + "
                         "built link; grows across sessions ('links' lists it)")
    lv.add_argument("--market-db", default="cubic_market.db", dest="market_db",
                    help="SQLite market-history database (default "
                         "cubic_market.db, alongside vends.json). Holds the "
                         "current catalogue AND full history; vends.json is "
                         "still written for compatibility")
    lv.add_argument("--no-market-db", action="store_false", dest="use_market_db",
                    help="don't open the SQLite market-history DB (JSON only)")
    lv.add_argument("--orders-db", default="cubic_orders.db", dest="orders_db",
                    help="SQLite buy-order escrow ledger (default "
                         "cubic_orders.db). Per-player balances + buy orders; "
                         "private, players cannot reach it")
    lv.add_argument("--no-orders-db", action="store_false", dest="use_orders_db",
                    help="don't open the buy-order ledger (disables buy/balance/"
                         "orders/cancel commands)")
    lv.add_argument("--share-url", default="https://castles.cc?realm={guid}",
                    dest="share_url",
                    help="template for a realm's Share link, {guid} = the "
                         "realm-registration GUID from login (confirmed to "
                         "match the browser's Share link)")
    lv.add_argument("--after-scan", default=None, dest="after_scan",
                    help="where to park once a guid-triggered scan finishes: a "
                         "realm Share link / GUID (entered directly), or a "
                         "player name (drop into their realm; they must be "
                         "online). Overrides the saved park.json for this run; "
                         "also settable live with 'after <link|guid|player>'")
    lv.add_argument("--control-port", type=int, default=0, dest="control_port",
                    help="start a web console on this port: a browser page with "
                         "a button that teleports the bot to a named player "
                         "(0 = off). Toggle live with 'control [port]'.")
    lv.add_argument("--control-host", default="127.0.0.1", dest="control_host",
                    help="address the web console binds to (default 127.0.0.1 = "
                         "this PC only; 0.0.0.0 exposes it on your LAN — set "
                         "--control-token if you do that)")
    lv.add_argument("--control-token", default="", dest="control_token",
                    help="if set, the web console requires ?token=... on every "
                         "request (use it whenever you bind to 0.0.0.0)")
    lv.add_argument("--public-port", type=int, default=0, dest="public_port",
                    help="serve the market publicly on this port: a read-only "
                         "site with the searchable price page at /, plus "
                         "/market.json, /market.csv, /history.json?item=, "
                         "/changes.json, /stats.json (0 = off). This is a "
                         "SEPARATE server from --control-port and has no route "
                         "that controls the bot, so it's the only one safe to "
                         "expose to the internet. Toggle live with 'public'.")
    lv.add_argument("--public-host", default="0.0.0.0", dest="public_host",
                    help="address the public market site binds to (default "
                         "0.0.0.0 = reachable from your LAN/tunnel, which is "
                         "the point; 127.0.0.1 keeps it to this PC)")
    lv.add_argument("--publish-dir", default="", dest="publish_dir",
                    help="default folder for 'market publish' — the static "
                         "price site (index.html, market.json, market.csv, "
                         "stats.json, changes.json) that a file server can "
                         "host with the bot switched off. Setting this also "
                         "refreshes that folder automatically after a scan — "
                         "see --publish-every")
    lv.add_argument("--command-fifo", default="bot.cmd", dest="command_fifo",
                    help="named pipe to read console commands from when no "
                         "terminal is attached, so every command still works "
                         "while running as a systemd service: "
                         "echo 'market publish' > bot.cmd . Relative paths sit "
                         "next to cc_client.py. Output goes to the journal. "
                         "Empty string disables it (the bot then just runs "
                         "headless with no way to send commands)")
    lv.add_argument("--headless", action="store_true", dest="headless",
                    help="never read keyboard input (no interactive prompt). The "
                         "GUI passes this for its spawned bot: a --windowed exe "
                         "has no real console, so the terminal-input path would "
                         "spin and flood the log. Commands still arrive over the "
                         "control server / FIFO.")
    lv.add_argument("--simple", action="store_true", dest="simple",
                    help="restrict the bot to the CORE feature set only "
                         "(teleport/nav, guid, vend/market scanning, Discord). "
                         "Every other command (prize, quiz, building, scanners, "
                         "trading, translate, ...) is refused on all command "
                         "paths. The simple GUI build passes this automatically.")
    lv.add_argument("--keep-zero-price", action="store_true",
                    dest="keep_zero_price",
                    help="record listings priced at 0 as well. OFF by default: "
                         "nothing can be bought for 0 Cubits, so a 0 is an "
                         "empty/idle vending slot, a display piece, or a blank "
                         "the scanner misread — never a real sale. By default "
                         "they are dropped from vends.json, from the history "
                         "DB, and from the catalogue views. An UNKNOWN (null) "
                         "price is not a zero and is always kept")
    lv.add_argument("--publish-page", default="market.html",
                    dest="publish_page",
                    help="filename for the published price page (default "
                         "market.html). It is deliberately NOT index.html: a "
                         "hosting folder usually already has one, and "
                         "publishing must not overwrite it. Set this to "
                         "index.html only if the site owns that folder")
    lv.add_argument("--publish-every", type=float, default=120.0,
                    dest="publish_every",
                    help="minimum seconds between automatic refreshes of "
                         "--publish-dir after a scan (default 120). A crawl "
                         "scans realm after realm and each refresh rewrites "
                         "~12 MB, so this debounces them. 0 = never refresh "
                         "automatically, only on 'market publish'")
    lv.add_argument("--public-cache", type=float, default=30.0,
                    dest="public_cache",
                    help="seconds to cache each public page/response, so "
                         "refreshes don't rebuild the catalogue every hit "
                         "(default 30; 0 disables caching)")
    lv.add_argument("--park-file", default="park.json", dest="park_file",
                    help="JSON storing the persistent waiting-realm target "
                         "(default park.json)")
    lv.add_argument("--chat-gap", type=float, default=2.5, dest="chat_gap",
                    help="minimum seconds between ANY two automatic bot chat "
                         "messages (price replies, command answers, "
                         "acknowledgements). Spaces out bursts so the bot never "
                         "machine-guns the channel (default 2.5)")
    lv.add_argument("--chat-delay", type=float, default=1.0, dest="chat_delay",
                    help="seconds to wait before each automatic bot reply goes "
                         "out, so it doesn't fire instantly like a bot "
                         "(default 1.0)")
    lv.add_argument("--mentions-file", default="mentions.log",
                    dest="mentions_file",
                    help="append every chat line that mentions the bot by name "
                         "(username + message + realm + timestamp) to this file "
                         "for later review; the same line also prints to the "
                         "console/journal. On by default; set to \"\" to skip the "
                         "file (the console line still prints)")
    lv.add_argument("--approved-file", default="approved_users.json",
                    dest="approved_file",
                    help="JSON allowlist of Cubic Castles usernames permitted to "
                         "use privileged in-game chat commands (summon, scan "
                         "realm). Public commands (price, help, realm) stay open "
                         "to everyone. Manage with the 'approve'/'unapprove'/"
                         "'approved' console commands or the web console")
    lv.add_argument("--whispers-file", default="whispers.log",
                    dest="whispers_file",
                    help="append every whisper the bot receives and every whisper "
                         "reply it sends (direction + user + message + timestamp) "
                         "to this file. On by default; set to \"\" to skip the file "
                         "(the console line still prints)")
    lv.add_argument("--no-whisperbot", action="store_true", dest="no_whisperbot",
                    help="do not answer whispers (private messages). By default the "
                         "bot treats a whisper exactly like an addressed public "
                         "command and replies privately by whispering back")
    lv.add_argument("--answer-public", action="store_true", dest="answer_public",
                    help="ALSO keep answering commands in public chat. By default, "
                         "once the whisper bot is on it REPLACES public chat: "
                         "public keyword/price/summon/scan commands are ignored and "
                         "everyone is served through whispers instead")
    lv.add_argument("--translate", action="store_true", dest="translate",
                    help="start with the live chat translator ON (detect foreign "
                         "chat and re-post an English version). Off by default; "
                         "toggle live with the 'translate on/off' command. "
                         "Settings persist in translate.json")
    lv.add_argument("--no-translate", action="store_true", dest="no_translate",
                    help="force the live translator OFF at startup, overriding "
                         "translate.json")
    lv.add_argument("--translate-mode", dest="translate_mode",
                    choices=["public", "whisper"], default=None,
                    help="where translations go: 'public' (public chat) or "
                         "'whisper' (privately to --translate-to). Persisted")
    lv.add_argument("--translate-to", dest="translate_to", default=None,
                    help="player NAME who receives whispered translations "
                         "(used when --translate-mode whisper)")
    lv.add_argument("--translate-provider", dest="translate_provider",
                    default=None,
                    help="translation backend: 'auto' (default = best LOCAL "
                         "engine, no key), 'argos' (on-device neural model, fully "
                         "offline once models are cached), 'builtin' (tiny offline "
                         "phrasebook), 'libre' (self-hosted LibreTranslate), or the "
                         "optional hosted APIs 'deepl'/'google' (keys read from env "
                         "vars only, never stored in code)")
    lv.add_argument("--spawn-log", default="spawns.jsonl", dest="spawn_log",
                    help="append every server-given spawn (with its realm) to "
                         "this JSONL file; empty string disables")
    lv.add_argument("--crawl-delay", type=float, default=8.0, dest="crawl_delay",
                    help="MINIMUM seconds between realm joins (reconnects) during a "
                         "crawl — the main throttle against server rate-limits. "
                         "Applied adaptively: the arrival+settle+scan time of each "
                         "realm counts toward this gap, so slow realms wait 0 and "
                         "only fast ones are paced. Reconnect frequency (and ban "
                         "exposure) is the same as a fixed sleep, with far less "
                         "idle time. Higher is gentler/safer (default 8)")
    lv.add_argument("--crawl-max", type=int, default=20, dest="crawl_max",
                    help="default cap on realms visited per crawl (default 20)")
    lv.add_argument("--rescan-batch", type=int, default=15,
                    dest="rescan_batch",
                    help="run 'rescan' in batches of this many realms, draining "
                         "the auto-Hollowarp queue between each batch so hollas "
                         "that arrive during a long rescan get joined promptly "
                         "instead of piling up. 0 = crawl the whole list at once "
                         "(old behavior) (default 15)")
    lv.add_argument("--rescan-drop-after", type=int, default=4,
                    dest="rescan_drop_after",
                    help="drop a watchlisted realm from the rescan list after it "
                         "fails to resolve this many rescans in a row (gone or "
                         "renamed); resolving once resets the count. 0 disables "
                         "auto-prune (default 4)")
    lv.add_argument("--crawl-arrival-timeout", type=float, default=7.0,
                    dest="crawl_arrival_timeout",
                    help="seconds to wait to enter a crawled realm before "
                         "skipping it as unreachable (default 7; a reachable "
                         "realm loads well within this, so a longer wait just "
                         "burns time on private/gone/full realms)")
    lv.add_argument("--crawl-scan-timeout", type=float, default=300.0,
                    dest="crawl_scan_timeout",
                    help="max seconds for one realm's scan before moving on "
                         "(default 300)")
    lv.add_argument("--crawl-file", default="crawl.csv", dest="crawl_file",
                    help="append each crawled realm's machines here as the crawl "
                         "runs (default crawl.csv; empty string disables)")
    lv.add_argument("--crawl-discover-gap", type=float, default=0.7,
                    dest="crawl_discover_gap",
                    help="seconds between the search queries used to auto-discover "
                         "realms (bare 'crawl'); discovery does not reconnect "
                         "(default 0.7)")
    lv.add_argument("--spawn-timeout", type=float, default=8.0,
                    dest="spawn_timeout",
                    help="seconds to wait for the server's spawn placement "
                         "before falling back to --x/--y (default 8)")
    lv.add_argument("--step", type=int, default=P.WALK_TICK,
                    help=f"distance per n/s/e/w step (default {P.WALK_TICK} = "
                         f"one walk tick, measured from a real walk capture)")
    lv.add_argument("--auto-hollowarp", action="store_true", default=True,
                    dest="auto_hollowarp",
                    help="auto-join every Hollawarp broadcast, scan it, watchlist "
                         "it if it has vends, then park (ON by default)")
    lv.add_argument("--no-auto-hollowarp", action="store_false",
                    dest="auto_hollowarp",
                    help="disable the auto-Hollawarp harvester")
    lv.add_argument("--warp-delay", type=float, default=2.0, dest="warp_delay",
                    help="seconds to pause after each auto-Hollowarp scan before "
                         "taking the next queued warp (default 2)")
    lv.add_argument("--offmap-x", type=int, default=0, dest="offmap_x",
                    help="on any scan-join (holla/guid/joinname/crawl), jump the "
                         "avatar to this absolute X BLOCK to hide it off-map; "
                         "default 0 (map origin). Tune live with 'offmap <x> <y> "
                         "<z>'")
    lv.add_argument("--offmap-y", type=int, default=0, dest="offmap_y",
                    help="absolute Y block for the off-map hide spot; default 0")
    lv.add_argument("--offmap-z", type=int, default=0, dest="offmap_z",
                    help="absolute Z block for the off-map hide spot; default 0")
    lv.add_argument("--no-wander", action="store_true", dest="no_wander",
                    help="disable wander entirely: no idle glancing AND no "
                         "off-map relocation when joining a realm — the avatar "
                         "just stays where the server places it.")
    lv.add_argument("--no-reconnect", action="store_false", dest="auto_reconnect",
                    help="disable auto-reconnect (by default, if the server "
                         "kicks/drops the connection the client logs back in "
                         "on its own, with backoff)")
    lv.add_argument("--reconnect-delay", type=float, default=5.0,
                    dest="reconnect_delay",
                    help="seconds to wait before the FIRST reconnect attempt "
                         "after a drop (default 5; doubles each failed try)")
    lv.add_argument("--reconnect-max", type=float, default=120.0,
                    dest="reconnect_max",
                    help="cap on the reconnect backoff wait (default 120s) — "
                         "keeps retries slow so the server doesn't throttle us")
    lv.add_argument("--idle-timeout", type=float, default=120.0,
                    dest="idle_timeout",
                    help="if NO frame arrives for this many seconds the "
                         "connection is treated as a silent kick and rebuilt "
                         "(default 120; 0 disables the watchdog). Raise it if a "
                         "very quiet realm triggers false reconnects")
    lv.add_argument("--quiet", action="store_true", dest="quiet",
                    help="start in REGULAR (minimal) output mode instead of LOG "
                         "mode — only status, results, errors and replies; the "
                         "chat/block/scan-progress chatter is hidden. Toggle "
                         "live with the 'log' command")
    lv.add_argument("--i-accept-live-risk", action="store_true",
                    dest="i_accept_live_risk")

    args = ap.parse_args()
    if args.mode == "replay":
        return run_replay(args.capture, args.key)
    if args.mode == "live":
        return run_live(args)


if __name__ == "__main__":
    sys.exit(main() or 0)

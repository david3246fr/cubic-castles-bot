#!/usr/bin/env python3
"""
Cubic Castles wire protocol codec  (Stage 4, transport-independent).

Everything needed to build and parse game messages, with NO network code — so it
can be fully validated offline against captured frames before anything connects.

Frame model (from stage2/SCHEMA.md, all reverse-engineered):
  * a message body is  [u16 type][fields...]
  * on the wire it becomes:  body + TERMINATOR, then XXTEA-encrypted over the
    largest multiple-of-4 prefix, with the trailing 1-3 bytes left raw
  * key + data are little-endian 32-bit words
  * the first login frames are sent CLEARTEXT (no encryption, no terminator)
"""
import math
import re
import struct
import uuid
import xxtea

# terminator = magic words 0xFFEE 0xCCDD 0xAAEE 0xCCAA, each a u16 in a LE u32
TERMINATOR = struct.pack("<4I", 0x0000FFEE, 0x0000CCDD, 0x0000AAEE, 0x0000CCAA)
TERM_ANCHOR = struct.pack("<2H", 0xFFEE, 0xCCDD)


def key_from_hex(hex_):
    """16-byte key hex -> 4 little-endian words (as XXTEA expects)."""
    return list(struct.unpack("<4I", bytes.fromhex(hex_)))


# --------------------------------------------------------------------------
# frame layer
# --------------------------------------------------------------------------

def encrypt_frame(body, key_words, add_terminator=True):
    """body bytes -> on-wire encrypted frame bytes."""
    plain = body + (TERMINATOR if add_terminator else b"")
    n = (len(plain) // 4) * 4
    if n < 8:
        # too short to XXTEA; sent as-is (rare)
        return plain
    return xxtea.encrypt_bytes(plain[:n], key_words, "<") + plain[n:]


def decrypt_frame(frame, key_words):
    """on-wire encrypted frame -> (full_plaintext, body_without_terminator, had_term)."""
    n = (len(frame) // 4) * 4
    if n >= 8:
        plain = xxtea.decrypt_bytes(frame[:n], key_words, "<") + frame[n:]
    else:
        plain = frame
    idx = plain.find(TERMINATOR)
    if idx < 0:
        idx = plain.find(TERM_ANCHOR)
    body = plain[:idx] if idx >= 0 else plain
    return plain, body, idx >= 0


# --------------------------------------------------------------------------
# field helpers (protocol primitives)
# --------------------------------------------------------------------------

def w_u16(v):  return struct.pack("<H", v & 0xFFFF)
def w_u32(v):  return struct.pack("<I", v & 0xFFFFFFFF)
def w_i32(v):  return struct.pack("<i", v)
def w_f32(v):  return struct.pack("<f", v)


def w_str(s):
    """length-prefixed string: u32 length + utf-8 bytes + NUL.
    The length field INCLUDES the NUL terminator (confirmed: 'hello' -> len 6)."""
    return w_str_bytes(s.encode("utf-8"))


def w_str_bytes(raw):
    """Length-prefixed protocol string from already encoded bytes.

    Most game strings are UTF-8 and should use ``w_str``. Chat emojis are the
    known exception: the official client sends a private one-byte value which
    is not valid UTF-8.
    """
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError("raw protocol string must be bytes-like")
    raw = bytes(raw)
    if b"\x00" in raw:
        raise ValueError("raw protocol string cannot contain NUL")
    b = raw + b"\x00"
    return struct.pack("<I", len(b)) + b


class Reader:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def u16(self):
        v = struct.unpack_from("<H", self.d, self.p)[0]; self.p += 2; return v

    def u32(self):
        v = struct.unpack_from("<I", self.d, self.p)[0]; self.p += 4; return v

    def i32(self):
        v = struct.unpack_from("<i", self.d, self.p)[0]; self.p += 4; return v

    def f32(self):
        v = struct.unpack_from("<f", self.d, self.p)[0]; self.p += 4; return v

    def s(self):
        # length includes the NUL terminator; strip it, do not skip an extra byte
        return self.s_bytes().decode("utf-8", "replace")

    def s_bytes(self):
        """Read a length-prefixed string without assuming its encoding."""
        n = self.u32()
        b = self.d[self.p:self.p + n]; self.p += n
        return b[:-1] if b.endswith(b"\x00") else b

    def rest(self):
        return self.d[self.p:]


# --------------------------------------------------------------------------
# message types (names from schema; extend as more fields are mapped)
# --------------------------------------------------------------------------

# Names confirmed by F9 action-label correlation (cc_identify.py) unless marked.
MSG = {
    0x0002: "LOGIN",             # handshake, cleartext
    0x0004: "POST_LOGIN",        # startup, right after login
    0x0005: "WORLD_STATE",       # startup, large (215-242b) — confirmed startup 0.94
    0x0006: "MOVE",              # walk 0.60
    0x0007: "MOVE2",             # walk 0.62 (movement variant)
    0x011a: "PEER_MOVE",         # rx 60b, one per tick per moving player nearby
    0x0008: "JUMP",              # jump 0.75
    0x000b: "ENTITY_STATE",      # startup 1.0 (20/132b tagged records)
    0x000c: "CHAT_TEXT",         # chat 0.75 — carries the actual message text
    0x000d: "WORLD_LOAD_0d",     # startup 1.0
    0x000f: "WORLD_OBJECTS",     # the realm's placed blocks (70-byte records)
    0x0021: "WORLD_OBJECTS_2",   # same, compact 44-byte records, count-prefixed
    0x0011: "STATE_0011",        # startup (8b)
    0x000e: "INVENTORY/ENTER",   # rx big = inventory; tx small = realm check-in
    0x0009: "DROP_ITEM",         # tx: drop what you're holding, at your position
    0x000a: "BLOCK_INTERACT",    # tx/rx: click the block at (x,y,z)
    0x0010: "PICKUP",            # tx/rx: pick up a world object by GUID
    0x0014: "BLOCK_QUERY",       # tx: what is at (x,y,z) -> rx guid + kind
    0x0037: "INVENTORY_CHANGED", # rx: short notice after a drop/pickup
    0x0040: "PASSWORD_GUESS",    # tx: submit a Password Sentry guess (lenpfx str)
    0x0019: "BACKEND_HANDOFF",   # host+port redirect — confirmed
    0x001c: "BLOCK_ACTION",      # select/place-block 1.0
    0x0026: "FRIEND_REQUEST",    # add-friend by name — confirmed
    0x0027: "FRIENDS_LIST",      # friends + pending arrays (rx) / refresh (tx)
    0x002b: "UNFRIEND",          # remove friend / cancel request by name
    0x0031: "CHAT_TOGGLE",       # chat 0.67 — 3-byte typing/channel toggle
    0x005f: "REALM_ID",          # realm name + owner, on every realm entry
    0x0088: "ONLINE_FRIENDS",    # tx refresh / rx count + friend GUIDs
    0x0089: "TELEPORT",          # tx: teleport to a player GUID (handoff)
    0x00c8: "REALM_SEARCH",      # tx: realm-browser search (own guid + name)
    0x00d3: "REALM_JOIN",        # tx: join realm by GUID (all-FF = browse)
    0x00e1: "SEARCH_RESULTS",    # rx: realm-browser results markup (fragmented)
    0x00ba: "MENU_DIALOG",       # rx: server menu (e.g. "Whisper to Who?"); tx: pick
    0x0145: "REALM_INFO",        # startup 1.0 — carries realm name string
    0x005a: "SRV_HEARTBEAT",     # every idle
    0x0101: "CLIENT_HEARTBEAT",  # every idle
}


def msg_name(t):
    return MSG.get(t, f"UNKNOWN_0x{t:04x}")


def body_type(body):
    return struct.unpack_from("<H", body)[0] if len(body) >= 2 else None


# ---- builders for messages we understand well enough to construct ----

# The login body (tx 0x0002) is, in order:
#   u16 type=0x0002
#   u32 = length of the token string (0 -> empty token, first hello)
#   token bytes (+NUL if non-empty)
#   str display_name, str account_id, str client_id, str platform,
#   str version, str steam_id
# The first hello sends an EMPTY token; the authenticated hello sends the real
# account token. Confirmed byte-for-byte against captured login frames.

def build_login(token, display_name, account_id, client_id, platform,
                version, steam_id):
    # token slot is a normal length-prefixed string; the first hello uses "".
    return (w_u16(0x0002) + w_str(token) +
            w_str(display_name) + w_str(account_id) + w_str(client_id) +
            w_str(platform) + w_str(version) + w_str(steam_id))


def recover_key_from_response(response, next_frame):
    """Recover the XXTEA key issued in a login response WITHOUT parsing the
    variable session-info block: test every 16-byte window against the first
    encrypted frame and keep the one that yields the magic terminator.
    Returns (key_words, key_hex) or None."""
    for off in range(0, len(response) - 15):
        cand = response[off:off + 16]
        kw = list(struct.unpack("<4I", cand))
        _, _, had_term = decrypt_frame(next_frame, kw)
        if had_term:
            return kw, cand.hex()
    return None


# ---- gameplay message structure (from captured bodies) ----
#
# MOVE (0x0006) / JUMP (0x0008) use a tagged field list: repeated
#   [u32 tag][u32 value]
# where tags 0x10/0x15/0x58 carry position components (values change as the
# avatar moves) and a trailing counter increments per message. Full tag meaning
# is still being mapped; parse_tagged exposes the raw pairs.

def parse_tagged(body, start=2):
    """Parse a MOVE/JUMP-style body into (tag, value) u32 pairs."""
    r = Reader(body)
    r.p = start
    pairs = []
    while r.p + 8 <= len(body):
        tag = r.u32()
        val = r.u32()
        pairs.append((tag, val))
    return pairs, body[r.p:]


def build_move_raw(pairs, leader=b""):
    """Construct a MOVE body from (tag, value) u32 pairs. `leader` is any
    bytes between the type and the first pair (JUMP has a 1-byte leader)."""
    out = w_u16(0x0006) + leader
    for tag, val in pairs:
        out += w_u32(tag) + w_u32(val)
    return out


# Position MOVE (0x0006), fixed 62-byte layout as sent by the real client to
# announce/spawn the avatar: three coordinates X, Y, Z, then zero padding, then
# a 4-byte tail [seq, 00, 00, 01].
#
# COORDINATE ENCODING (proven on capture 222119, diag_coords.py): each coordinate
# is split across TWO u32s as  high * 100000 + low.  The leading word is NOT a
# field tag — walking straight makes the pair carry (…, 99xxx) -> (…+1, 0xxx),
# and once decoded a walk tick is a constant +72802 with a perfect diagonal of
# +-51478 (72802 / sqrt(2)). No low half ever reached 100000 in any capture.
COORD_BASE = 100000


def enc_coord(v):
    """full coordinate -> (high, low) as the wire carries it."""
    return divmod(int(v), COORD_BASE)


def dec_coord(high, low):
    return high * COORD_BASE + low


WALK_TICK = 72802          # one walk step, in full coordinate units
# Full-speed velocity component the real client puts in the motion block while
# walking (capture 20260819-153252-walk: ±2799 on the primary axis, ramping
# 1999->2799 on accel and back to 0 on stop). Receivers use this vector to face
# and animate the avatar; a zero-velocity position change just snaps it.
WALK_SPEED = 2799


def heading_deg(vx, vy):
    """Compass heading the client puts in the motion block for a velocity/step
    (vx, vy): 0deg = -Y, 90 = +X, 180 = +Y, 270 = -X (proven: capture
    20260819-153252-walk, motion offset +24 == round(atan2(vx,-vy)) exactly)."""
    return int(round(math.degrees(math.atan2(vx, -vy)))) % 360


def build_move(x, y, z, seq=1, vx=0, vy=0, moving=False, heading=None):
    """0x0006 position frame.

    The motion block carries, at offset +4 the signed X velocity, at +12 the
    signed Y velocity, and at **+24 the FACING angle in degrees** — the field that
    actually turns the avatar for other clients, and which the real client keeps
    populated even while standing still so a parked player still faces a
    direction. `heading` sets that field (0-359); if it's None and moving, it's
    derived from the velocity. With moving=True the tail motion-state byte is 0x04
    (walking) else 0x00. moving=False + heading=None reproduces the old zeroed
    still-frame exactly (back-compat)."""
    xh, xl = enc_coord(x)
    yh, yl = enc_coord(y)
    zh, zl = enc_coord(z)
    motion = bytearray(32)
    if moving:
        struct.pack_into("<i", motion, 4, int(vx))
        struct.pack_into("<i", motion, 12, int(vy))
        if heading is None and (vx or vy):
            heading = heading_deg(vx, vy)
    if heading is not None:
        struct.pack_into("<I", motion, 24, int(heading) % 360)
    tail = bytes([seq & 0xFF,
                  0x30 if (moving or heading is not None) else 0x00,
                  0x04 if moving else 0x00,
                  0x01])
    body = (w_u16(0x0006) +
            w_u32(xh) + w_u32(xl) +
            w_u32(yh) + w_u32(yl) +
            w_u32(zh) + w_u32(zl) +
            bytes(motion) + tail)
    assert len(body) == 62, len(body)
    return body


def build_jump(x, y, z, seq=1, leader=0):
    """0x0008 JUMP — one frame triggers the hop; the client then reports the arc
    via the normal 0x0006 stream. 37-byte layout proven byte-exact against capture
    20260819-201746-jump: type | 1-byte leader | X(hi,lo) Y(hi,lo) Z(hi,lo) |
    8 zero bytes (vx,vy, both 0 for a jump-in-place) | seq | 0x00. Send at the
    current position; the shared move sequence counter continues through it."""
    xh, xl = enc_coord(x)
    yh, yl = enc_coord(y)
    zh, zl = enc_coord(z)
    body = (w_u16(0x0008) + bytes([leader & 0xFF]) +
            w_u32(xh) + w_u32(xl) +
            w_u32(yh) + w_u32(yl) +
            w_u32(zh) + w_u32(zl) +
            b"\x00" * 8 + bytes([seq & 0xFF, 0x00]))
    assert len(body) == 37, len(body)
    return body


def parse_move(body):
    """tx/rx 0x0006 (62-byte form) -> (x, y, z) as full coordinates."""
    pairs, _tail = parse_tagged(body)
    if len(pairs) < 3:
        return None
    return tuple(dec_coord(h, l) for h, l in pairs[:3])


# CHAT: tx 0x0031 is a 3-byte typing/channel TOGGLE (31 00 00 / 31 00 01), NOT the
# text. The actual message text travels on 0x000c (CHAT_TEXT), confirmed by
# decoding real sends ("hello", "123", ...).
def build_chat_toggle(on):
    return w_u16(0x0031) + bytes([1 if on else 0])


def build_chat(text):
    """tx 0x000c — send a chat message. Structure confirmed from capture:
    type + u32-length-prefixed UTF-8 text (+ NUL)."""
    return w_u16(0x000c) + w_str(text)


CHAT_EMOJI_THUMBS_UP = 0xC9
CHAT_EMOJI_100 = 0xE5
CAPTURED_CHAT_EMOJI_CODES = frozenset((CHAT_EMOJI_THUMBS_UP, CHAT_EMOJI_100))


def build_chat_emoji(code):
    """tx 0x000c -- send one captured in-game chat emoji.

    The official client does not send these as Unicode. Capture 20260807-154729
    proves an ordinary chat body containing one private byte: either C9 or E5.
    Restrict this helper to observed codes so an untested private value cannot
    accidentally be sent by a typo.
    """
    if isinstance(code, bool) or not isinstance(code, int):
        raise TypeError("emoji code must be an integer")
    if code not in CAPTURED_CHAT_EMOJI_CODES:
        known = ", ".join(f"{value:02x}" for value in sorted(CAPTURED_CHAT_EMOJI_CODES))
        raise ValueError(f"unknown chat emoji code 0x{code:02x}; captured codes: {known}")
    return w_u16(0x000c) + w_str_bytes(bytes([code]))


def build_chat_mixed(*parts):
    """tx 0x000c -- build one message containing text and captured emojis.

    String parts are encoded as UTF-8. Integer parts must be emoji codes already
    observed from the official client. All parts share one length-prefixed chat
    payload and therefore render as one message rather than separate entries.
    """
    raw = bytearray()
    for part in parts:
        if isinstance(part, str):
            raw.extend(part.encode("utf-8"))
        elif (not isinstance(part, bool) and isinstance(part, int) and
              part in CAPTURED_CHAT_EMOJI_CODES):
            raw.append(part)
        else:
            raise ValueError("chat parts must be text or a captured emoji code")
    return w_u16(0x000c) + w_str_bytes(raw)


# --- inline text colour ---------------------------------------------------
# The game's text renderer colours a run of text by prefixing it with a DLE
# control byte (0x10) followed by an ASCII tag "c(r,g,b)"; the colour then holds
# until the next tag. Channels are normalized floats in the 0..1 range, not
# byte values. Captures contain, for example, c(.6,.6,.6) on whispers,
# c(.5,1,1) on help notices, and c(1,1,.5) on Hollawarp notices.
#
# This proves the SERVER -> CLIENT renderer format. Whether the server accepts
# and re-broadcasts the same markup supplied by a client in outbound 0x000c is
# still a live-test question, so build_chat_colored remains experimental.
COLOUR_CTRL = b"\x10"
COLOUR_TAG_RE = re.compile(
    rb"\x10c\(((?:0|1|\.[0-9]+|0\.[0-9]+|1\.0+)),"
    rb"((?:0|1|\.[0-9]+|0\.[0-9]+|1\.0+)),"
    rb"((?:0|1|\.[0-9]+|0\.[0-9]+|1\.0+))\)"
)

# A few named colours matching the "5 - 1" look (bright red / bright blue).
COLOURS = {
    "red": (255, 0, 0), "green": (0, 200, 0), "blue": (40, 90, 255),
    "yellow": (255, 220, 0), "orange": (255, 140, 0), "purple": (180, 60, 255),
    "pink": (255, 105, 180), "cyan": (0, 220, 220), "white": (255, 255, 255),
    "black": (0, 0, 0), "gray": (140, 140, 140), "grey": (140, 140, 140),
}


def colour_tag(r, g, b):
    """Build the captured DLE + ``c(r,g,b)`` renderer tag.

    Callers may use ordinary 0..255 RGB values (the public ``sayc`` syntax) or
    normalized 0..1 floats. On the wire they are always normalized to 0..1.
    """
    def channel(value):
        if isinstance(value, bool):
            raise ValueError("colour channel must be numeric")
        try:
            value = float(value)
        except (TypeError, ValueError):
            raise ValueError("colour channel must be numeric") from None
        if not 0 <= value <= 255:
            raise ValueError("colour channel out of range 0..255")
        if value > 1:
            value /= 255.0
        rendered = f"{value:.3f}".rstrip("0").rstrip(".")
        if rendered.startswith("0."):
            rendered = rendered[1:]
        return rendered

    return COLOUR_CTRL + (
        f"c({channel(r)},{channel(g)},{channel(b)})".encode("ascii")
    )


def parse_colour_markup(raw_text):
    """Split renderer-marked bytes into visible text/colour runs.

    Returns ``(visible_text, segments)``. Each segment is a ``(text, rgb)``
    pair, where ``rgb`` is a normalized float tuple or ``None`` before the
    first colour tag. Unrecognized control bytes remain visible replacement
    characters instead of being silently discarded.
    """
    raw_text = bytes(raw_text)
    segments = []
    colour = None
    at = 0
    visible = []
    for match in COLOUR_TAG_RE.finditer(raw_text):
        if match.start() > at:
            text = raw_text[at:match.start()].decode("utf-8", "replace")
            segments.append((text, colour))
            visible.append(text)
        colour = tuple(float(value) for value in match.groups())
        at = match.end()
    if at < len(raw_text):
        text = raw_text[at:].decode("utf-8", "replace")
        segments.append((text, colour))
        visible.append(text)
    return "".join(visible), segments


def build_chat_colored(segments):
    """tx 0x000c — a chat message whose text carries inline colour markup.

    `segments` is a list of (text, colour) pairs. `colour` is None (default
    colour), a (r,g,b) tuple, or a name from COLOURS. The whole thing is one
    normal chat body (u32 length + bytes + NUL via w_str_bytes); the colour
    control bytes live inside the text. EXPERIMENTAL — see COLOUR_CTRL note.
    """
    raw = bytearray()
    for text, colour in segments:
        if colour is not None:
            if isinstance(colour, str):
                if colour.lower() not in COLOURS:
                    raise ValueError(f"unknown colour '{colour}'")
                colour = COLOURS[colour.lower()]
            raw.extend(colour_tag(*colour))
        raw.extend(str(text).encode("utf-8"))
    return w_u16(0x000c) + w_str_bytes(bytes(raw))


def parse_chat(body):
    """Parse an inbound 0x000c chat: type + 0x0001 + 16-byte sender GUID +
    lenpfx text + 1 status byte."""
    r = Reader(body)
    assert r.u16() == 0x000c
    r.u16()                       # 0x0001 marker
    sender = r.d[r.p:r.p + 16]; r.p += 16
    raw_text = r.s_bytes()
    emoji_code = (raw_text[0]
                  if len(raw_text) == 1 and raw_text[0] in CAPTURED_CHAT_EMOJI_CODES
                  else None)
    has_colour_markup = COLOUR_TAG_RE.search(raw_text) is not None
    text, colour_segments = parse_colour_markup(raw_text)
    status = r.d[r.p] if r.p < len(r.d) else None
    return {"sender_guid": sender.hex(), "text": text,
            "raw_text": raw_text, "emoji_code": emoji_code, "status": status,
            "has_colour_markup": has_colour_markup,
            "colour_segments": colour_segments}


# WHISPER (private message). Decoded from captures 20260809-175448 / -181910.
# There is NO direct "/whisper <name> <msg>" form (user confirmed /w, /r, and an
# inline name all do nothing) — sending is a two-step server-driven MENU:
#   1. send ordinary chat text "/whisper <msg>"   (build_whisper_open)  -> the
#      message is carried here; the recipient is NOT.
#   2. server replies rx 0x00ba "Whisper to Who?" menu (parse_whisper_menu):
#      type + 0x0001 + u32 menu_id + str title + str subtitle + u8 real_count +
#      entry strings (the real user names first, then blank 14-space filler rows
#      that pad the menu to a fixed height).
#   3. pick a name by its row index: tx 0x00ba + u32 menu_id + u8 index
#      (build_whisper_select) — this is the click that actually delivers it.
# A whisper (both the sender's own echo AND an inbound one) arrives as an ORDINARY
# rx 0x000c chat frame whose body text is server-formatted with a colour-markup
# tag: b"\x10" + "c(r,g,b)" + "(WHISPER)\n" + <message>. The 16-byte sender GUID
# is in the normal chat position, so parse_chat already yields it; the message
# carries NO sender name, so the sender is identified by GUID only. Distinguish an
# inbound whisper from the echo of your own by comparing sender_guid to your own.
WHISPER_MENU_TYPE = 0x00ba
WHISPER_MENU_TITLE = "Whisper to Who?"
# Observed identical (0x0000010e) across two independent sessions, so it looks like
# a fixed dialog id rather than a per-session token — but always echo back whatever
# the live menu carried rather than hardcoding this.
WHISPER_MENU_ID_SEEN = 0x0000010e
WHISPER_TAG = b"(WHISPER)"
# The server rejects a longer /whisper command with the misleading response
# "You need to make your whisper longer!" and never opens the recipient picker.
# This conservative payload limit is capture/live-tested and leaves the command
# prefix outside the budget.
WHISPER_TEXT_MAX_BYTES = 90


def build_whisper_open(text):
    """Step 1 of sending a whisper: the plain "/whisper <msg>" chat command that
    makes the server pop the recipient picker. Byte-exact vs capture."""
    if len(text.encode("utf-8")) > WHISPER_TEXT_MAX_BYTES:
        raise ValueError(
            f"whisper text exceeds {WHISPER_TEXT_MAX_BYTES}-byte safe limit"
        )
    return w_u16(0x000c) + w_str("/whisper " + text)


def build_whisper_select(menu_id, index):
    """Step 3: click row `index` in the "Whisper to Who?" menu identified by
    `menu_id` (from parse_whisper_menu). Byte-exact vs capture."""
    if not (0 <= index <= 0xFF):
        raise ValueError("whisper menu index out of range")
    return w_u16(WHISPER_MENU_TYPE) + w_u32(menu_id) + bytes([index])


def parse_whisper_menu(body):
    """Parse a rx 0x00ba "Whisper to Who?" picker. Returns
    {menu_id, title, subtitle, real_count, entries, names} or None. `entries` is
    every row (including the blank filler rows); `names` is the non-blank rows with
    their original row index preserved as (index, name)."""
    try:
        r = Reader(body)
        if r.u16() != WHISPER_MENU_TYPE:
            return None
        r.u16()                                   # 0x0001 marker
        menu_id = r.u32()
        title = r.s()
        subtitle = r.s()
        if title != WHISPER_MENU_TITLE:
            return None
        real_count = r.d[r.p]; r.p += 1
        entries = []
        while r.p < len(r.d) - 2:                  # stop before the terminator
            before = r.p
            s = r.s()
            if r.p == before:                      # no progress -> bail
                break
            entries.append(s)
        names = [(i, e) for i, e in enumerate(entries) if e.strip()]
        return {"menu_id": menu_id, "title": title, "subtitle": subtitle,
                "real_count": real_count, "entries": entries, "names": names}
    except Exception:
        return None


def parse_whisper(body):
    """If a rx 0x000c chat frame is a whisper (server-formatted with the
    b"\\x10...(WHISPER)\\n" tag), return {sender_guid, message}; else None. A user
    cannot type the leading 0x10 colour-control byte, so an ordinary public message
    that merely contains the text "(WHISPER)" is correctly rejected."""
    try:
        c = parse_chat(body)
    except Exception:
        return None
    rt = c.get("raw_text") or b""
    if not rt.startswith(b"\x10") or WHISPER_TAG not in rt:
        return None
    nl = rt.find(b"\n", rt.find(WHISPER_TAG))
    if nl < 0:
        return None
    msg = rt[nl + 1:].split(b"\x00", 1)[0].decode("utf-8", "replace")
    return {"sender_guid": c["sender_guid"], "message": msg}


def build_heartbeat(tick, session_token):
    """tx 0x0101: type + u32 incrementing tick + constant per-session token
    (11 bytes observed). Pass the token captured from this session's heartbeats."""
    return w_u16(0x0101) + w_u32(tick) + session_token


def parse_heartbeat(body):
    r = Reader(body)
    assert r.u16() == 0x0101
    tick = r.u32()
    token = r.rest()
    return {"tick": tick, "session_token": token}


def parse_player_state(body):
    """0x0005 player state: type + 0x0001 + 16-byte guid + lenpfx name +
    three (high, low) coordinate pairs for X, Y, Z (see COORD_BASE).
    Returns {guid, name, x, y, z} with FULL coordinates, or None."""
    try:
        r = Reader(body)
        r.u16(); r.u16()
        guid = body[r.p:r.p + 16]; r.p += 16
        name = r.s()
        base = r.p
        if base + 24 > len(body):
            return None
        vals = struct.unpack_from("<6I", body, base)
        x = dec_coord(vals[0], vals[1])
        y = dec_coord(vals[2], vals[3])
        z = dec_coord(vals[4], vals[5])
        return {"guid": guid.hex(), "name": name, "x": x, "y": y, "z": z}
    except Exception:
        return None


def parse_self_move(body):
    """0x0023 'you are now here': type + 0x0001 + 16-byte guid + three
    (high, low) coordinate pairs. Returns FULL (x, y, z) or None. Used to adopt
    the server's teleport placement."""
    if len(body) < 44:
        return None
    vals = struct.unpack_from("<6I", body, 20)
    return (dec_coord(vals[0], vals[1]),
            dec_coord(vals[2], vals[3]),
            dec_coord(vals[4], vals[5]))


def parse_notice(body):
    """0x000d server text notice: type + 3-byte header + u32 len + text.
    Returns the text, or None if it isn't a text notice."""
    if len(body) < 9:
        return None
    n = struct.unpack_from("<I", body, 5)[0]
    if n < 1 or 9 + n > len(body):
        return None
    txt = body[9:9 + n]
    if not all(c in (0, 9, 10, 13) or 32 <= c < 127 for c in txt):
        return None
    return txt.rstrip(b"\x00\n").decode("utf-8", "replace")


def parse_notice_00de(body):
    """rx 0x00de — a short server toast: type + 0x0001 marker + u32 len + text.
    Distinct layout from the 0x000d notice (its length sits at offset 4, not 5).
    Carries "Not enough Cubits!" after a failed vending confirm, and
    "Your price was set to: N Cubits" after setting a vend price. Confirmed in
    capture-20260814-172846. Returns the text, or None if it isn't one."""
    if body_type(body) != 0x00de or len(body) < 8:
        return None
    n = struct.unpack_from("<I", body, 4)[0]
    if n < 1 or 8 + n > len(body):
        return None
    txt = body[8:8 + n]
    if not all(c in (0, 9, 10, 13) or 32 <= c < 127 for c in txt):
        return None
    return txt.rstrip(b"\x00\n").decode("utf-8", "replace")


def parse_wallet_balance(body):
    """rx 0x0011 — a small state broadcast carrying the player's current Cubit
    balance at offset 4 as a u32 little-endian. Verified 1803 -> 1793 across a
    10-Cubit purchase in capture-20260814-172846. Returns the balance int, or
    None if the frame is too short / not a 0x0011."""
    if body_type(body) != 0x0011 or len(body) < 8:
        return None
    return struct.unpack_from("<I", body, 4)[0]


def build_enter(guid):
    """tx 0x000e — realm-registration frame. The client sends two after every
    login: one with its own guid, one with the realm-registration guid (both
    read from the login response). This is what makes the server place us in
    the realm (and, after a teleport, onto the friend)."""
    if isinstance(guid, str):
        guid = bytes.fromhex(guid)
    return w_u16(0x000e) + guid


def guids_from_response(response):
    """Two 16-byte guids follow the name/account strings in a login response:
    (own_guid, realm_registration_guid). Returns (bytes, bytes) or (None, None)."""
    try:
        r = Reader(response)
        r.u16(); r.u16(); r.s(); r.s()
        return response[r.p:r.p + 16], response[r.p + 16:r.p + 32]
    except Exception:
        return None, None


def build_friend_request(name):
    """tx 0x0026 — send a friend request to a player by name. Confirmed
    byte-exact against capture. The client also sends a 2-byte 0x0027 afterward
    to refresh the friends list."""
    return w_u16(0x0026) + w_str(name)


def build_refresh_friends():
    """tx 0x0027 (no body) — ask the server to (re)send the friends list."""
    return w_u16(0x0027)


def build_refresh_online_friends():
    """tx 0x0088 (no body) — ask which friends are currently online.

    The official client sends this immediately after ``build_refresh_friends``
    before every player teleport, then waits for the corresponding 0x0088
    response before sending 0x0089.
    """
    return w_u16(0x0088)


def build_unfriend(name):
    """tx 0x002b — remove a friend BY NAME. The same message cancels a still
    pending outgoing friend request (confirmed in capture 212753: 0x002b
    'tractor man' right after requesting them). Byte layout mirrors 0x0026."""
    return w_u16(0x002b) + w_str(name)


def build_teleport(guid):
    """tx 0x0089 — teleport to the player/target with this 16-byte GUID.
    Triggers a realm handoff (rx 0x0019) + reconnect. `guid` is bytes or hex."""
    if isinstance(guid, str):
        guid = bytes.fromhex(guid)
    assert len(guid) == 16, "teleport GUID must be 16 bytes"
    return w_u16(0x0089) + guid


def build_join_realm(guid):
    """tx 0x00d3 — join the realm with this 16-byte registration GUID (the same
    token the login response gives us and the Share link carries). This is what
    the in-game realm browser's Go/Visit button sends: the server answers with a
    backend handoff (rx 0x0019) and we reconnect + re-login into the realm, the
    exact same machinery as teleport. An all-0xFF GUID is the browser's "list
    realms" form, NOT a join. `guid` is bytes or hex.
    Verified byte-exact vs capture 162327 (Example's Collection)."""
    if isinstance(guid, str):
        guid = bytes.fromhex(guid)
    assert len(guid) == 16, "realm GUID must be 16 bytes"
    return w_u16(0x00d3) + guid + b"\x01\x00\x00\x00\x00"


OPEN_BROWSER_GUID = b"\xff" * 16


def build_open_realm_browser():
    """tx 0x00d3 with an all-0xFF GUID — the realm browser's 'open / list' form.
    This is NOT a join (no rx 0x0019 handoff): it's how the real client OPENS
    the browser. The server will not answer a 0x00c8 search until the browse
    session has been opened this way, so a standalone client must send this
    first. Same message shape as build_join_realm(all-FF)."""
    return build_join_realm(OPEN_BROWSER_GUID)


def build_realm_search(name, own_guid):
    """tx 0x00c8 — realm-browser search query: own player GUID + the search
    text. Server replies with the matching realms. `own_guid` is bytes or hex.
    Verified byte-exact vs capture 162327 ('Example's Collection')."""
    if isinstance(own_guid, str):
        own_guid = bytes.fromhex(own_guid)
    assert len(own_guid) == 16, "own GUID must be 16 bytes"
    return w_u16(0x00c8) + own_guid + w_str(name)


def build_place_block(x, y, z, bx, by, bz, *, inventory_slot, facing=128,
                      nonce=52546, rot=2):
    """tx 0x000b — place the item in ``inventory_slot`` at (bx,by,bz).
    `x,y,z` = the player's full-coord position (where they're standing).
    ``facing`` and legacy-named ``nonce`` appear to be the integer/fractional
    parts of facing in degrees, using the same base 100000 as coordinates.
    They are not a placement sequence: repeated poses reuse both words while
    targets change. The meaning of the final ``rot`` field remains unproven.
    Defaults reproduce an old capture, not a validated arbitrary-pose policy.
    Layout:
      0b00 | X(hi,lo) Y(hi,lo) Z(hi,lo) | facing(u32) | nonce(u32) | 01 00 |
      bx by bz (u32) | inventory_slot(u16) | rot(u16)

    The field was resolved from capture-20260828-123223-place7.  Gold Block is
    catalogue item 290, but it was record/slot 5 in every inventory snapshot;
    all nine placements sent 5 here while quantity 290 fell from 32 to 23.
    Therefore callers MUST resolve the desired catalogue item id against the
    latest ordered inventory snapshot immediately before sending.  Passing a
    catalogue item id here is unsafe and can address the wrong slot.

    The slot is deliberately a required keyword: a default could place a rare
    item after inventory changes. All live callers use the verified builder.
    Packet shape is capture-verified; live acceptance is not established."""
    if (isinstance(inventory_slot, bool)
            or not isinstance(inventory_slot, int)
            or not 0 <= inventory_slot <= 0xFFFF):
        raise ValueError("inventory_slot must be an integer from 0 through 65535")
    xh, xl = enc_coord(x)
    yh, yl = enc_coord(y)
    zh, zl = enc_coord(z)
    return (w_u16(0x000b)
            + w_u32(xh) + w_u32(xl) + w_u32(yh) + w_u32(yl)
            + w_u32(zh) + w_u32(zl)
            + w_u32(facing) + w_u32(nonce) + b"\x01\x00"
            + w_u32(bx) + w_u32(by) + w_u32(bz)
            + struct.pack("<H", inventory_slot) + struct.pack("<H", rot))


def inventory_slot_for_item(inventory, item_id):
    """Return the current zero-based slot containing ``item_id``, else ``None``.

    Slots are positions in the ordered rx 0x000e record array, not persistent
    identifiers.  Re-resolve after every inventory update because removing the
    last item from a stack can shift every later slot.
    """
    if not inventory:
        return None
    for slot, item in enumerate(inventory.get("items", ())):
        if item.get("item_id") == item_id and item.get("qty", 0) > 0:
            return slot
    return None


def build_select_item(own_guid, item_guid):
    """tx 0x001c — select/hold a hotbar item: player guid + code 0x000a + the
    inventory item's guid + 00 00. Decoded from capture 091520."""
    if isinstance(own_guid, str):
        own_guid = bytes.fromhex(own_guid)
    if isinstance(item_guid, str):
        item_guid = bytes.fromhex(item_guid)
    return w_u16(0x001c) + own_guid + struct.pack("<H", 0x000a) + item_guid + b"\x00\x00"


def parse_sign_prompt(body):
    """rx 0x00c8 'Enter Sign Text' — the editor prompt the server sends right
    after a sign is placed. It carries the new sign's GUID at offset 4:
      c8 00 | 01 00 | sign_guid(16) | u32 len | "Enter Sign Text\\0" | trailer
    Returns the guid hex, or None if this 0x00c8 isn't the sign prompt. Verified
    on captures 000632 + 003913 (the guid matches the one the write used)."""
    if body_type(body) != 0x00c8 or len(body) < 20:
        return None
    if b"Enter Sign Text" not in body:
        return None
    return body[4:20].hex()


def build_write_sign(sign_guid, text):
    """tx 0x00c8 — set a SIGN's text. Same wire shape as build_realm_search, but
    the 16-byte GUID is the SIGN block's own GUID (from a rx 0x0014 block query),
    not the player's, and the string is the sign message. The server tells the
    two apart by whose GUID it is. Verified byte-exact vs capture 000632: the
    sign at block (2,3,99), guid 2efcf8f6341de944bb80ab41d9268ab3, was set to
    'hello' by exactly `c800 <guid> 06000000 68656c6c6f00`."""
    if isinstance(sign_guid, str):
        sign_guid = bytes.fromhex(sign_guid)
    assert len(sign_guid) == 16, "sign GUID must be 16 bytes"
    return w_u16(0x00c8) + sign_guid + w_str(text)


_REALM_LINK_RE = re.compile(rb'<link\s+"\{([0-9A-Fa-f-]{36})\}">(.*?)</link>', re.S)


def realm_guid_to_wire(reg):
    """Registry GUID string ('{13980BD1-4310-...}' or bare) -> 16 wire bytes.
    Cubic uses the standard Windows GUID byte order (bytes_le): first three
    groups little-endian, last two as-is. Verified: {13980BD1-4310-42B1-937E-
    115B638E8259} -> d10b98131043b142937e115b638e8259 (the 0x00d3 join GUID)."""
    return uuid.UUID(reg.strip().strip("{}")).bytes_le


def parse_realm_search(body):
    """rx 0x00e1 'Search Results' -> [(name, wire_guid_hex)] in list order.

    The realm browser is a server-pushed markup menu; each realm is a
    `<link "{GUID}">...Name...</link>` where GUID is a registry-format GUID and
    the visible name may be wrapped in extra tags (<color black> etc). We strip
    the inner tags for the name and convert the GUID to the wire form that
    build_join_realm wants. The same realm can appear in several sections
    (recent / all) — order is preserved; callers dedup as needed."""
    out = []
    for g, txt in _REALM_LINK_RE.findall(body):
        try:
            wire = realm_guid_to_wire(g.decode("latin1"))
        except (ValueError, AttributeError):
            continue
        name = re.sub(rb"<[^>]+>", b"", txt).strip().decode("latin1", "replace")
        if name:
            out.append((name, wire.hex()))
    return out


# The Hollawarp link, confirmed from a live capture (2026-08-04): a rx 0x000d
# server notice tagged "(HOLLA)" carrying `~LINK={GUID} ~TEXT="...Hollawarp"`.
# The GUID is a registry-format realm-registration GUID (joinable with 0x00d3).
_HOLLA_LINK_RE = re.compile(rb'~LINK=\{([0-9A-Fa-f-]{36})\}')
# Fallback: any bare registry-format {8-4-4-4-12} GUID anywhere in the frame.
_ANY_REG_GUID_RE = re.compile(rb'\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-'
                              rb'[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}?')


def parse_hollowarp(body):
    """Pull the realm-registration GUID out of a Hollawarp broadcast so the
    client can auto-join it (0x00d3), returning wire-hex or None.

    Confirmed layout (rx 0x000d, "(HOLLA)" tag): `~LINK={GUID} ~TEXT="..."`.
    We match ~LINK= first, then fall back to any registry GUID / realm-browser
    <link "{GUID}"> markup for robustness. None if no GUID is found."""
    m = (_HOLLA_LINK_RE.search(body) or _REALM_LINK_RE.search(body)
         or _ANY_REG_GUID_RE.search(body))
    if not m:
        return None
    try:
        return realm_guid_to_wire(m.group(1).decode("latin1")).hex()
    except (ValueError, AttributeError):
        return None


# The label the holla link is shown under IS the realm's display name.
_HOLLA_TEXT_RE = re.compile(rb'~TEXT="([^"]*)"')


def parse_hollowarp_name(body):
    """Pull the realm's DISPLAY NAME out of a Hollawarp broadcast so the client
    can re-join it by NAME (a realm-browser search + join, the way a player
    would) instead of following the raw GUID link.

    The holla notice is `~LINK={GUID} ~TEXT="Realm Name"`; ~TEXT is the clickable
    link's label, i.e. the realm name. Falls back to the text inside a
    `<link "{GUID}">Name</link>` markup tag. Returns the stripped name string,
    or None if none is present (caller then falls back to the GUID join)."""
    for m in (_HOLLA_TEXT_RE.search(body), _REALM_LINK_RE.search(body)):
        if not m:
            continue
        # the name group is the last capture (~TEXT="(name)" or <link ...>(name))
        name = re.sub(rb"<[^>]+>", b"", m.group(m.re.groups)).strip()
        if name:
            return name.decode("latin1", "replace")
    return None


def _read_guid_names(body, i, count=None):
    """Read up to `count` (or as many as parse) [16-byte GUID][u32 len][name+NUL]
    entries starting at `i`. Returns ({name: guid_hex}, next_offset)."""
    out = {}
    n_read = 0
    while i + 20 <= len(body) and (count is None or n_read < count):
        guid = body[i:i + 16]
        n = struct.unpack_from("<I", body, i + 16)[0]
        if not (1 <= n <= 40) or i + 20 + n > len(body):
            break
        s = body[i + 20:i + 20 + n].rstrip(b"\x00")
        if not (s and all(32 <= c < 127 for c in s)):
            break
        out[s.decode("latin1")] = guid.hex()
        i += 20 + n
        n_read += 1
    return out, i


def parse_friends(body):
    """rx 0x0027 friends list -> {name: guid_hex}.
    Layout: 8-byte header (27 00 | 01 00 | u32 count), then repeating entries of
    [16-byte GUID][u32 name-len][name+NUL]. The GUID comes BEFORE the name."""
    return parse_friends_full(body)[0]


def parse_friends_full(body):
    """rx 0x0027 -> (friends, pending), each {name: guid_hex}.

    After the confirmed-friends array there is a SECOND array with the same
    entry layout, prefixed by its own u32 count: the PENDING friend requests.
    A player you just sent a request to shows up there WITH THEIR GUID — which
    is how a non-friend's GUID can be resolved from a name (see the `guid`
    command in cc_client.py)."""
    count = struct.unpack_from("<I", body, 4)[0] if len(body) >= 8 else 0
    friends, i = _read_guid_names(body, 8, count)
    pending = {}
    if i + 4 <= len(body):
        pcount = struct.unpack_from("<I", body, i)[0]
        if 0 <= pcount <= 200:
            pending, _ = _read_guid_names(body, i + 4, pcount)
    return friends, pending


def parse_online_friends(body):
    """rx 0x0088 -> list of online friend GUIDs as lowercase hex strings.

    Layout: u16 type, u16 stage, u32 count, then ``count`` raw 16-byte GUIDs.
    """
    if len(body) < 8 or body_type(body) != 0x0088:
        return []
    count = struct.unpack_from("<I", body, 4)[0]
    if count > 1000 or len(body) < 8 + count * 16:
        return []
    return [body[i:i + 16].hex()
            for i in range(8, 8 + count * 16, 16)]


# ---- world objects: the blocks a realm is built from -------------------------
#
# rx 0x000f carries the realm's placed objects as a flat array of fixed records
# (no compression, no voxel grid — a realm IS this list). rx 0x0021 is the same
# thing in a compact form, count-prefixed.
#
#   0x000f:  [u16 type][u16 0x0001] then N x 70-byte records
#   0x0021:  [u16 type][u16 0x0001][u32 count] then count x 44-byte records
#
#   record:  guid(16) | kind(1) | X(u32 block, u32 sub) Y(..) Z(..)
#            0x000f only: the same three coordinates repeated
#            u16 type_id | 01 | 00 | flag        (0x0021 tail is 3 bytes)
#
# Coordinates use the same split as everything else: block index + sub-position
# below COORD_BASE. 99% of objects sit exactly on the grid (sub == 0).
# `kind` groups them: 2 = the bulk of build blocks, 1 / 5 / 6 = smaller sets
# (props, plants, special blocks — meaning not yet pinned down).
#
# The two sources are NOT the same catalogue: 0x000f type ids run to ~2000 (the
# block catalogue), while 0x0021 ids are a small enum (0-3) over different kinds
# (0, 3, 4, 10, 12) — functional objects rather than build blocks. Each parsed
# object carries `src` so the two are never pooled.

def _read_object(rec, wide):
    c = struct.unpack_from("<6I", rec, 17)
    if wide:                       # 70-byte record: coords repeated, 5-byte tail
        type_id, _one, _zero, flag = struct.unpack_from("<HBBB", rec, 65)
    else:                          # 44-byte record: 3-byte tail
        type_id, flag = struct.unpack_from("<HB", rec, 41)
    return {"guid": rec[:16].hex(), "kind": rec[16],
            "bx": c[0], "by": c[2], "bz": c[4],
            "x": dec_coord(c[0], c[1]), "y": dec_coord(c[2], c[3]),
            "z": dec_coord(c[4], c[5]),
            "type_id": type_id, "flag": flag}


def parse_world_objects(body):
    """rx 0x000f or rx 0x0021 -> list of world-object dicts (see above).
    Returns [] if the body isn't one of those or doesn't divide evenly."""
    t = body_type(body)
    if t == 0x000f:
        size, start, wide = 70, 4, True
    elif t == 0x0021:
        size, start, wide = 44, 8, False
    else:
        return []
    payload = body[start:]
    if not payload or len(payload) % size:
        return []
    out = []
    for i in range(0, len(payload), size):
        o = _read_object(payload[i:i + size], wide)
        o["src"] = t            # type_id means different things per source
        out.append(o)
    return out


def parse_inventory(body):
    """rx 0x000e (the big form, >100 bytes) — the player's inventory.

        0e 00 | 01 00 | player guid(16) | u8 ? | u8 count | count x [u8 flag]
        [u16 item_id][u16 qty] | trailer (u32 fields + realm/owner text)

    Verified on capture 000932: dropping and re-picking an item appended
    exactly one 5-byte record (flag 1, id 769, qty 1) and bumped the count
    53 -> 54, with the array still ending exactly at the trailer.

    Note tx 0x000e is a different message (the realm check-in, build_enter);
    only the large inbound form is an inventory.
    """
    if len(body) < 30 or body_type(body) != 0x000e:
        return None
    count = body[21]
    items, off = [], 22
    for _ in range(count):
        if off + 5 > len(body):
            return None
        flag = body[off]
        item_id, qty = struct.unpack_from("<HH", body, off + 1)
        items.append({"slot": len(items), "flag": flag,
                      "item_id": item_id, "qty": qty})
        off += 5
    return {"guid": body[4:20].hex(), "items": items, "end": off}


def build_block_query(bx, by, bz):
    """tx 0x0014 — ask what object occupies a block. The server answers with
    rx 0x0014 = the same coordinates + that block's 16-byte GUID + a byte.
    Coordinates are plain block indices (u32), not the block/sub split."""
    return w_u16(0x0014) + w_u32(bx) + w_u32(by) + w_u32(bz)


def parse_block_query_reply(body):
    """rx 0x0014 -> {bx, by, bz, kind, guid, text, short}.

        14 00 | 01 00 | u32 bx | u32 by | u32 bz | u8 kind [| guid(16)]
        [ u32 len | text ]      <- only when the object has a description

    The optional text is how a VENDING MACHINE reports itself, e.g.
    "Your Vending Machine has 0 Cubits in it and costs 3000 Cubits."
    (kind 0x00 carried the text; kind 0x15 replies were the bare 33-byte form).
    Some occupied blocks use a 19-byte acknowledgement with only the coordinates
    and three trailing bytes.  It is still positive occupancy evidence and must
    not be discarded as if the server stayed silent; ``guid`` is ``None`` there.
    """
    if body_type(body) != 0x0014 or len(body) < 17:
        return None
    bx, by, bz = struct.unpack_from("<3I", body, 4)
    short = len(body) < 33
    out = {"bx": bx, "by": by, "bz": bz, "kind": body[16],
           "guid": None if short else body[17:33].hex(),
           "text": None, "short": short}
    if len(body) > 37:
        n = struct.unpack_from("<I", body, 33)[0]
        if 0 < n <= len(body) - 37:
            out["text"] = body[37:37 + n].rstrip(b"\x00").decode("utf-8", "replace")
    return out


def build_use_object(guid):
    """tx 0x010f — use/open the world object with this GUID. On a vending
    machine the server answers with the purchase dialog (rx 0x00ca)."""
    if isinstance(guid, str):
        guid = bytes.fromhex(guid)
    return w_u16(0x010f) + guid


def parse_dialog(body):
    """rx 0x00ca — a server-driven confirmation dialog:

        ca 00 | 01 00 | dialog guid(16) | u32 len | title | u32 len | text

    A vending machine's purchase prompt spells out the goods in plain text:
    "Are you sure you want to buy 1 Drop Scaffold item(s) for 3000 Cubits?"
    -> {guid, title, text}. See parse_vending_offer() for the parsed fields.
    """
    if body_type(body) != 0x00ca or len(body) < 24:
        return None
    r = Reader(body)
    r.u16(); r.u16()
    guid = body[r.p:r.p + 16]; r.p += 16
    try:
        title = r.s()
        text = r.s()
    except Exception:
        return None
    return {"guid": guid.hex(), "title": title, "text": text}


def build_dialog_response(guid, confirm):
    """tx 0x00ca + dialog guid + 1 byte: 1 = confirm, 0 = cancel.

    WARNING: confirming a vending-machine dialog SPENDS CURRENCY. Only send
    with confirm=True when a purchase is actually intended."""
    if isinstance(guid, str):
        guid = bytes.fromhex(guid)
    return w_u16(0x00ca) + guid + bytes([1 if confirm else 0])


# --------------------------------------------------------------------------
# Plot / rental "bumper" (Stage 13). Decoded 2026-08-20 from
# capture-20260820-111921-bumper. Hitting a bumper block pops a rent dialog:
#   tx 0x00d9 (the player's CURRENT position) then tx 0x00d7 (the target bumper
#   block) -> the server answers with rx 0x00ca, the SAME confirm dialog used
#   for vending (parse_dialog / build_dialog_response already handle it).
# Both trigger frames mirror the real client byte-for-byte. Whether 0x00d7 alone
# suffices, and whether the server range-gates the hit (must be near the
# bumper), is verified live with the `bumphit` test command before any auto-rent
# loop is allowed to stake Cubits.  See memory: cubic-castles-plot-bumper.
# --------------------------------------------------------------------------
BUMP_FACING = 179          # facing word the capture carried; the trigger seems
                           # indifferent to it — kept for a faithful replay.


def build_bump_pos(x, y, z, facing=BUMP_FACING):
    """tx 0x00d9 — the position half of a bumper hit: the player's CURRENT fine
    position + facing, in the same high*100000+low coord split as MOVE (0x0006).
    34-byte layout, byte-exact vs capture-20260820-111921-bumper."""
    xh, xl = enc_coord(x); yh, yl = enc_coord(y); zh, zl = enc_coord(z)
    body = (w_u16(0x00d9) +
            w_u32(xh) + w_u32(xl) +
            w_u32(yh) + w_u32(yl) +
            w_u32(zh) + w_u32(zl) +
            w_u32(int(facing) % 360) + w_u32(10000))
    assert len(body) == 34, len(body)
    return body


def build_bump_hit(bx, by, bz):
    """tx 0x00d7 — the "hit THIS bumper block" half: the target block indices,
    each as (block, 0) in the coord split (low is always 0). 28-byte layout,
    byte-exact vs the capture (block 46,12,93). Send right after build_bump_pos;
    the server answers with the rent dialog (rx 0x00ca)."""
    body = (w_u16(0x00d7) +
            w_u32(bx) + w_u32(0) +
            w_u32(by) + w_u32(0) +
            w_u32(bz) + w_u32(0) +
            bytes([0x00, 0x01]))
    assert len(body) == 28, len(body)
    return body


_BUMP_TIME_RE = re.compile(r"(\d{1,2}):(\d{2}):(\d{2})\s+left")


def classify_rent_dialog(title, text):
    """Classify a rx 0x00ca dialog (title + text from parse_dialog) as a plot
    bumper prompt. Returns {kind, seconds_left, owner} where kind is:
      available      - empty plot, rentable NOW (offers to rent, names no renter)
                       -> the only kind that is safe to confirm (YES rents/spends)
      occupied_other - rented by someone else ("HH:MM:SS left in this area rented
                       by <name>."; OKAY only) -> keep waiting
      occupied_self  - already rented by us ("...rented by <you>. ...rent
                       again?") -> skip, do not re-rent our own plot
      not_bumper     - some other 0x00ca dialog (vending / trade / ...)
    """
    t = text or ""
    low = t.lower()
    rented_by = "left in this area rented by" in low
    offers_rent = "rent this area" in low
    secs = None
    m = _BUMP_TIME_RE.search(t)
    if m:
        hh, mm, ss = (int(g) for g in m.groups())
        secs = hh * 3600 + mm * 60 + ss
    owner = None
    om = re.search(r"rented by ([^.]+)\.", t)
    if om:
        owner = om.group(1).strip()
    if rented_by:
        return {"kind": "occupied_self" if offers_rent else "occupied_other",
                "seconds_left": secs, "owner": owner}
    if offers_rent:
        return {"kind": "available", "seconds_left": None, "owner": None}
    return {"kind": "not_bumper", "seconds_left": None, "owner": None}


# --------------------------------------------------------------------------
# Prize machine / Password Sentry (Stage 12). Decoded 2026-08-17 from
# capture-20260817-165823 (own machine, password "7391"). See PRIZE.md.
#
# Opening the "WHAT'S THE PASSWORD?" box is CLIENT-SIDE ONLY — no server
# message. The server only hears the guess, and ties it to whatever Password
# Sentry the player is standing at (there is NO machine GUID in the submit).
# --------------------------------------------------------------------------

def build_password_guess(text):
    """tx 0x0040 — submit one password guess to the Password Sentry the player
    is currently standing at. Length-prefixed string, same encoding as chat
    (u32 length INCLUDING the NUL). Verified byte-exact vs capture 165823:
    guess "3257" -> `4000 05000000 33323537 00`, "7391" -> `4000 ...37333931 00`.
    No GUID: the server resolves the machine by proximity/interaction context."""
    return w_u16(0x0040) + w_str(str(text))


def parse_wrong_password(body):
    """rx 0x0036 — the "Wrong Password!" rejection dialog. SAME title/body shape
    as parse_dialog(0x00ca), but 0x0036 is REUSED by trades ('Trade Pending'),
    so callers must key on the title. Returns {title, text} only when the title
    is the wrong-password one, else None.

        36 00 | 01 00 | u32 len | title NUL | u32 len | body NUL
        title = "Wrong Password!", body = "You typed in a bad password.  Nice try."
    """
    if body_type(body) != 0x0036 or len(body) < 8:
        return None
    r = Reader(body)
    r.u16(); r.u16()
    try:
        title = r.s()
        text = r.s()
    except Exception:
        return None
    if "password" not in title.lower():
        return None
    return {"title": title, "text": text}


def build_claim_prize(guid):
    """tx 0x00d6 — claim/dispense the prize from a Prize Dispenser after a
    CORRECT password. On a right guess the server does NOT reply with 0x0036;
    it sends rx 0x0014 (a block-query-shaped reply) carrying the DISPENSER
    object's guid, and the client must send this to actually dispense. The
    server then drops the prize as kind-1 world object(s) to pick up (tx 0x0010).
    Verified in capture 165823: dispenser guid c2a0dd...945d -> prize dropped."""
    if isinstance(guid, str):
        guid = bytes.fromhex(guid)
    return w_u16(0x00d6) + guid


# --------------------------------------------------------------------------
# Two-player TRADE (Stage 10). Decoded 2026-08-15 from a real 169-cubit deposit
# (see TRADE.md). The trade GUID (16 bytes) keys every message of one trade.
# --------------------------------------------------------------------------

def parse_trade_request(body):
    """rx 0x00a8 — another player opened a trade with us:

        a8 00 | 01 00 | u32 len + name+NUL | trade_guid(16) |
        their_player_guid(16) | token(16)

    Returns {name, trade_guid, their_guid, token} (guids hex), or None."""
    if body_type(body) != 0x00a8:
        return None
    r = Reader(body)
    r.u16(); r.u16()
    try:
        name = r.s()
    except Exception:
        return None
    if len(body) - r.p < 16:
        return None
    trade_guid = body[r.p:r.p + 16]; r.p += 16
    their = body[r.p:r.p + 16] if len(body) - r.p >= 16 else b""
    r.p += 16
    token = body[r.p:r.p + 16] if len(body) - r.p >= 16 else b""
    return {"name": name, "trade_guid": trade_guid.hex(),
            "their_guid": their.hex(), "token": token.hex()}


def parse_trade_offer(body):
    """rx 0x00ae — the current stake on the table:

        ae 00 | 01 00 | trade_guid(16) | u32 our_cubits | u32 their_cubits | u8 flag

    `their_cubits` is what the other player has put in — the DEPOSIT amount.
    Returns {trade_guid, our_cubits, their_cubits, flag}, or None."""
    if body_type(body) != 0x00ae or len(body) < 20:
        return None
    r = Reader(body)
    r.u16(); r.u16()
    trade_guid = body[r.p:r.p + 16]; r.p += 16
    our = their = 0
    flag = None
    try:
        if len(body) - r.p >= 4:
            our = r.u32()
        if len(body) - r.p >= 4:
            their = r.u32()
        if len(body) - r.p >= 1:
            flag = body[r.p]
    except Exception:
        return None
    return {"trade_guid": trade_guid.hex(), "our_cubits": our,
            "their_cubits": their, "flag": flag}


def parse_trade_accept_state(body):
    """Parse the server's compact rx 0x00a9 acceptance-state broadcast.

        a9 00 | 01 00 | trade_guid(16) | u8 state

    Live traffic shows state 0 when the trade is not currently accepted. The
    game uses this packet to change the button from ``Accepted!`` through its
    deciding animation and back to ``Accept Trade`` without changing Cubits.
    """
    if body_type(body) != 0x00a9 or len(body) < 21:
        return None
    return {"trade_guid": body[4:20].hex(), "state": body[20]}


def parse_trade_close(body):
    """rx 0x00ac — a trade window closed: `ac 00 | 01 00 | trade_guid(16)`.
    Returns {trade_guid} (all-zero guid = the window fully closed), or None."""
    if body_type(body) != 0x00ac or len(body) < 20:
        return None
    return {"trade_guid": body[4:20].hex()}


# A trade click is not a vending-dialog response. Capture 20260815-171804 shows
# that the three state sends associated with the two visible buttons produce a
# 31-byte body. The trade window opens without a bot send. Clicking ACCEPT emits
# the first state; clicking YES is followed by CONFIRM and COMMIT states. The
# best-fitting empty-offer layout is:
#
#   a9 00 | trade_guid(16) | 4 x u16 offered slots | u32 our_cubits | u8 state
#
# Unlike receive messages, client->server messages do not carry the 01 00 server
# marker. State values still need one minimal live probe, so the client keeps a
# few complete three-state profiles below.
TRADE_PHASES = ("accept", "confirm", "commit")


def build_trade_state(trade_guid, state, our_cubits=0, item_slots=None):
    """Build one 31-byte tx 0x00a9 trade-state update.

    Auto-deposits leave all four offered slots and ``our_cubits`` at zero. That
    makes every generated candidate receive-only: it cannot offer the bot's
    inventory or wallet to the other player. The layout is a strong inference
    from the captured official frames and remains guarded in ``cc_client``.
    """
    if isinstance(trade_guid, str):
        trade_guid = bytes.fromhex(trade_guid)
    if len(trade_guid) != 16:
        raise ValueError("trade_guid must be exactly 16 bytes")
    if not 0 <= int(state) <= 0xFF:
        raise ValueError("trade state must fit in one byte")
    if not 0 <= int(our_cubits) <= 0xFFFFFFFF:
        raise ValueError("our_cubits must fit in a u32")
    slots = tuple(item_slots if item_slots is not None else (0, 0, 0, 0))
    if len(slots) != 4 or any(not 0 <= int(slot) <= 0xFFFF for slot in slots):
        raise ValueError("item_slots must contain exactly four u16 values")
    return (w_u16(0x00a9) + trade_guid +
            b"".join(w_u16(int(slot)) for slot in slots) +
            w_u32(int(our_cubits)) + bytes([int(state)]))


def trade_accept_candidates(trade_guid, their_guid="", token="", our_cubits=0,
                            phase="accept"):
    """Return the proven empty-side packet(s) for one phase of the trade flow.

    PROVEN 2026-08-15 from a two-client --plaintext capture (the framer hook dumped
    the outgoing bytes BEFORE encryption, so no send-cipher was needed). Both
    players sent EXACTLY two clicks with an identical, simple shape:

        ACCEPT  (click "Accept Trade") : aa 00 | trade_guid(16) | 01
        CONFIRM (click "YES")          : ca 00 | trade_guid(16) | 01

    There is NO third "commit" message, and client->server messages carry NO
    ``01 00`` marker (that marker is receive-side only). Earlier probing failed
    because it used 0x00a9 (which is only the server's RX accept-STATE broadcast,
    never a client send) and often prepended the 01 00 marker.

    SAFETY: neither message references a cubit amount or item slot, so the bot's
    side always stays empty — it can only receive a deposit, never give anything
    away. Returned as a one-item ranked list for API compatibility.
    """
    g = bytes.fromhex(trade_guid) if isinstance(trade_guid, str) else trade_guid
    if phase == "accept":
        return [("proven_aa", w_u16(0x00aa) + g + b"\x01")]
    if phase == "confirm":
        return [("proven_aa", w_u16(0x00ca) + g + b"\x01")]
    if phase == "commit":
        return [("proven_aa", b"")]         # no real commit message exists
    raise ValueError(f"unknown trade phase {phase!r}")


def build_trade_accept(trade_guid, their_guid="", token="", phase="accept"):
    """Build the proven empty-side action for one trade click (see
    trade_accept_candidates)."""
    return trade_accept_candidates(trade_guid, their_guid, token,
                                   phase=phase)[0][1]


def build_trade_offer(trade_guid, cubits):
    """Stake `cubits` from OUR side of a trade — the withdrawal/payout direction.

        ae 00 | trade_guid(16) | u32 cubits          (no 01 00 marker; send-side)

    Format taken from the 2026-08-15 two-client --plaintext capture (a real player
    staked cubits with exactly this shape). DANGER: this GIVES cubits away — callers
    must gate it to a player's own authorised withdrawal and re-check the server's
    echoed offer before confirming (see cc_client withdrawal flow)."""
    g = bytes.fromhex(trade_guid) if isinstance(trade_guid, str) else trade_guid
    if not 0 <= int(cubits) <= 0xFFFFFFFF:
        raise ValueError("cubits must fit in a u32")
    return w_u16(0x00ae) + g + w_u32(int(cubits))


def build_open_register(bx, by, bz):
    """tx 0x00a4 — OPEN a cash register at a block. Decoded 2026-08-16 from the
    register capture: clicking a register sends this, and the server answers with
    a trade request (rx 0x00a8) from the shop owner — the register 'menu' IS a
    two-player trade. Coords are the block's (high, low) u32 pairs, exactly like
    build_move; a register sits on-grid so the low halves are 0.

        a4 00 | u32 bx_hi | u32 bx_lo | u32 by_hi | u32 by_lo | u32 bz_hi | u32 bz_lo

    NB: this INITIATES A TRADE with the owner. Pair every send with a prompt
    build_trade_cancel() unless a real trade is intended."""
    xh, xl = enc_coord(bx * COORD_BASE)      # accept a plain block index
    yh, yl = enc_coord(by * COORD_BASE)
    zh, zl = enc_coord(bz * COORD_BASE)
    return (w_u16(0x00a4) +
            w_u32(xh) + w_u32(xl) +
            w_u32(yh) + w_u32(yl) +
            w_u32(zh) + w_u32(zl))


def build_trade_cancel(trade_guid):
    """tx 0x00ab + trade_guid(16) — cancel/close a trade. Decoded 2026-08-16:
    closing a register menu sent exactly this and the server echoed rx 0x00ab.
    Sends nothing of value, so it is always safe to fire to back out of a trade."""
    g = bytes.fromhex(trade_guid) if isinstance(trade_guid, str) else trade_guid
    return w_u16(0x00ab) + g


# type ids confirmed to sit on a vending machine's block. Seeded from live
# scans (438 = Mannequin machine, 543 = the Drop Scaffold machine); cc_client
# appends to its own machine_types.json as scans confirm more.
# 438 is the only id proven to be the machine itself (capture 002035); 543 was
# in here by mistake — that is Drop Scaffold, the goods it was holding. Nothing
# selects machines by id any more, so treat this as a note, not a filter.
MACHINE_TYPE_IDS = {438}


# The GLASS CASE (a.k.a. display case) is the one block that holds a shown item.
# Proven in capture 20260805-231653: an empty case is a single 0x000f object with
# type_id 1113; stocking it makes the displayed item appear as a SECOND 0x000f
# object stacked on the SAME block. The item's world type_id == its inventory
# item_id (same numbering: the case was inventory id 1113, the item id 521, and
# both left inventory when placed), so a displayed item is fully identified by its
# type_id and named by the same oracle as inventory. Add more display-furniture
# type_ids here if other case variants turn up.
GLASS_CASE_TYPE_IDS = {1113}


MANNEQUIN_TYPE_ID = 438


def build_query_object(guid):
    """tx 0x000e + object guid — ask the server for a display object's CONTENTS.
    Same wire as build_enter (the realm check-in), but addressed to a world
    object's guid instead of the realm/own guid: the server replies rx 0x000e
    (the inventory form) listing what is IN/ON that object. This is how the game
    reads a MANNEQUIN's outfit — click it, and the worn items come back as slots.
    A pure read: no dialog, no purchase, nothing spent (solved capture 102217)."""
    return build_enter(guid)


def worn_items(inv):
    """From a parse_inventory() result for a mannequin query reply, return the
    filled slots as [(item_id, qty)] — dropping the empty slots (id 0). A
    mannequin has a fixed slot count; empty wardrobe slots come through as id 0."""
    if not inv:
        return []
    return [(it["item_id"], it["qty"]) for it in inv["items"] if it["item_id"]]


def realm_inventory(objects, include_offgrid=False):
    """A realm's whole on-display inventory, aggregated by item.

    Everything a realm shows off — items in glass, dressed on mannequins, on
    pedestals or open shelves — rides the wire as ordinary PLACED OBJECTS in the
    0x000f / 0x0021 stream (the glass/mannequin furniture itself is a building
    block and, like terrain and signs, is NOT in the stream). So the realm's
    displayed collection is simply its placed objects, and since world type_id ==
    inventory item_id, each is a real item id.

    Proven on Example's Collection (capture-adjacent dump 20260805-232940):
    789 placed objects / 395 distinct ids, largest stack only 28 — i.e. the
    stream is the collection, not walls and floors.

    Returns {"total": N, "distinct": M, "counts": {type_id: count}} where a stack
    of the same id on one display counts once per object (how many are shown).
    Grid-aligned only unless include_offgrid (off-grid = items dropped on the
    floor). This is a pure read — nothing is sent."""
    counts = {}
    total = 0
    for o in objects:
        if not include_offgrid and (o.get("x", 0) % COORD_BASE
                                    or o.get("y", 0) % COORD_BASE):
            continue
        counts[o["type_id"]] = counts.get(o["type_id"], 0) + 1
        total += 1
    return {"total": total, "distinct": len(counts), "counts": counts}


def find_glass_displays(objects, glass_ids=GLASS_CASE_TYPE_IDS):
    """Passively read a realm's glass-case inventory from its world objects.

    `objects` is any iterable of parsed world-object dicts (parse_world_objects
    output — the 0x000f / 0x0021 stream). Groups them by grid-aligned block and,
    for every block holding a glass case, reports the OTHER object(s) on that
    block as the item(s) on display. Nothing is sent — this is a pure read.

        [ { "block": (bx, by, bz),
            "cases": <how many case objects on the block>,
            "items": [ { "type_id", "guid", "kind" }, ... ],   # empty = empty case
            "stocked": bool } , ... ]

    A block with a case and no other object is an empty case (stocked=False)."""
    by_block = {}
    for o in objects:
        # off-grid objects are dropped items lying on the floor, not placed
        if o.get("x", 0) % COORD_BASE or o.get("y", 0) % COORD_BASE:
            continue
        by_block.setdefault((o["bx"], o["by"], o["bz"]), []).append(o)

    out = []
    for block, objs in by_block.items():
        cases = [o for o in objs if o["type_id"] in glass_ids]
        if not cases:
            continue
        items = [{"type_id": o["type_id"], "guid": o["guid"], "kind": o["kind"]}
                 for o in objs if o["type_id"] not in glass_ids]
        out.append({"block": block, "cases": len(cases),
                    "items": items, "stocked": bool(items)})
    out.sort(key=lambda r: r["block"])
    return out


_VEND_RE = re.compile(
    r"buy\s+(\d+)\s+(.+?)\s+item\(s\)\s+for\s+([\d,]+)\s+(\w+)", re.I)
_MACHINE_RE = re.compile(
    r"has\s+([\d,]+)\s+(\w+)\s+in it and costs\s+([\d,]+)\s+(\w+)", re.I)


def parse_vending_offer(text):
    """Pull the structured offer out of a vending machine's text.

    Handles both the machine description ("... has 0 Cubits in it and costs
    3000 Cubits.") and the purchase prompt ("... buy 1 Drop Scaffold item(s)
    for 3000 Cubits?"). Returns {item, qty, price, currency, stock} with
    whatever the text supplied, or None."""
    if not text:
        return None
    m = _VEND_RE.search(text)
    if m:
        return {"item": m.group(2).strip(), "qty": int(m.group(1)),
                "price": int(m.group(3).replace(",", "")),
                "currency": m.group(4), "stock": None}
    m = _MACHINE_RE.search(text)
    if m:
        return {"item": None, "qty": None,
                "price": int(m.group(3).replace(",", "")),
                "currency": m.group(4),
                "stock": int(m.group(1).replace(",", ""))}
    return None


def build_block_interact(bx, by, bz):
    """tx 0x000a — interact with (click) the block at these indices. The server
    echoes rx 0x000a = actor guid + the u16 coordinates."""
    return w_u16(0x000a) + w_u32(bx) + w_u32(by) + w_u32(bz)


def build_pickup(guid):
    """tx 0x0010 — pick up the world object with this GUID (confirmed: sent
    right after a drop, server echoes rx 0x0010 with the same guid)."""
    if isinstance(guid, str):
        guid = bytes.fromhex(guid)
    return w_u16(0x0010) + guid


def parse_realm_id(body):
    """rx 0x005f — sent on every realm entry (login AND after a teleport
    handoff): type + 0x0001 + lenpfx realm name + lenpfx owner name.
    Confirmed across 7 captures ('New Eden'/'SirKewberth',
    \"botname's Collection\"/'Example', ...). Returns {realm, owner} or None."""
    try:
        r = Reader(body)
        if r.u16() != 0x005f:
            return None
        r.u16()
        return {"realm": r.s(), "owner": r.s()}
    except Exception:
        return None


def parse_backend_handoff(body):
    """rx 0x0019 -> (host, port)."""
    r = Reader(body)
    assert r.u16() == 0x0019
    r.u16()               # field
    host = r.s()
    port = r.u16()
    return host, port


def build_post_login(response):
    """POST_LOGIN (tx 0x0004) echoes a 16-byte value the server put in the login
    response, 32 bytes past the echoed name/account strings. Sending it triggers
    the server to push the full world data incl. the friends list (rx 0x0027).
    Returns the body bytes, or None if it can't be located."""
    try:
        r = Reader(response)
        r.u16(); r.u16(); r.s(); r.s()      # type, stage, name, account
        off = r.p + 32
        val = response[off:off + 16]
        if len(val) != 16:
            return None
        return w_u16(0x0004) + val
    except Exception:
        return None


def parse_login_response(body):
    """rx 0x0002 -> dict with echoed identity and the raw session-info blob.
    The 16-byte XXTEA key lives inside info_blob (offset varies); a real client
    parses the blob's fields to locate it. We expose the blob for extraction."""
    r = Reader(body)
    assert r.u16() == 0x0002
    stage = r.u16()
    name = r.s()
    acct = r.s()
    blob = r.rest()
    return {"stage": stage, "name": name, "account_id": acct, "info_blob": blob}

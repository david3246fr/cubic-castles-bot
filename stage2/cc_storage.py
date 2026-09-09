#!/usr/bin/env python3
"""
Cubic Castles market history — SQLite storage (Stage 5).

The vending scanner in cc_client.py used to keep the whole market in a single
JSON file (vends.json) keyed by realm NAME, where a rescan simply replaced that
realm's entry.  That has two problems: names are not stable identifiers (a realm
can be renamed or re-hosted, and names collide — 'shop'/'SHOP'/'Shop' are three
different realms), and every replaced listing was lost forever.

This module keeps the SAME idea of a *current* catalogue (rescanning a realm
replaces its current listings) but stores it in SQLite, keyed by realm and
machine GUID, and it ALSO retains every observation and every removal/price/item
change as history you can query.

Design rules (see MARKET_DB.md):
  * Realms and machines are identified by GUID, never by name.
  * A COMPLETED scan is authoritative: it replaces the realm's current listings
    and removes current listings for machines that were not seen.  A partial /
    interrupted / timed-out / failed scan updates only what it saw and NEVER
    removes an unseen listing.
  * Every observation is appended to offer_history; current_offers only points
    at the latest.  Nothing is ever deleted from history.
  * Foreign keys on, WAL journal, a busy timeout, UTC ISO-8601 timestamps,
    every statement parameterised.

Nothing here connects to the game.  It is pure local persistence, safe to run
and test offline.

CLI:
    py cc_storage.py init [--db PATH]
    py cc_storage.py migrate-json --vends vends.json --realms realms.json \
        [--watchlist watchlist.json] [--names names.json] [--dry-run] [--db PATH]
    py cc_storage.py import-names --names names.json [--db PATH]
    py cc_storage.py export-current --out vends-current.json [--db PATH]
    py cc_storage.py stats [--db PATH]
    py cc_storage.py backup --out backups/market.db [--force] [--db PATH]
"""
import argparse
import json
import os
import re
import sqlite3
import statistics
import threading
from datetime import datetime, timezone

SCHEMA_VERSION = 1

# Default DB lives next to this module, alongside vends.json.
DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "cubic_market.db")

# A scan is only authoritative enough to REMOVE unseen current listings when it
# ran to completion.  Every other outcome preserves the previous catalogue.
AUTHORITATIVE_STATUS = "completed"
VALID_STATUSES = {"completed", "partial", "interrupted", "timed_out", "failed"}

# Event types recorded in offer_events.
EV_ADDED = "added"
EV_PRICE = "price_changed"
EV_ITEM = "item_changed"
EV_QTY = "quantity_changed"
EV_STOCK = "stock_changed"
EV_UNCHANGED = "unchanged"
EV_REMOVED = "removed"
EV_REAPPEARED = "reappeared"


def utcnow_iso():
    """Current UTC time as an ISO-8601 string, second precision."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- item-name normalisation ------------------------------------------------
# Same general idea the price bot uses: lowercase, drop punctuation, collapse
# whitespace, trim.  Word separators (- and /) become spaces so 'Black-Halo'
# reads as two words; other punctuation (apostrophes, quotes, ?, !) is deleted
# so "Cupid's Halo" -> "cupids halo".
_SEP_RE = re.compile(r"[-/]+")
_DROP_RE = re.compile(r"[^a-z0-9\s]")
_WS_RE = re.compile(r"\s+")


def normalize_item(name):
    """Normalise a vending item name for matching.

    'Cupid\\'s Halo' -> 'cupids halo'; 'CUPIDS  HALO' -> 'cupids halo';
    'Black-Halo' -> 'black halo'.  Returns '' for empty/None input."""
    if not name:
        return ""
    s = str(name).lower()
    s = _SEP_RE.sub(" ", s)
    s = _DROP_RE.sub("", s)
    s = _WS_RE.sub(" ", s).strip()
    return s


class MarketDB:
    """A SQLite-backed store of the current market plus its full history.

    Safe to share one instance across threads: every public method takes an
    internal lock and uses its own cursor (a cursor is never shared between
    threads).  Open once, call close() (or use it as a context manager) when
    done."""

    def __init__(self, path=DEFAULT_DB_PATH, timeout=30.0):
        self.path = path
        self._lock = threading.RLock()
        d = os.path.dirname(os.path.abspath(path))
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        # check_same_thread=False + our own lock: the client's reader thread and
        # the command thread both touch the DB.  WAL + serialising through the
        # lock keeps that safe without sharing a cursor.
        self._conn = sqlite3.connect(path, timeout=timeout,
                                     check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._configure()
        self._init_schema()

    # -- lifecycle ----------------------------------------------------------
    def _configure(self):
        c = self._conn
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA busy_timeout=30000")

    def close(self):
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.commit()
                finally:
                    self._conn.close()
                    self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # -- schema -------------------------------------------------------------
    def _init_schema(self):
        """Create every table/index if missing.  Idempotent: safe to call on an
        existing database, and re-running never changes data."""
        with self._lock:
            cur = self._conn.cursor()
            cur.executescript("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS realms (
                guid          TEXT PRIMARY KEY,
                name          TEXT,
                owner         TEXT,
                link          TEXT,
                first_seen_at TEXT,
                last_seen_at  TEXT
            );

            CREATE TABLE IF NOT EXISTS machines (
                guid          TEXT PRIMARY KEY,
                realm_guid    TEXT,
                x             INTEGER,
                y             INTEGER,
                z             INTEGER,
                first_seen_at TEXT,
                last_seen_at  TEXT,
                FOREIGN KEY (realm_guid) REFERENCES realms(guid)
            );

            CREATE TABLE IF NOT EXISTS items (
                id               INTEGER PRIMARY KEY,
                normalized_name  TEXT UNIQUE,
                display_name     TEXT,
                protocol_item_id INTEGER
            );

            CREATE TABLE IF NOT EXISTS item_aliases (
                normalized_alias TEXT PRIMARY KEY,
                item_id          INTEGER,
                FOREIGN KEY (item_id) REFERENCES items(id)
            );

            -- id -> name table from the game (names.json), used to assign a
            -- protocol_item_id to an item ONLY when the normalised name matches
            -- exactly one game item.  Ambiguous names stay unmapped.
            CREATE TABLE IF NOT EXISTS protocol_names (
                protocol_item_id INTEGER PRIMARY KEY,
                normalized_name  TEXT,
                display_name     TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_sessions (
                id               INTEGER PRIMARY KEY,
                realm_guid       TEXT,
                started_at       TEXT,
                completed_at     TEXT,
                status           TEXT,
                source           TEXT,
                offers_found     INTEGER,
                probes_attempted INTEGER,
                probes_answered  INTEGER,
                error            TEXT,
                FOREIGN KEY (realm_guid) REFERENCES realms(guid)
            );

            CREATE TABLE IF NOT EXISTS offer_history (
                id                 INTEGER PRIMARY KEY,
                scan_id            INTEGER,
                machine_guid       TEXT,
                item_id            INTEGER,
                original_item_name TEXT,
                quantity           INTEGER,
                price              INTEGER,
                currency           TEXT,
                stock              INTEGER,
                observed_at        TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_sessions(id),
                FOREIGN KEY (machine_guid) REFERENCES machines(guid),
                FOREIGN KEY (item_id) REFERENCES items(id)
            );

            CREATE TABLE IF NOT EXISTS current_offers (
                machine_guid TEXT PRIMARY KEY,
                history_id   INTEGER,
                updated_at   TEXT,
                FOREIGN KEY (machine_guid) REFERENCES machines(guid),
                FOREIGN KEY (history_id) REFERENCES offer_history(id)
            );

            CREATE TABLE IF NOT EXISTS offer_events (
                id             INTEGER PRIMARY KEY,
                scan_id        INTEGER,
                machine_guid   TEXT,
                event_type     TEXT,
                old_history_id INTEGER,
                new_history_id INTEGER,
                created_at     TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_sessions(id),
                FOREIGN KEY (machine_guid) REFERENCES machines(guid)
            );

            -- Optional mirror of watchlist.json so the importer can move it into
            -- SQLite without the client having to change its own persistence.
            CREATE TABLE IF NOT EXISTS watchlist (
                realm_guid TEXT PRIMARY KEY,
                name       TEXT,
                owner      TEXT,
                link       TEXT,
                added_at   TEXT
            );

            CREATE INDEX IF NOT EXISTS ix_machines_realm
                ON machines(realm_guid);
            CREATE INDEX IF NOT EXISTS ix_items_protocol
                ON items(protocol_item_id);
            CREATE INDEX IF NOT EXISTS ix_protonames_norm
                ON protocol_names(normalized_name);
            CREATE INDEX IF NOT EXISTS ix_hist_machine
                ON offer_history(machine_guid);
            CREATE INDEX IF NOT EXISTS ix_hist_item
                ON offer_history(item_id);
            CREATE INDEX IF NOT EXISTS ix_hist_price
                ON offer_history(price);
            CREATE INDEX IF NOT EXISTS ix_hist_currency
                ON offer_history(currency);
            CREATE INDEX IF NOT EXISTS ix_hist_observed
                ON offer_history(observed_at);
            CREATE INDEX IF NOT EXISTS ix_hist_scan
                ON offer_history(scan_id);
            CREATE INDEX IF NOT EXISTS ix_events_machine
                ON offer_events(machine_guid);
            CREATE INDEX IF NOT EXISTS ix_events_type
                ON offer_events(event_type);
            CREATE INDEX IF NOT EXISTS ix_events_scan
                ON offer_events(scan_id);
            CREATE INDEX IF NOT EXISTS ix_events_created
                ON offer_events(created_at);
            CREATE INDEX IF NOT EXISTS ix_scans_realm
                ON scan_sessions(realm_guid);
            CREATE INDEX IF NOT EXISTS ix_scans_started
                ON scan_sessions(started_at);
            CREATE INDEX IF NOT EXISTS ix_scans_status
                ON scan_sessions(status);
            """)
            row = cur.execute("SELECT version FROM schema_version").fetchone()
            if row is None:
                cur.execute("INSERT INTO schema_version(version) VALUES (?)",
                            (SCHEMA_VERSION,))
            self._conn.commit()

    # -- item resolution ----------------------------------------------------
    def _protocol_id_for(self, cur, norm):
        """The game item id whose normalised name equals `norm`, but only when
        that is unambiguous.  Several game ids can share a normalised name
        (e.g. '(unused)'); in that case we return None rather than guess."""
        rows = cur.execute(
            "SELECT protocol_item_id FROM protocol_names "
            "WHERE normalized_name = ?", (norm,)).fetchall()
        if len(rows) == 1:
            return rows[0][0]
        return None

    def _resolve_item(self, cur, original_name):
        """Map a raw vending item name to an items.id, creating the item on
        first sight.  Confirmed aliases resolve to their target item.  A new
        item gets a protocol_item_id only on an exact, unambiguous name match;
        uncertain names are stored WITHOUT one until an alias/mapping is added.
        Returns the item id, or None if the name is empty."""
        norm = normalize_item(original_name)
        if not norm:
            return None
        row = cur.execute("SELECT id FROM items WHERE normalized_name = ?",
                          (norm,)).fetchone()
        if row:
            return row[0]
        row = cur.execute(
            "SELECT item_id FROM item_aliases WHERE normalized_alias = ?",
            (norm,)).fetchone()
        if row:
            return row[0]
        pid = self._protocol_id_for(cur, norm)
        cur.execute(
            "INSERT INTO items(normalized_name, display_name, protocol_item_id) "
            "VALUES (?, ?, ?)", (norm, str(original_name).strip(), pid))
        return cur.lastrowid

    def add_alias(self, alias, item_identifier):
        """Record a confirmed alias: future items whose normalised name equals
        `alias` resolve to the same item as `item_identifier` (an existing
        display name, normalised name, or numeric items.id).  Idempotent."""
        with self._lock:
            cur = self._conn.cursor()
            item_id = self._lookup_item_id(cur, item_identifier)
            if item_id is None:
                raise ValueError(f"no item matching {item_identifier!r}")
            cur.execute(
                "INSERT OR REPLACE INTO item_aliases(normalized_alias, item_id) "
                "VALUES (?, ?)", (normalize_item(alias), item_id))
            self._conn.commit()
            return item_id

    def _lookup_item_id(self, cur, ident):
        if isinstance(ident, int):
            row = cur.execute("SELECT id FROM items WHERE id = ?",
                              (ident,)).fetchone()
            return row[0] if row else None
        norm = normalize_item(ident)
        row = cur.execute("SELECT id FROM items WHERE normalized_name = ?",
                          (norm,)).fetchone()
        return row[0] if row else None

    # -- names.json ---------------------------------------------------------
    def import_names(self, names_path):
        """Load the game's id->name table (names.json = {id: name}) into
        protocol_names.  Idempotent (INSERT OR REPLACE by id).  Returns the
        number of names loaded."""
        with open(names_path, encoding="utf-8") as fh:
            data = json.load(fh)
        with self._lock:
            cur = self._conn.cursor()
            n = 0
            for k, v in data.items():
                try:
                    pid = int(k)
                except (ValueError, TypeError):
                    continue
                cur.execute(
                    "INSERT OR REPLACE INTO protocol_names"
                    "(protocol_item_id, normalized_name, display_name) "
                    "VALUES (?, ?, ?)", (pid, normalize_item(v), v))
                n += 1
            self._conn.commit()
            return n

    def ensure_names(self, names_path):
        """Import names.json only if protocol_names is empty and the file
        exists.  Convenience for the client's startup."""
        with self._lock:
            cur = self._conn.cursor()
            have = cur.execute(
                "SELECT COUNT(*) FROM protocol_names").fetchone()[0]
        if not have and names_path and os.path.exists(names_path):
            return self.import_names(names_path)
        return 0

    # -- realm / machine upserts (caller holds the lock + transaction) ------
    @staticmethod
    def _upsert_realm(cur, guid, name, owner, link, ts):
        cur.execute("""
            INSERT INTO realms(guid, name, owner, link, first_seen_at,
                               last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(guid) DO UPDATE SET
                name = COALESCE(excluded.name, realms.name),
                owner = COALESCE(excluded.owner, realms.owner),
                link = COALESCE(excluded.link, realms.link),
                last_seen_at = excluded.last_seen_at
        """, (guid, name, owner, link, ts, ts))

    @staticmethod
    def _upsert_machine(cur, guid, realm_guid, x, y, z, ts):
        cur.execute("""
            INSERT INTO machines(guid, realm_guid, x, y, z, first_seen_at,
                                 last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(guid) DO UPDATE SET
                realm_guid = COALESCE(excluded.realm_guid, machines.realm_guid),
                x = COALESCE(excluded.x, machines.x),
                y = COALESCE(excluded.y, machines.y),
                z = COALESCE(excluded.z, machines.z),
                last_seen_at = excluded.last_seen_at
        """, (guid, realm_guid, x, y, z, ts, ts))

    # -- the core: publish a scan ------------------------------------------
    def publish_scan(self, result):
        """Record one realm scan and update the current catalogue.

        `result` is a dict:
            status        one of VALID_STATUSES
            realm_guid    stable realm id (required)
            realm_name    display name (optional)
            realm_owner   (optional)
            realm_link    (optional)
            started_at    ISO ts (optional; defaults to now)
            completed_at  ISO ts (optional)
            source        free label, e.g. 'live_scan' / 'imported_json'
            probes_attempted / probes_answered / error   (optional)
            offers        list of dicts, each:
                machine_guid (required), item (raw text name), qty, price,
                currency, stock, x, y, z, observed_at (optional)

        A COMPLETED scan is authoritative: after storing what it saw it removes
        current listings for machines in this realm that were NOT observed.  Any
        other status leaves unseen current listings alone.  Everything runs in a
        single transaction; on any error it rolls back and the DB is unchanged.

        Returns the new scan_sessions.id."""
        status = result.get("status", "completed")
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid scan status {status!r}")
        realm_guid = result.get("realm_guid")
        if not realm_guid:
            raise ValueError("publish_scan requires a realm_guid")
        started_at = result.get("started_at") or utcnow_iso()
        completed_at = result.get("completed_at")
        if completed_at is None and status == "completed":
            completed_at = utcnow_iso()
        offers = result.get("offers") or []

        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
                self._upsert_realm(cur, realm_guid,
                                   result.get("realm_name"),
                                   result.get("realm_owner"),
                                   result.get("realm_link"),
                                   completed_at or started_at)

                cur.execute("""
                    INSERT INTO scan_sessions(realm_guid, started_at,
                        completed_at, status, source, offers_found,
                        probes_attempted, probes_answered, error)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (realm_guid, started_at, completed_at, status,
                      result.get("source", "live_scan"), len(offers),
                      result.get("probes_attempted"),
                      result.get("probes_answered"), result.get("error")))
                scan_id = cur.lastrowid

                observed = set()
                for off in offers:
                    mguid = off.get("machine_guid")
                    if not mguid:
                        continue
                    observed.add(mguid)
                    obs_at = off.get("observed_at") or completed_at or started_at
                    self._upsert_machine(cur, mguid, realm_guid,
                                         off.get("x"), off.get("y"),
                                         off.get("z"), obs_at)
                    item_name = off.get("item")
                    item_id = self._resolve_item(cur, item_name)

                    # State BEFORE this observation: the previous current offer
                    # (if any), and whether this machine has ANY earlier history.
                    prev = cur.execute(
                        "SELECT h.id, h.item_id, h.original_item_name, "
                        "h.quantity, h.price, h.currency, h.stock "
                        "FROM current_offers c "
                        "JOIN offer_history h ON h.id = c.history_id "
                        "WHERE c.machine_guid = ?", (mguid,)).fetchone()
                    had_history = cur.execute(
                        "SELECT 1 FROM offer_history WHERE machine_guid = ? "
                        "LIMIT 1", (mguid,)).fetchone() is not None

                    cur.execute("""
                        INSERT INTO offer_history(scan_id, machine_guid, item_id,
                            original_item_name, quantity, price, currency, stock,
                            observed_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (scan_id, mguid, item_id, item_name, off.get("qty"),
                          _as_int(off.get("price")), off.get("currency"),
                          _as_int(off.get("stock")), obs_at))
                    new_hid = cur.lastrowid

                    event = self._classify(prev, had_history, item_id, item_name,
                                           off)
                    old_hid = prev["id"] if prev else None
                    cur.execute("""
                        INSERT INTO offer_events(scan_id, machine_guid,
                            event_type, old_history_id, new_history_id,
                            created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (scan_id, mguid, event, old_hid, new_hid, obs_at))

                    cur.execute("""
                        INSERT INTO current_offers(machine_guid, history_id,
                            updated_at)
                        VALUES (?, ?, ?)
                        ON CONFLICT(machine_guid) DO UPDATE SET
                            history_id = excluded.history_id,
                            updated_at = excluded.updated_at
                    """, (mguid, new_hid, obs_at))

                # Removal: only a COMPLETED scan is authoritative enough to say a
                # machine is gone.  Anything else keeps the old current listing.
                if status == AUTHORITATIVE_STATUS:
                    stale = cur.execute("""
                        SELECT c.machine_guid, c.history_id
                        FROM current_offers c
                        JOIN machines m ON m.guid = c.machine_guid
                        WHERE m.realm_guid = ?
                    """, (realm_guid,)).fetchall()
                    ts = completed_at or started_at
                    for r in stale:
                        if r["machine_guid"] in observed:
                            continue
                        cur.execute("""
                            INSERT INTO offer_events(scan_id, machine_guid,
                                event_type, old_history_id, new_history_id,
                                created_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (scan_id, r["machine_guid"], EV_REMOVED,
                              r["history_id"], None, ts))
                        cur.execute(
                            "DELETE FROM current_offers WHERE machine_guid = ?",
                            (r["machine_guid"],))

                self._conn.commit()
                return scan_id
            except Exception:
                self._conn.rollback()
                raise

    @staticmethod
    def _classify(prev, had_history, item_id, item_name, off):
        """Decide the single event type for one observed machine."""
        if prev is None:
            # No current listing.  If the machine has earlier history it was
            # removed before and is now back; otherwise it is brand new.
            return EV_REAPPEARED if had_history else EV_ADDED
        # Compare against the previous current offer, most significant first.
        prev_norm = normalize_item(prev["original_item_name"])
        if (item_id is not None and prev["item_id"] is not None
                and item_id != prev["item_id"]) or \
                (normalize_item(item_name) != prev_norm):
            return EV_ITEM
        if _as_int(off.get("price")) != prev["price"]:
            return EV_PRICE
        if _norm_qty(off.get("qty")) != _norm_qty(prev["quantity"]):
            return EV_QTY
        if _as_int(off.get("stock")) != prev["stock"]:
            return EV_STOCK
        return EV_UNCHANGED

    # -- reports ------------------------------------------------------------
    def _q(self, sql, params=()):
        with self._lock:
            cur = self._conn.cursor()
            return [dict(r) for r in cur.execute(sql, params).fetchall()]

    def _one(self, sql, params=()):
        with self._lock:
            cur = self._conn.cursor()
            row = cur.execute(sql, params).fetchone()
            return dict(row) if row else None

    _CURRENT_SELECT = """
        SELECT h.original_item_name AS item, h.quantity AS qty, h.price,
               h.currency, h.stock, h.machine_guid, c.updated_at,
               r.guid AS realm_guid, r.name AS realm, r.owner, r.link,
               m.x, m.y, m.z
        FROM current_offers c
        JOIN offer_history h ON h.id = c.history_id
        JOIN machines m ON m.guid = c.machine_guid
        LEFT JOIN realms r ON r.guid = m.realm_guid
    """

    def current_for_item(self, term, include_unpriced=True):
        """Current listings whose item matches `term` (normalised substring),
        cheapest first within each currency-agnostic ordering by price.

        A listing priced at 0 is NEVER a real sale (an empty/idle vending slot,
        a display piece, or a blank the scanner read as 0), so it is globally
        excluded from the current market here. Listings with an UNKNOWN price
        (NULL — the scanner couldn't parse it) are kept by default so the item
        still shows up; pass include_unpriced=False to drop those too (used by
        callers that need a price to work with)."""
        key = normalize_item(term)
        where = (" WHERE (h.price IS NULL OR h.price <> 0)" if include_unpriced
                 else " WHERE h.price > 0")
        rows = self._q(self._CURRENT_SELECT + where +
                       " ORDER BY h.price IS NULL, h.price ASC")
        if key:
            rows = [r for r in rows if key in normalize_item(r["item"])]
        return rows

    def current_in_realm(self, realm):
        """Current listings in a realm, given its GUID or (case-insensitive)
        name."""
        by_guid = self._q(self._CURRENT_SELECT +
                          " WHERE r.guid = ? ORDER BY h.price", (realm,))
        if by_guid:
            return by_guid
        return self._q(self._CURRENT_SELECT +
                       " WHERE LOWER(r.name) = LOWER(?) ORDER BY h.price",
                       (realm,))

    def cheapest_current(self, term):
        """The single cheapest current listing matching `term`, per currency."""
        rows = self.current_for_item(term)
        best = {}
        for r in rows:
            if r["price"] is None or r["price"] <= 0:   # 0 isn't a real sale
                continue
            cur = r["currency"] or ""
            if cur not in best or r["price"] < best[cur]["price"]:
                best[cur] = r
        return best

    def item_history(self, term, days=None, include_unchanged=True):
        """Full observation history for items matching `term`, newest first.
        `days` limits to the last N days; include_unchanged=False drops repeated
        identical observations (rows whose event was 'unchanged')."""
        key = normalize_item(term)
        sql = """
            SELECT h.id, h.original_item_name AS item, h.quantity AS qty,
                   h.price, h.currency, h.stock, h.observed_at, h.machine_guid,
                   r.name AS realm, r.guid AS realm_guid,
                   e.event_type
            FROM offer_history h
            LEFT JOIN machines m ON m.guid = h.machine_guid
            LEFT JOIN realms r ON r.guid = m.realm_guid
            LEFT JOIN offer_events e
                   ON e.new_history_id = h.id
        """
        params = []
        where = []
        if days is not None:
            where.append("h.observed_at >= ?")
            params.append(_days_ago_iso(days))
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY h.observed_at DESC, h.id DESC"
        rows = self._q(sql, tuple(params))
        if key:
            rows = [r for r in rows if key in normalize_item(r["item"])]
        if not include_unchanged:
            rows = [r for r in rows if r["event_type"] != EV_UNCHANGED]
        return rows

    def machine_history(self, machine_guid):
        """Every observation and every event for one machine, newest first."""
        obs = self._q("""
            SELECT h.id, h.original_item_name AS item, h.quantity AS qty,
                   h.price, h.currency, h.stock, h.observed_at, s.status,
                   s.id AS scan_id
            FROM offer_history h
            JOIN scan_sessions s ON s.id = h.scan_id
            WHERE h.machine_guid = ?
            ORDER BY h.observed_at DESC, h.id DESC
        """, (machine_guid,))
        events = self._q("""
            SELECT event_type, old_history_id, new_history_id, created_at,
                   scan_id
            FROM offer_events
            WHERE machine_guid = ?
            ORDER BY created_at DESC, id DESC
        """, (machine_guid,))
        info = self._one("""
            SELECT m.guid, m.realm_guid, m.x, m.y, m.z, r.name AS realm,
                   r.owner
            FROM machines m LEFT JOIN realms r ON r.guid = m.realm_guid
            WHERE m.guid = ?
        """, (machine_guid,))
        return {"machine": info, "observations": obs, "events": events}

    def price_changes(self, hours=None, term=None):
        """price_changed events, newest first, showing old->new price.  Filter
        to the last `hours` and/or an item `term`."""
        sql = """
            SELECT e.created_at, e.machine_guid, e.event_type,
                   oh.price AS old_price, oh.currency AS old_currency,
                   nh.price AS new_price, nh.currency AS new_currency,
                   nh.original_item_name AS item, r.name AS realm
            FROM offer_events e
            LEFT JOIN offer_history oh ON oh.id = e.old_history_id
            LEFT JOIN offer_history nh ON nh.id = e.new_history_id
            LEFT JOIN machines m ON m.guid = e.machine_guid
            LEFT JOIN realms r ON r.guid = m.realm_guid
            WHERE e.event_type = ?
        """
        params = [EV_PRICE]
        if hours is not None:
            sql += " AND e.created_at >= ?"
            params.append(_hours_ago_iso(hours))
        sql += " ORDER BY e.created_at DESC, e.id DESC"
        rows = self._q(sql, tuple(params))
        if term:
            key = normalize_item(term)
            rows = [r for r in rows if key in normalize_item(r["item"])]
        return rows

    def _events_of(self, event_type, hours=None):
        sql = """
            SELECT e.created_at, e.machine_guid, e.event_type,
                   nh.original_item_name AS item, nh.price, nh.currency,
                   nh.quantity AS qty, oh.original_item_name AS old_item,
                   oh.price AS old_price, r.name AS realm, r.guid AS realm_guid
            FROM offer_events e
            LEFT JOIN offer_history nh ON nh.id = e.new_history_id
            LEFT JOIN offer_history oh ON oh.id = e.old_history_id
            LEFT JOIN machines m ON m.guid = e.machine_guid
            LEFT JOIN realms r ON r.guid = m.realm_guid
            WHERE e.event_type = ?
        """
        params = [event_type]
        if hours is not None:
            sql += " AND e.created_at >= ?"
            params.append(_hours_ago_iso(hours))
        sql += " ORDER BY e.created_at DESC, e.id DESC"
        return self._q(sql, tuple(params))

    def new_listings(self, hours=None):
        return self._events_of(EV_ADDED, hours)

    def removed_listings(self, hours=None):
        return self._events_of(EV_REMOVED, hours)

    def reappeared_listings(self, hours=None):
        return self._events_of(EV_REAPPEARED, hours)

    def changes(self, hours=24):
        """Everything that changed in the last `hours`, grouped by event type.
        Unchanged observations are excluded."""
        types = [EV_ADDED, EV_REMOVED, EV_REAPPEARED, EV_PRICE, EV_ITEM,
                 EV_QTY, EV_STOCK]
        out = {}
        for t in types:
            out[t] = self._events_of(t, hours)
        return out

    def item_price_stats(self, term, include_unchanged=True):
        """Per-currency price statistics for an item across ALL history.

        Currencies are NEVER combined — the result is keyed by currency.  Prices
        are the listing's TOTAL price (quantity is kept separately, not divided
        out).  Malformed/missing prices AND 0-prices (an idle slot isn't a real
        sale) are excluded from the maths."""
        rows = self.item_history(term, include_unchanged=include_unchanged)
        by_cur = {}
        for r in rows:
            if r["price"] is None or r["price"] <= 0:
                continue
            by_cur.setdefault(r["currency"] or "", []).append(r)
        stats = {}
        for cur, rs in by_cur.items():
            prices = [r["price"] for r in rs]
            qtys = [r["qty"] for r in rs if r["qty"]]
            stats[cur] = {
                "count": len(prices),
                "min": min(prices),
                "max": max(prices),
                "avg": round(statistics.fmean(prices), 2),
                "median": statistics.median(prices),
                "min_qty": min(qtys) if qtys else None,
                "max_qty": max(qtys) if qtys else None,
                "note": "prices are total listing price; quantity is not "
                        "divided out",
            }
        return stats

    def most_recent_observation(self, term):
        rows = self.item_history(term)
        return rows[0] if rows else None

    def stale_current(self, hours=24):
        """Realms whose most recent COMPLETED scan is older than `hours` (or
        which have never had a completed scan) but that still have current
        listings — i.e. catalogues that may be out of date."""
        cutoff = _hours_ago_iso(hours)
        return self._q("""
            SELECT r.guid AS realm_guid, r.name AS realm, r.owner,
                   COUNT(c.machine_guid) AS current_offers,
                   MAX(s.completed_at) AS last_completed
            FROM realms r
            JOIN machines m ON m.realm_guid = r.guid
            JOIN current_offers c ON c.machine_guid = m.guid
            LEFT JOIN scan_sessions s
                   ON s.realm_guid = r.guid AND s.status = 'completed'
            GROUP BY r.guid
            HAVING last_completed IS NULL OR last_completed < ?
            ORDER BY last_completed IS NULL DESC, last_completed ASC
        """, (cutoff,))

    def recent_scans(self, n=10):
        return self._q("""
            SELECT s.id, s.realm_guid, r.name AS realm, s.started_at,
                   s.completed_at, s.status, s.source, s.offers_found,
                   s.probes_attempted, s.probes_answered, s.error
            FROM scan_sessions s
            LEFT JOIN realms r ON r.guid = s.realm_guid
            ORDER BY s.started_at DESC, s.id DESC
            LIMIT ?
        """, (n,))

    def recent_scan_failures(self, n=10):
        return self._q("""
            SELECT s.id, s.realm_guid, r.name AS realm, s.started_at,
                   s.completed_at, s.status, s.offers_found, s.error
            FROM scan_sessions s
            LEFT JOIN realms r ON r.guid = s.realm_guid
            WHERE s.status != 'completed'
            ORDER BY s.started_at DESC, s.id DESC
            LIMIT ?
        """, (n,))

    def scan_status(self):
        """The most recent scan session (any status)."""
        return self._one("""
            SELECT s.id, s.realm_guid, r.name AS realm, s.started_at,
                   s.completed_at, s.status, s.source, s.offers_found,
                   s.probes_attempted, s.probes_answered, s.error
            FROM scan_sessions s
            LEFT JOIN realms r ON r.guid = s.realm_guid
            ORDER BY s.started_at DESC, s.id DESC
            LIMIT 1
        """)

    def scan_coverage(self):
        """Per-realm scan coverage: how many completed vs total scans, and the
        last completion time."""
        return self._q("""
            SELECT r.guid AS realm_guid, r.name AS realm,
                   COUNT(s.id) AS scans,
                   SUM(CASE WHEN s.status='completed' THEN 1 ELSE 0 END)
                       AS completed,
                   MAX(s.completed_at) AS last_completed
            FROM realms r
            LEFT JOIN scan_sessions s ON s.realm_guid = r.guid
            GROUP BY r.guid
            ORDER BY r.name
        """)

    def stats(self):
        """Headline database statistics for the `dbstats` command."""
        with self._lock:
            cur = self._conn.cursor()

            def n(sql, p=()):
                return cur.execute(sql, p).fetchone()[0]

            data = {
                "db_path": self.path,
                "realms": n("SELECT COUNT(*) FROM realms"),
                "machines": n("SELECT COUNT(*) FROM machines"),
                "current_offers": n("SELECT COUNT(*) FROM current_offers"),
                "observations": n("SELECT COUNT(*) FROM offer_history"),
                "scans": n("SELECT COUNT(*) FROM scan_sessions"),
                "failed_scans": n("SELECT COUNT(*) FROM scan_sessions "
                                  "WHERE status != 'completed'"),
                "items": n("SELECT COUNT(*) FROM items"),
                "aliases": n("SELECT COUNT(*) FROM item_aliases"),
                "events": n("SELECT COUNT(*) FROM offer_events"),
                "watchlist": n("SELECT COUNT(*) FROM watchlist"),
                "oldest_observation": n(
                    "SELECT MIN(observed_at) FROM offer_history"),
                "newest_observation": n(
                    "SELECT MAX(observed_at) FROM offer_history"),
            }
        try:
            size = os.path.getsize(self.path)
        except OSError:
            size = 0
        # WAL pages not yet checkpointed add to the on-disk footprint.
        for ext in ("-wal", "-shm"):
            try:
                size += os.path.getsize(self.path + ext)
            except OSError:
                pass
        data["db_size_bytes"] = size
        return data

    # -- current-catalogue export (vends.json compatibility) ----------------
    def export_current(self, out_path):
        """Regenerate the legacy vends.json shape from the CURRENT catalogue
        only (no removed or historical listings).  Realms are keyed by name for
        backward compatibility, but the data comes from GUID-keyed tables.
        Returns (realm_count, machine_count)."""
        rows = self._q(self._CURRENT_SELECT + " ORDER BY r.name, h.price")
        realms = {}
        machines = 0
        for r in rows:
            name = r["realm"] or r["realm_guid"]
            e = realms.get(name)
            if e is None:
                e = realms[name] = {
                    "guid": r["realm_guid"], "owner": r["owner"],
                    "link": r["link"], "updated": r["updated_at"],
                    "machines": [],
                }
            if r["updated_at"] and (not e["updated"]
                                    or r["updated_at"] > e["updated"]):
                e["updated"] = r["updated_at"]
            e["machines"].append({
                "item": r["item"], "qty": r["qty"], "price": r["price"],
                "currency": r["currency"], "guid": r["machine_guid"],
            })
            machines += 1
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(realms, fh, indent=1, ensure_ascii=False, default=str)
        return len(realms), machines

    # -- JSON migration -----------------------------------------------------
    def import_json(self, vends_path=None, realms_path=None,
                    watchlist_path=None, names_path=None, dry_run=False):
        """Import the legacy JSON files.  Idempotent: a legacy realm snapshot is
        keyed by (realm_guid, its 'updated' timestamp, source='imported_json'),
        so re-running skips snapshots already imported and never duplicates
        observations.  Original files are only READ, never written.

        Malformed entries are counted and skipped without aborting the import.
        Returns a report dict.  With dry_run=True nothing is written."""
        report = {"realms": 0, "machines": 0, "offers": 0, "watchlist": 0,
                  "skipped_snapshots": 0, "malformed": [], "dry_run": dry_run}

        if names_path and os.path.exists(names_path) and not dry_run:
            self.import_names(names_path)

        # --- realms.json (name -> {guid, link, owner, seen}) ---------------
        realms_data = _safe_load(realms_path)
        if realms_data:
            for name, e in realms_data.items():
                if not isinstance(e, dict) or not e.get("guid"):
                    report["malformed"].append(f"realm {name!r}")
                    continue
                report["realms"] += 1
                if not dry_run:
                    with self._lock:
                        cur = self._conn.cursor()
                        try:
                            cur.execute("BEGIN")
                            self._upsert_realm(cur, e["guid"], name,
                                               e.get("owner"), e.get("link"),
                                               e.get("seen") or utcnow_iso())
                            self._conn.commit()
                        except Exception:
                            self._conn.rollback()
                            raise

        # --- vends.json (name -> {guid, owner, link, updated, machines}) ----
        vends_data = _safe_load(vends_path)
        if vends_data:
            for name, e in vends_data.items():
                if not isinstance(e, dict) or not e.get("guid"):
                    report["malformed"].append(f"vends realm {name!r}")
                    continue
                guid = e["guid"]
                updated = e.get("updated") or e.get("seen") or utcnow_iso()
                if self._snapshot_imported(guid, updated):
                    report["skipped_snapshots"] += 1
                    continue
                offers = []
                for m in e.get("machines", []) or []:
                    if not isinstance(m, dict):
                        report["malformed"].append(
                            f"machine in {name!r}: {m!r}")
                        continue
                    mguid = m.get("guid")
                    if not mguid:
                        report["malformed"].append(
                            f"machine in {name!r} has no guid")
                        continue
                    offers.append({
                        "machine_guid": mguid, "item": m.get("item"),
                        "qty": m.get("qty"), "price": m.get("price"),
                        "currency": m.get("currency"), "stock": m.get("stock"),
                        "x": m.get("x"), "y": m.get("y"), "z": m.get("z"),
                        "observed_at": _to_iso(updated),
                    })
                report["realms"] = report["realms"]  # (realms counted above)
                report["machines"] += len(offers)
                report["offers"] += len(offers)
                if not dry_run:
                    self.publish_scan({
                        "status": "completed",
                        "realm_guid": guid, "realm_name": name,
                        "realm_owner": e.get("owner"),
                        "realm_link": e.get("link"),
                        "started_at": _to_iso(updated),
                        "completed_at": _to_iso(updated),
                        "source": "imported_json",
                        "offers": offers,
                    })

        # --- watchlist.json (guid -> {guid, name, owner, link, added}) ------
        wl_data = _safe_load(watchlist_path)
        if wl_data:
            for guid, e in wl_data.items():
                if not isinstance(e, dict) or not (e.get("guid") or guid):
                    report["malformed"].append(f"watchlist {guid!r}")
                    continue
                report["watchlist"] += 1
                if not dry_run:
                    with self._lock:
                        cur = self._conn.cursor()
                        try:
                            cur.execute("BEGIN")
                            cur.execute("""
                                INSERT OR REPLACE INTO watchlist(realm_guid,
                                    name, owner, link, added_at)
                                VALUES (?, ?, ?, ?, ?)
                            """, (e.get("guid") or guid, e.get("name"),
                                  e.get("owner"), e.get("link"),
                                  _to_iso(e.get("added")) or utcnow_iso()))
                            self._conn.commit()
                        except Exception:
                            self._conn.rollback()
                            raise
        return report

    def _snapshot_imported(self, realm_guid, updated):
        """True if a legacy snapshot for this realm+timestamp is already in the
        DB — the idempotency guard for import_json."""
        row = self._one("""
            SELECT id FROM scan_sessions
            WHERE realm_guid = ? AND source = 'imported_json'
              AND started_at = ?
        """, (realm_guid, _to_iso(updated)))
        return row is not None

    # -- backup -------------------------------------------------------------
    def backup(self, out_path, overwrite=False):
        """Write a consistent snapshot of the database using SQLite's online
        backup API (safe even while the DB is being written).  Refuses to
        clobber an existing file unless overwrite=True.  Returns the byte size
        of the backup."""
        if os.path.exists(out_path) and not overwrite:
            raise FileExistsError(
                f"{out_path} already exists (pass overwrite=True to replace)")
        d = os.path.dirname(os.path.abspath(out_path))
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        with self._lock:
            dest = sqlite3.connect(out_path)
            try:
                self._conn.backup(dest)
            finally:
                dest.close()
        return os.path.getsize(out_path)


# --- small helpers ----------------------------------------------------------
def _as_int(v):
    """Best-effort int of a price/stock that might be '1,499' or None.
    Returns None for missing/garbage so it is excluded from maths."""
    if v is None:
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v).replace(",", "").strip())
    except (ValueError, TypeError):
        return None


def _norm_qty(v):
    """Quantity, defaulting a missing value to 1 for change comparison (a
    listing with no stated qty is one item)."""
    iv = _as_int(v)
    return 1 if iv is None else iv


def _safe_load(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


def _to_iso(ts):
    """Coerce a legacy 'YYYY-MM-DD HH:MM:SS' local timestamp (or an already-ISO
    string) into a stable string used as the observation time.  Kept verbatim
    if it already looks ISO; otherwise the space is turned into 'T'."""
    if not ts:
        return None
    s = str(ts).strip()
    if "T" in s:
        return s
    return s.replace(" ", "T", 1)


def _hours_ago_iso(hours):
    from datetime import timedelta
    return (datetime.now(timezone.utc)
            - timedelta(hours=hours)).isoformat(timespec="seconds")


def _days_ago_iso(days):
    from datetime import timedelta
    return (datetime.now(timezone.utc)
            - timedelta(days=days)).isoformat(timespec="seconds")


# --- CLI --------------------------------------------------------------------
def _cli(argv=None):
    ap = argparse.ArgumentParser(
        description="Cubic Castles market-history SQLite store")
    ap.add_argument("--db", default=DEFAULT_DB_PATH,
                    help=f"database path (default {DEFAULT_DB_PATH})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create/upgrade the schema")

    mj = sub.add_parser("migrate-json", help="import the legacy JSON files")
    mj.add_argument("--vends", default=None)
    mj.add_argument("--realms", default=None)
    mj.add_argument("--watchlist", default=None)
    mj.add_argument("--names", default=None)
    mj.add_argument("--dry-run", action="store_true")

    inm = sub.add_parser("import-names", help="load names.json id->name table")
    inm.add_argument("--names", required=True)

    ec = sub.add_parser("export-current",
                        help="write current listings as vends.json format")
    ec.add_argument("--out", required=True)

    sub.add_parser("stats", help="show database statistics")

    bk = sub.add_parser("backup", help="safe online backup of the database")
    bk.add_argument("--out", required=True)
    bk.add_argument("--force", action="store_true",
                    help="overwrite the backup if it already exists")

    args = ap.parse_args(argv)

    with MarketDB(args.db) as db:
        if args.cmd == "init":
            print(f"schema ready at {args.db} (version {SCHEMA_VERSION})")
        elif args.cmd == "migrate-json":
            rep = db.import_json(args.vends, args.realms, args.watchlist,
                                 args.names, dry_run=args.dry_run)
            tag = " (DRY RUN — nothing written)" if rep["dry_run"] else ""
            print(f"migrate-json{tag}:")
            print(f"  realms imported     : {rep['realms']}")
            print(f"  machines imported   : {rep['machines']}")
            print(f"  offers imported     : {rep['offers']}")
            print(f"  watchlist imported  : {rep['watchlist']}")
            print(f"  snapshots skipped   : {rep['skipped_snapshots']} "
                  f"(already imported)")
            if rep["malformed"]:
                print(f"  malformed (skipped) : {len(rep['malformed'])}")
                for m in rep["malformed"][:20]:
                    print(f"      - {m}")
                if len(rep["malformed"]) > 20:
                    print(f"      … and {len(rep['malformed']) - 20} more")
        elif args.cmd == "import-names":
            n = db.import_names(args.names)
            print(f"loaded {n} item name(s) from {args.names}")
        elif args.cmd == "export-current":
            realms, machines = db.export_current(args.out)
            print(f"wrote {machines} current listing(s) across {realms} "
                  f"realm(s) -> {args.out}")
        elif args.cmd == "stats":
            for k, v in db.stats().items():
                print(f"  {k:20} {v}")
        elif args.cmd == "backup":
            try:
                size = db.backup(args.out, overwrite=args.force)
            except FileExistsError:
                print(f"{args.out} already exists — pass --force to overwrite, "
                      f"or choose another name")
                return 1
            print(f"backup written -> {args.out}  ({size:,} bytes)")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_cli() or 0)

#!/usr/bin/env python3
"""
Cubic Castles buy-order escrow — SQLite ledger (Stage 10, experimental).

An in-game bot takes buy orders in chat: a player says which item they want, how
many, and the most they'll pay per unit.  They deposit cubits with the bot; the
bot buys the item at or below their limit out of THAT player's deposited balance,
and later hands back the item plus any leftover cubits.

This module is the MONEY-SAFETY CORE only.  It is pure local persistence and
never connects to the game — so it is safe to run and test offline, exactly like
cc_storage.py.  The live pieces it deliberately does NOT contain:

  * the chat parsing (lives in cc_client.py's command registry), and
  * the secure player<->bot TRADE that actually moves cubits/items in-game.
    That wire protocol is not reversed yet (no trade window is mapped in
    SCHEMA.md), so deposits/payouts here are recorded by the caller once a trade
    has been observed and confirmed.  This ledger is the source of truth for
    "who is owed what"; the trade capture is a separate future step.

Design rules (mirroring MARKET_DB.md's hard-won lessons):

  * BALANCE IS DERIVED, NEVER STORED.  We keep an append-only, double-entry
    `ledger`; a player's balance is SUM(delta) over their rows.  There is no
    mutable balance column to corrupt, and every cubit is auditable to the entry
    that moved it.
  * ACCOUNTS ARE KEYED BY NORMALISED PLAYER NAME.  The name is the SOLE
    identity.  We still record the last chat GUID we saw for that name, but only
    as passive audit metadata — GUIDs are per-session and change between logins,
    so they never gate anything (keying money to them would lock out returning
    players).
  * ISOLATION BY CONSTRUCTION.  Every write is filtered by one account; the
    overspend check and the debit happen in ONE transaction, so a player can
    never spend past their own deposits nor touch another player's funds.
  * IDEMPOTENCY.  Every value move carries a UNIQUE idempotency key.  The client
    reconnects/replays (the connection is swapped on teleport), so a repeated
    deposit or purchase-confirm must count exactly once.
  * Foreign keys on, WAL journal, a busy timeout, UTC ISO-8601 timestamps,
    every statement parameterised.  Cubits are whole numbers (integer cents-free
    currency); amounts are non-negative integers and deltas are signed.

CLI:
    py cc_orders.py init [--db PATH]
    py cc_orders.py balances [--db PATH]
    py cc_orders.py account NAME [--db PATH]
    py cc_orders.py orders [--open] [--db PATH]
    py cc_orders.py ledger NAME [--db PATH]
"""
import argparse
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

SCHEMA_VERSION = 1

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "cubic_orders.db")

# Ledger entry reasons (the `reason` column).  Sign convention: deposits and
# refunds credit the player (+), everything the bot pays out or spends debits (-).
R_DEPOSIT = "deposit"          # player handed cubits to the bot            (+)
R_PURCHASE = "purchase"        # bot bought a unit for this player          (-)
R_PAYOUT = "payout"            # bot handed leftover cubits back to player  (-)
R_REFUND = "refund"            # correction crediting the player            (+)
R_ADJUST = "adjust"            # manual correction (signed)                 (+/-)
VALID_REASONS = {R_DEPOSIT, R_PURCHASE, R_PAYOUT, R_REFUND, R_ADJUST}

# Order lifecycle.  An order RESERVES funds only while OPEN; DONE means no more
# buying will happen (filled or cancelled) and there may be items + leftover to
# collect; COLLECTED closes it.
S_OPEN = "open"
S_DONE = "done"
S_COLLECTED = "collected"
VALID_STATUSES = {S_OPEN, S_DONE, S_COLLECTED}

# Why an order stopped buying (orders.close_reason), set when it leaves OPEN.
C_FILLED = "filled"            # bought the full requested quantity
C_CANCELLED = "cancelled"      # stopped early by the player / operator


class OrderError(Exception):
    """A rule violation the caller should surface to the player (e.g. not enough
    balance, unknown order, wrong state).  Never a programming bug."""


def utcnow_iso():
    """Current UTC time as an ISO-8601 string, second precision."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- player-name normalisation ----------------------------------------------
# The ACCOUNT KEY.  Case- and whitespace-insensitive so 'Example', 'example'
# and 'MISTER  90' are one account, but otherwise faithful to what the player
# typed (we do NOT strip punctuation the way item matching does — two different
# names must never collapse together, since that would merge two people's money).
_WS_RE = re.compile(r"\s+")


def normalize_name(name):
    """Normalise a player display name into its account key.

    Casefold + collapse internal whitespace + strip.  Returns '' for empty/None.
    'Example' -> 'example'."""
    if not name:
        return ""
    return _WS_RE.sub(" ", str(name).casefold()).strip()


def new_idempotency_key():
    """A fresh unique key for a value move, when the caller has no natural one."""
    return uuid.uuid4().hex


class OrderStore:
    """SQLite-backed escrow ledger: per-player balances, buy orders, and an
    append-only double-entry ledger.

    Safe to share one instance across threads: every public method takes an
    internal lock and uses its own cursor.  Open once, call close() (or use it as
    a context manager) when done."""

    def __init__(self, path=DEFAULT_DB_PATH, timeout=30.0):
        self.path = path
        self._lock = threading.RLock()
        d = os.path.dirname(os.path.abspath(path))
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
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

            -- One row per player.  The KEY is the normalised name; we also keep
            -- the friendly display name and the last chat GUID seen for it.
            CREATE TABLE IF NOT EXISTS accounts (
                name_norm     TEXT PRIMARY KEY,
                display_name  TEXT NOT NULL,
                guid          TEXT,          -- last wire GUID seen (cross-check)
                first_seen    TEXT NOT NULL,
                last_seen     TEXT NOT NULL
            );

            -- Append-only double-entry ledger.  Balance = SUM(delta) per account.
            -- Nothing is ever updated or deleted here.
            CREATE TABLE IF NOT EXISTS ledger (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                account       TEXT NOT NULL REFERENCES accounts(name_norm),
                order_id      INTEGER REFERENCES orders(id),
                delta         INTEGER NOT NULL,        -- signed cubits
                reason        TEXT NOT NULL,
                idem_key      TEXT NOT NULL UNIQUE,     -- exactly-once guard
                note          TEXT,
                ts            TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS orders (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                account       TEXT NOT NULL REFERENCES accounts(name_norm),
                item_query    TEXT NOT NULL,           -- what the player asked for
                item_norm     TEXT NOT NULL,           -- normalised, for matching
                qty_requested INTEGER NOT NULL,
                qty_bought    INTEGER NOT NULL DEFAULT 0,
                max_unit_price INTEGER NOT NULL,        -- limit price per unit
                status        TEXT NOT NULL,
                close_reason  TEXT,                     -- filled | cancelled
                created       TEXT NOT NULL,
                updated       TEXT NOT NULL
            );

            -- An immutable event log per order (audit trail of state changes).
            CREATE TABLE IF NOT EXISTS order_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id      INTEGER NOT NULL REFERENCES orders(id),
                event         TEXT NOT NULL,
                detail        TEXT,
                ts            TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_ledger_account ON ledger(account);
            CREATE INDEX IF NOT EXISTS idx_ledger_order   ON ledger(order_id);
            CREATE INDEX IF NOT EXISTS idx_orders_account ON orders(account);
            CREATE INDEX IF NOT EXISTS idx_orders_status  ON orders(status);
            CREATE INDEX IF NOT EXISTS idx_orders_item    ON orders(item_norm);
            CREATE INDEX IF NOT EXISTS idx_events_order   ON order_events(order_id);
            """)
            row = cur.execute("SELECT version FROM schema_version").fetchone()
            if row is None:
                cur.execute("INSERT INTO schema_version(version) VALUES (?)",
                            (SCHEMA_VERSION,))
            self._conn.commit()

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _check_amount(amount, what="amount"):
        """Cubit amounts are positive whole numbers."""
        if not isinstance(amount, int) or isinstance(amount, bool):
            raise OrderError(f"{what} must be a whole number of cubits")
        if amount <= 0:
            raise OrderError(f"{what} must be greater than zero")
        return amount

    def _touch_account(self, cur, name, guid=None):
        """Ensure an account row exists for `name`; refresh last_seen and record
        the latest chat GUID seen.  The GUID is audit metadata ONLY — the account
        key is the name, so a changed/absent GUID never affects anything.  Returns
        the name_norm.  Raises if the name normalises to empty."""
        norm = normalize_name(name)
        if not norm:
            raise OrderError("player name is empty")
        now = utcnow_iso()
        row = cur.execute("SELECT 1 FROM accounts WHERE name_norm=?",
                          (norm,)).fetchone()
        if row is None:
            cur.execute(
                "INSERT INTO accounts(name_norm, display_name, guid, "
                "first_seen, last_seen) VALUES (?,?,?,?,?)",
                (norm, str(name), guid, now, now))
        else:
            # Keep the freshest display name + last-seen guid, but never wipe a
            # recorded guid with a missing one.
            cur.execute(
                "UPDATE accounts SET display_name=?, last_seen=?, "
                "guid=COALESCE(?, guid) WHERE name_norm=?",
                (str(name), now, guid, norm))
        return norm

    def _balance(self, cur, norm):
        row = cur.execute(
            "SELECT COALESCE(SUM(delta), 0) AS bal FROM ledger WHERE account=?",
            (norm,)).fetchone()
        return int(row["bal"])

    def _reserved(self, cur, norm):
        """Cubits currently earmarked by this player's OPEN orders: for each open
        order, (qty_requested - qty_bought) * max_unit_price."""
        row = cur.execute(
            "SELECT COALESCE(SUM((qty_requested - qty_bought) * max_unit_price), 0)"
            " AS res FROM orders WHERE account=? AND status=?",
            (norm, S_OPEN)).fetchone()
        return int(row["res"])

    def _post_ledger(self, cur, norm, delta, reason, idem_key, order_id=None,
                     note=None):
        """Append one ledger row.  Raises OrderError on a duplicate idempotency
        key (the move already happened) so the caller can treat it as a no-op."""
        if reason not in VALID_REASONS:
            raise OrderError(f"unknown ledger reason {reason!r}")
        try:
            cur.execute(
                "INSERT INTO ledger(account, order_id, delta, reason, idem_key,"
                " note, ts) VALUES (?,?,?,?,?,?,?)",
                (norm, order_id, int(delta), reason, idem_key, note,
                 utcnow_iso()))
        except sqlite3.IntegrityError:
            raise OrderError(f"duplicate transaction ({idem_key})")

    def _order_row(self, cur, order_id):
        row = cur.execute("SELECT * FROM orders WHERE id=?",
                          (order_id,)).fetchone()
        if row is None:
            raise OrderError(f"no such order #{order_id}")
        return row

    def _log_event(self, cur, order_id, event, detail=None):
        cur.execute(
            "INSERT INTO order_events(order_id, event, detail, ts)"
            " VALUES (?,?,?,?)", (order_id, event, detail, utcnow_iso()))

    # -- public: money moves ------------------------------------------------
    def deposit(self, name, amount, idem_key=None, guid=None, note=None):
        """Record that `name` handed `amount` cubits to the bot (after a
        confirmed in-game trade).  Idempotent on idem_key.  Returns the new
        balance."""
        self._check_amount(amount, "deposit")
        idem_key = idem_key or new_idempotency_key()
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
                norm = self._touch_account(cur, name, guid)
                self._post_ledger(cur, norm, amount, R_DEPOSIT, idem_key,
                                  note=note)
                bal = self._balance(cur, norm)
                self._conn.commit()
                return bal
            except Exception:
                self._conn.rollback()
                raise

    def payout(self, name, amount, idem_key=None, note=None):
        """Record that the bot handed `amount` leftover cubits back to the player.
        Debits their balance; cannot exceed available balance.  Idempotent."""
        self._check_amount(amount, "payout")
        idem_key = idem_key or new_idempotency_key()
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
                norm = normalize_name(name)
                if not self._account_exists(cur, norm):
                    raise OrderError(f"no account for {name!r}")
                avail = self._balance(cur, norm) - self._reserved(cur, norm)
                if amount > avail:
                    raise OrderError(
                        f"payout {amount} exceeds available {avail} "
                        f"(reserved funds are locked to open orders)")
                self._post_ledger(cur, norm, -amount, R_PAYOUT, idem_key,
                                  note=note)
                bal = self._balance(cur, norm)
                self._conn.commit()
                return bal
            except Exception:
                self._conn.rollback()
                raise

    def refund(self, name, amount, idem_key=None, note=None):
        """Credit `amount` back to a player (a correction, not a deposit)."""
        self._check_amount(amount, "refund")
        idem_key = idem_key or new_idempotency_key()
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
                norm = normalize_name(name)
                if not self._account_exists(cur, norm):
                    raise OrderError(f"no account for {name!r}")
                self._post_ledger(cur, norm, amount, R_REFUND, idem_key,
                                  note=note)
                bal = self._balance(cur, norm)
                self._conn.commit()
                return bal
            except Exception:
                self._conn.rollback()
                raise

    # -- public: orders -----------------------------------------------------
    def place_order(self, name, item_query, qty, max_unit_price, guid=None):
        """Open a buy order.  Reserves qty*max_unit_price against the player's
        AVAILABLE balance (balance minus what's already reserved by their other
        open orders); refuses if they can't cover it.  Returns the order id."""
        self._check_amount(qty, "quantity")
        self._check_amount(max_unit_price, "max price")
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
                norm = self._touch_account(cur, name, guid)
                need = qty * max_unit_price
                avail = self._balance(cur, norm) - self._reserved(cur, norm)
                if need > avail:
                    raise OrderError(
                        f"order needs {need} cubits but only {avail} available "
                        f"(deposit more or lower the quantity/price)")
                now = utcnow_iso()
                cur.execute(
                    "INSERT INTO orders(account, item_query, item_norm, "
                    "qty_requested, qty_bought, max_unit_price, status, "
                    "created, updated) VALUES (?,?,?,?,?,?,?,?,?)",
                    (norm, item_query, normalize_name(item_query), qty, 0,
                     max_unit_price, S_OPEN, now, now))
                order_id = cur.lastrowid
                self._log_event(cur, order_id, "placed",
                                f"{qty} x '{item_query}' @<= {max_unit_price}")
                self._conn.commit()
                return order_id
            except Exception:
                self._conn.rollback()
                raise

    def record_purchase(self, order_id, unit_price, idem_key=None, qty=1,
                        note=None):
        """Record that the bot bought `qty` unit(s) for this order at
        `unit_price` each (must be <= the order's limit).  Debits the player and
        advances the order; when the full requested quantity is reached the order
        becomes DONE/filled.  Idempotent on idem_key.  Returns the updated order
        as a dict."""
        self._check_amount(unit_price, "unit price")
        self._check_amount(qty, "quantity")
        idem_key = idem_key or new_idempotency_key()
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
                o = self._order_row(cur, order_id)
                if o["status"] != S_OPEN:
                    raise OrderError(
                        f"order #{order_id} is {o['status']}, not open")
                if unit_price > o["max_unit_price"]:
                    raise OrderError(
                        f"price {unit_price} exceeds limit "
                        f"{o['max_unit_price']} for order #{order_id}")
                remaining = o["qty_requested"] - o["qty_bought"]
                if qty > remaining:
                    raise OrderError(
                        f"buying {qty} would exceed the {remaining} still "
                        f"needed on order #{order_id}")
                norm = o["account"]
                cost = unit_price * qty
                # Safety net: the reservation already guarantees this, but check
                # the raw balance too so a bug can never overdraw a player.
                bal = self._balance(cur, norm)
                if cost > bal:
                    raise OrderError(
                        f"purchase {cost} exceeds balance {bal} for {norm!r}")
                self._post_ledger(cur, norm, -cost, R_PURCHASE, idem_key,
                                  order_id=order_id,
                                  note=note or f"{qty}@{unit_price}")
                new_bought = o["qty_bought"] + qty
                now = utcnow_iso()
                if new_bought >= o["qty_requested"]:
                    cur.execute(
                        "UPDATE orders SET qty_bought=?, status=?, "
                        "close_reason=?, updated=? WHERE id=?",
                        (new_bought, S_DONE, C_FILLED, now, order_id))
                    self._log_event(cur, order_id, "filled",
                                    f"bought {qty}@{unit_price}")
                else:
                    cur.execute(
                        "UPDATE orders SET qty_bought=?, updated=? WHERE id=?",
                        (new_bought, now, order_id))
                    self._log_event(cur, order_id, "bought",
                                    f"{qty}@{unit_price} ({new_bought}/"
                                    f"{o['qty_requested']})")
                out = dict(self._order_row(cur, order_id))
                self._conn.commit()
                return out
            except Exception:
                self._conn.rollback()
                raise

    def cancel_order(self, order_id, reason=None):
        """Stop buying on an OPEN order.  Releases its remaining reservation.
        Any units already bought stay recorded and remain to be collected.
        Returns the updated order as a dict."""
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
                o = self._order_row(cur, order_id)
                if o["status"] != S_OPEN:
                    raise OrderError(
                        f"order #{order_id} is {o['status']}, cannot cancel")
                cur.execute(
                    "UPDATE orders SET status=?, close_reason=?, updated=? "
                    "WHERE id=?", (S_DONE, C_CANCELLED, utcnow_iso(), order_id))
                self._log_event(cur, order_id, "cancelled", reason)
                out = dict(self._order_row(cur, order_id))
                self._conn.commit()
                return out
            except Exception:
                self._conn.rollback()
                raise

    def collect_order(self, order_id):
        """Mark a DONE order's bought items as handed over to the player (after
        the collection trade).  Does NOT move cubits — leftover cubits are
        returned separately via payout().  Returns the updated order as a dict."""
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
                o = self._order_row(cur, order_id)
                if o["status"] == S_OPEN:
                    raise OrderError(
                        f"order #{order_id} is still open; cancel or fill it "
                        f"before collecting")
                if o["status"] == S_COLLECTED:
                    raise OrderError(f"order #{order_id} already collected")
                cur.execute(
                    "UPDATE orders SET status=?, updated=? WHERE id=?",
                    (S_COLLECTED, utcnow_iso(), order_id))
                self._log_event(cur, order_id, "collected",
                                f"{o['qty_bought']} item(s) handed over")
                out = dict(self._order_row(cur, order_id))
                self._conn.commit()
                return out
            except Exception:
                self._conn.rollback()
                raise

    # -- public: reads ------------------------------------------------------
    def _account_exists(self, cur, norm):
        return cur.execute("SELECT 1 FROM accounts WHERE name_norm=?",
                          (norm,)).fetchone() is not None

    def balance(self, name):
        """This player's total held cubits (SUM of their ledger)."""
        with self._lock:
            cur = self._conn.cursor()
            return self._balance(cur, normalize_name(name))

    def reserved(self, name):
        """Cubits locked to this player's open orders."""
        with self._lock:
            cur = self._conn.cursor()
            return self._reserved(cur, normalize_name(name))

    def available(self, name):
        """Cubits this player can still commit or withdraw (balance - reserved)."""
        with self._lock:
            cur = self._conn.cursor()
            norm = normalize_name(name)
            return self._balance(cur, norm) - self._reserved(cur, norm)

    def account_summary(self, name):
        """A dict of {display_name, balance, reserved, available, open_orders}
        or None if the account is unknown."""
        with self._lock:
            cur = self._conn.cursor()
            norm = normalize_name(name)
            row = cur.execute(
                "SELECT display_name, guid FROM accounts WHERE name_norm=?",
                (norm,)).fetchone()
            if row is None:
                return None
            bal = self._balance(cur, norm)
            res = self._reserved(cur, norm)
            n_open = cur.execute(
                "SELECT COUNT(*) AS n FROM orders WHERE account=? AND status=?",
                (norm, S_OPEN)).fetchone()["n"]
            return {
                "display_name": row["display_name"],
                "guid": row["guid"],
                "balance": bal,
                "reserved": res,
                "available": bal - res,
                "open_orders": int(n_open),
            }

    def get_order(self, order_id):
        with self._lock:
            cur = self._conn.cursor()
            row = cur.execute("SELECT * FROM orders WHERE id=?",
                             (order_id,)).fetchone()
            return dict(row) if row else None

    def orders_for(self, name, status=None):
        with self._lock:
            cur = self._conn.cursor()
            norm = normalize_name(name)
            if status:
                rows = cur.execute(
                    "SELECT * FROM orders WHERE account=? AND status=? "
                    "ORDER BY id", (norm, status)).fetchall()
            else:
                rows = cur.execute(
                    "SELECT * FROM orders WHERE account=? ORDER BY id",
                    (norm,)).fetchall()
            return [dict(r) for r in rows]

    def open_orders(self):
        """Every open order across all players (what the buyer loop scans)."""
        with self._lock:
            cur = self._conn.cursor()
            rows = cur.execute(
                "SELECT * FROM orders WHERE status=? ORDER BY id",
                (S_OPEN,)).fetchall()
            return [dict(r) for r in rows]

    def ledger_for(self, name):
        with self._lock:
            cur = self._conn.cursor()
            norm = normalize_name(name)
            rows = cur.execute(
                "SELECT * FROM ledger WHERE account=? ORDER BY id",
                (norm,)).fetchall()
            return [dict(r) for r in rows]

    def all_balances(self):
        """[(display_name, balance, reserved)] for every account, richest first."""
        with self._lock:
            cur = self._conn.cursor()
            rows = cur.execute("SELECT name_norm, display_name FROM accounts"
                              ).fetchall()
            out = []
            for r in rows:
                norm = r["name_norm"]
                out.append((r["display_name"], self._balance(cur, norm),
                            self._reserved(cur, norm)))
            out.sort(key=lambda t: t[1], reverse=True)
            return out


# --- CLI --------------------------------------------------------------------
def _main(argv=None):
    ap = argparse.ArgumentParser(description="Cubic Castles buy-order ledger")
    ap.add_argument("--db", default=DEFAULT_DB_PATH)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("balances")
    pa = sub.add_parser("account"); pa.add_argument("name")
    po = sub.add_parser("orders"); po.add_argument("--open", action="store_true")
    pl = sub.add_parser("ledger"); pl.add_argument("name")
    args = ap.parse_args(argv)

    with OrderStore(args.db) as db:
        if args.cmd == "init":
            print(f"initialised {args.db}")
        elif args.cmd == "balances":
            for name, bal, res in db.all_balances():
                extra = f" ({res} reserved)" if res else ""
                print(f"  {bal:>10}  {name}{extra}")
        elif args.cmd == "account":
            s = db.account_summary(args.name)
            if not s:
                print(f"no account for {args.name!r}"); return
            print(f"  {s['display_name']}")
            print(f"    balance   {s['balance']}")
            print(f"    reserved  {s['reserved']}")
            print(f"    available {s['available']}")
            print(f"    open      {s['open_orders']} order(s)")
        elif args.cmd == "orders":
            rows = db.open_orders() if args.open else None
            if rows is None:
                with db._lock:
                    rows = [dict(r) for r in db._conn.execute(
                        "SELECT * FROM orders ORDER BY id").fetchall()]
            for o in rows:
                print(f"  #{o['id']} [{o['status']}] {o['account']}: "
                      f"{o['qty_bought']}/{o['qty_requested']} x "
                      f"'{o['item_query']}' @<= {o['max_unit_price']}")
        elif args.cmd == "ledger":
            for e in db.ledger_for(args.name):
                oid = f" ord#{e['order_id']}" if e['order_id'] else ""
                print(f"  {e['ts']}  {e['delta']:>+8}  {e['reason']}{oid}")


if __name__ == "__main__":
    _main()

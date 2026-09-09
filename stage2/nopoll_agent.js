'use strict';

/*
 * Cubic Castles - noPoll WebSocket frame capture agent
 *
 * Hooks the 4 noPoll functions that carry game traffic, per the Stage 1
 * import-table analysis of Cubic.exe (32-bit MSVC, cdecl):
 *
 *   nopoll_conn_new(ctx, host_ip, host_port, host_name, get_url, protocols, origin)
 *   nopoll_conn_send_binary(conn, content, length)   -> outbound
 *   nopoll_conn_get_msg(conn) -> noPollMsg*          -> inbound
 *   nopoll_conn_close(conn)
 *
 * Payloads are read via the noPoll accessor API rather than by poking struct
 * offsets, so this stays correct across noPoll builds.
 */

var MODULE = 'libnopoll.dll';

/* How many outbound sends to backtrace, to locate the encryption layer above
 * noPoll. Set by the driver via rpc before the game starts talking. */
var btBudget = 0;

/* Plaintext capture. When enabled, hook the framer/encrypt function inside
 * Cubic.exe (RVA from Stage 2 static analysis) at ENTRY, before it XXTEA-
 * encrypts in place, and dump both the 128-bit key and the plaintext message.
 *
 *   framer  = Cubic.exe+0x11362c   __fastcall(ecx = message, edx = &cipher_state)
 *     2.1.33 message layout: [msg+4] = buffer, [msg+8] = length
 *     (the hook also recognizes the older reversed layout)
 *     cipher_state (edx) -> 16-byte XXTEA key
 */
var CUBIC = 'Cubic.exe';
var RVA_FRAMER = 0x11362c;
var RVA_XXTEA = 0x1133fd;
var RVA_APPEND_U32 = 0x208880;
var RVA_OUTER_CIPHER = 0x121150;
var RVA_SEND_CALLSITE = 0x121651;
var plaintextOn = false;
var lastKeyHex = null;   // re-emit whenever the key changes (per backend connection)
var cipherTraceBudget = 0;
var cipherTraceInstalled = false;
var traceFrameDepth = 0;
var traceSendPending = 0;

/* One-shot connection-object memory dump, for recovering the XXTEA session key
 * WITHOUT the (version-fragile, crash-prone) framer hook. The session key lives
 * in the connection object (Stage 2: "conn +0x14 = 16-byte key"); the stable
 * by-name send hook already holds that pointer. We dump a window of the object
 * plus one level of the heap pointers it holds, and brute-force the 16-byte key
 * out of it offline (diag_keyfromdump.py) by testing candidates against a real
 * encrypted frame — so the exact 2.1.33 offset doesn't need to be known. */
var connDumpCount = 0;
var CONN_DUMP_MAX = 8;   // dump the first N sends, not just one: the key-bearing
                         // register (esi->conn) is only stable on the plain
                         // movement/heartbeat send path, so one arbitrary send
                         // can miss it. Several snapshots almost always include
                         // one clean movement send where [esi+0x14] is the key.

function _hexOf(ab) {
    if (!ab) return null;
    var u = new Uint8Array(ab), s = '';
    for (var i = 0; i < u.length; i++) s += (u[i] < 16 ? '0' : '') + u[i].toString(16);
    return s;
}

function _readHex(p, n) {
    try { return _hexOf(p.readByteArray(n)); } catch (e) { return null; }
}

function _looksLikePtr(v) {
    // user-space heap-ish address on 32-bit Windows
    try {
        return !v.isNull() && v.compare(ptr('0x10000')) > 0 &&
               v.compare(ptr('0x7ffeffff')) < 0;
    } catch (e) { return false; }
}

function dumpConnRegions(conn, ctx) {
    var regions = [];
    var seen = {};          // addr string -> true (dedupe + cycle guard)
    var MAX = 600;          // hard cap on regions emitted

    function tryDump(addr, size, label) {
        if (regions.length >= MAX) return false;
        var k = addr.toString();
        if (seen[k]) return false;
        seen[k] = true;
        var h = _readHex(addr, size);
        if (!h) return false;
        regions.push({ label: label, addr: k, hex: h });
        return true;
    }

    function follow(baseAddr, span, childSize, prefix) {
        var kids = [];
        for (var o = 0; o < span && regions.length < MAX; o += 4) {
            try {
                var pv = baseAddr.add(o).readPointer();
                if (_looksLikePtr(pv)) {
                    var lab = prefix + '+0x' + o.toString(16) + '->';
                    if (tryDump(pv, childSize, lab)) kids.push(pv);
                }
            } catch (e) { /* not a pointer / unreadable */ }
        }
        return kids;
    }

    // PRIORITY ORDER. The session key travels in a REGISTER (edx carried the
    // cipher-state pointer into the framer) and lives in the send wrapper's
    // STACK locals. The nopoll CONNECTION object has been shown NOT to hold it,
    // so it goes LAST and shallow — earlier runs let its deep pointers eat the
    // whole region budget before the stack/registers were ever reached.
    if (ctx) {
        // 1) each register -> a GENEROUS window of what it points at, plus one
        // level deep. The recv key sat at [esi+0x14]; the SEND key lives in the
        // same connection struct but past the 0x100 we grabbed last time, so
        // dump much more of each register target (0x600) to reach it.
        var REGS = ['esi', 'edx', 'edi', 'ebp', 'eax', 'ecx', 'ebx'];
        for (var ri = 0; ri < REGS.length && regions.length < MAX; ri++) {
            try {
                var rv = ctx[REGS[ri]];
                if (rv && _looksLikePtr(rv) &&
                        tryDump(rv, 0x600, 'reg_' + REGS[ri])) {
                    follow(rv, 0x600, 0x100, 'reg_' + REGS[ri]);
                }
            } catch (e) { /* not a pointer */ }
        }
        // 2) the stack: wrapper locals + one level of the pointers they hold
        try {
            var sp = ctx.esp || ctx.sp;
            if (sp) {
                tryDump(sp, 0x1000, 'stack');
                var s1 = follow(sp, 0x1000, 0x100, 'stack');
                for (var j = 0; j < s1.length && regions.length < MAX; j++) {
                    follow(s1[j], 0x100, 0x60, 'S1_' + j);
                }
            }
        } catch (e) { /* stack read failed */ }
    }

    // 3) the connection object LAST and shallow (it doesn't carry the key)
    if (regions.length < MAX) {
        tryDump(conn, 0x400, 'conn');
        follow(conn, 0x400, 0x80, 'conn');
    }

    send({ type: 'conn_dump', ts: Date.now(), regions: regions });
}

rpc.exports = {
    setBacktraceBudget: function (n) { btBudget = n; return btBudget; },
    enablePlaintext: function () { plaintextOn = true; return installPlaintext(); },
    enableCipherTrace: function (n) {
        cipherTraceBudget = Math.max(1, n | 0);
        return installCipherTrace();
    }
};

function _traceSnapshot(msg, maxBytes) {
    var out = { msg: msg.toString() };
    try { out.buf = msg.add(4).readPointer().toString(); } catch (e) {}
    try { out.len = msg.add(8).readU32(); } catch (e) {}
    try { out.field14 = msg.add(0x14).readU32(); } catch (e) {}
    try { out.cursor = msg.add(0x1c).readU32(); } catch (e) {}
    try {
        var bp = msg.add(4).readPointer();
        var cap = maxBytes === undefined ? 512 : maxBytes;
        var n = Math.min(out.len || 0, cap);
        if (!bp.isNull() && n > 0) out.hex = _readHex(bp, n);
    } catch (e) {}
    return out;
}

function installCipherTrace() {
    if (cipherTraceInstalled) return 'already-installed';
    var m = Process.findModuleByName(CUBIC);
    if (!m) return 'no-module';
    cipherTraceInstalled = true;

    Interceptor.attach(m.base.add(RVA_FRAMER), {
        onEnter: function () {
            this.enabled = cipherTraceBudget > 0;
            if (!this.enabled) return;
            cipherTraceBudget--;
            traceFrameDepth++;
            this.msg = this.context.ecx;
            this.state = this.context.edx;
            var rec = { type: 'cipher_stage', stage: 'framer_enter',
                        ts: Date.now(), snapshot: _traceSnapshot(this.msg, 512) };
            if (!this.state.isNull()) rec.key_hex = _readHex(this.state, 16);
            send(rec);
        },
        onLeave: function () {
            if (!this.enabled) return;
            send({ type: 'cipher_stage', stage: 'framer_leave', ts: Date.now(),
                   snapshot: _traceSnapshot(this.msg, 512) });
            traceSendPending++;
            traceFrameDepth = Math.max(0, traceFrameDepth - 1);
        }
    });

    Interceptor.attach(m.base.add(RVA_XXTEA), {
        onEnter: function () {
            this.enabled = traceFrameDepth > 0;
            if (!this.enabled) return;
            this.buf = this.context.ecx;
            this.words = this.context.edx.toUInt32();
            this.size = Math.min(this.words * 4, 512);
            var keyPtr = null;
            try { keyPtr = this.context.esp.add(4).readPointer(); } catch (e) {}
            var rec = { type: 'cipher_stage', stage: 'xxtea_enter', ts: Date.now(),
                        buf: this.buf.toString(), words: this.words,
                        hex: _readHex(this.buf, this.size) };
            if (keyPtr && !keyPtr.isNull()) rec.key_hex = _readHex(keyPtr, 16);
            send(rec);
        },
        onLeave: function () {
            if (!this.enabled) return;
            send({ type: 'cipher_stage', stage: 'xxtea_leave', ts: Date.now(),
                   buf: this.buf.toString(), words: this.words,
                   hex: _readHex(this.buf, this.size) });
        }
    });

    // Four calls append the framing words. Recording the object fields before
    // and after each call settles the otherwise ambiguous +16/+28 length jump.
    Interceptor.attach(m.base.add(RVA_APPEND_U32), {
        onEnter: function () {
            this.enabled = traceFrameDepth > 0;
            if (!this.enabled) return;
            this.msg = this.context.ecx;
            try { this.value = this.context.esp.add(4).readU32(); } catch (e) {}
            this.before = _traceSnapshot(this.msg, 0);
        },
        onLeave: function () {
            if (!this.enabled) return;
            send({ type: 'cipher_stage', stage: 'append_u32', ts: Date.now(),
                   value: this.value, before: this.before,
                   after: _traceSnapshot(this.msg, 0) });
        }
    });

    // Current clients optionally apply a second send-only transform after the
    // XXTEA framer.  __fastcall ECX is the message and EDX is the repeating
    // key; stack args are key length (u16) and the per-packet counter (u32).
    Interceptor.attach(m.base.add(RVA_OUTER_CIPHER), {
        onEnter: function () {
            this.enabled = traceSendPending > 0;
            if (!this.enabled) return;
            this.msg = this.context.ecx;
            this.key = this.context.edx;
            try { this.keyLen = this.context.esp.add(4).readU16(); }
            catch (e) { this.keyLen = 0; }
            try { this.counter = this.context.esp.add(8).readU32(); }
            catch (e) {}
            send({ type: 'cipher_stage', stage: 'outer_enter', ts: Date.now(),
                   key_len: this.keyLen, key_hex: _readHex(this.key, this.keyLen),
                   counter: this.counter,
                   snapshot: _traceSnapshot(this.msg, 512) });
        },
        onLeave: function () {
            if (!this.enabled) return;
            send({ type: 'cipher_stage', stage: 'outer_leave', ts: Date.now(),
                   key_len: this.keyLen, counter: this.counter,
                   snapshot: _traceSnapshot(this.msg, 512) });
        }
    });

    // This instruction is immediately before the pushes for
    // nopoll_conn_send_binary(conn, buffer, length). It proves what Cubic.exe
    // itself hands to the transport library, independently of the export hook.
    Interceptor.attach(m.base.add(RVA_SEND_CALLSITE), {
        onEnter: function () {
            if (traceSendPending <= 0) return;
            traceSendPending--;
            var msg = this.context.ebx;
            send({ type: 'cipher_stage', stage: 'send_callsite', ts: Date.now(),
                   snapshot: _traceSnapshot(msg, 512) });
        }
    });

    return 'installed framer=+0x' + RVA_FRAMER.toString(16) +
           ' xxtea=+0x' + RVA_XXTEA.toString(16) +
           ' outer=+0x' + RVA_OUTER_CIPHER.toString(16) +
           ' send=+0x' + RVA_SEND_CALLSITE.toString(16);
}

function installPlaintext() {
    var base;
    try {
        var m = Process.findModuleByName(CUBIC);
        base = m ? m.base : null;
    } catch (e) { base = null; }
    if (base === null) { return 'no-module'; }

    var framer = base.add(RVA_FRAMER);
    Interceptor.attach(framer, {
        onEnter: function (args) {
            // __fastcall: ecx, edx passed in registers -> Frida maps to args[0], args[1]
            var msg = this.context.ecx;
            var cipherState = this.context.edx;
            if (msg.isNull()) return;

            function toHex(ab) {
                var u = new Uint8Array(ab), s = '';
                for (var i = 0; i < u.length; i++) {
                    s += (u[i] < 16 ? '0' : '') + u[i].toString(16);
                }
                return s;
            }

            var out = { type: 'plaintext', ts: Date.now() };
            var plain = null;
            try {
                // 2.1.33 swapped the two fields used by the old hook. Prefer
                // the current pointer/length layout, then fall back so captures
                // remain useful if an older executable is restored.
                var bufPtr = msg.add(4).readPointer();
                var len = msg.add(8).readU32();
                if (len > 0 && len < 0x100000 && !bufPtr.isNull()) {
                    plain = bufPtr.readByteArray(len);
                    out.layout = 'ptr4-len8';
                }
                if (!plain) {
                    len = msg.add(4).readU32();
                    bufPtr = msg.add(8).readPointer();
                    if (len > 0 && len < 0x100000 && !bufPtr.isNull()) {
                        plain = bufPtr.readByteArray(len);
                        out.layout = 'len4-ptr8';
                    }
                }
                if (plain) out.len = len;
            } catch (e) { out.err = 'msg read: ' + e; }

            // Dump the XXTEA key as hex whenever it CHANGES. Each backend
            // connection (realm switch) negotiates its own key, so emitting only
            // once misses every connection after the first.
            if (!cipherState.isNull()) {
                try {
                    var kh = toHex(cipherState.readByteArray(16));
                    if (kh !== lastKeyHex) {
                        out.key_hex = kh;
                        lastKeyHex = kh;
                    }
                } catch (e) { /* ignore */ }
            }
            send(out, plain);
        }
    });
    // Second hook: the v2 outbound-encryptor path. At RVA 0x111e06, esi = the
    // v2 session object whose [+0x78]/[+0x88] hold the second-layer key material
    // (the framer's cipher-state is a different, smaller struct). Dump them + a
    // window, tagged so we can line them up with the v2 (+28) frames offline.
    try {
        var v2site = base.add(0x111e06);
        Interceptor.attach(v2site, {
            onEnter: function () {
                var esi = this.context.esi;
                if (esi.isNull()) return;
                var o = { type: 'v2keys', ts: Date.now() };
                function th(p, n) { try { var u = new Uint8Array(p.readByteArray(n)), s = ''; for (var i = 0; i < u.length; i++) s += (u[i] < 16 ? '0' : '') + u[i].toString(16); return s; } catch (e) { return null; } }
                o.esi = esi.toString();
                o.k78 = th(esi.add(0x78), 16);
                o.k88 = th(esi.add(0x88), 16);
                o.ka8 = th(esi.add(0xa8), 16);
                // big window from the object so ANY offset is recoverable offline
                o.win = th(esi, 0x400);
                // also follow pointers found at +0x78/+0x88/+0xa8 in case the key
                // is stored indirectly (a pointer to a 16-byte buffer)
                try { o.p78 = th(esi.add(0x78).readPointer(), 32); } catch (e) {}
                try { o.p88 = th(esi.add(0x88).readPointer(), 32); } catch (e) {}
                try { o.pa8 = th(esi.add(0xa8).readPointer(), 32); } catch (e) {}
                send(o);
            }
        });
    } catch (e) { /* ignore */ }
    return 'installed@' + framer;
}

function log(msg) {
    send({ type: 'log', msg: msg });
}

/* ---- module-scoped export resolution (Frida 17 API, with fallbacks) ---- */

function findModule(name) {
    if (typeof Process.findModuleByName === 'function') {
        return Process.findModuleByName(name);
    }
    // very old fallback
    return Module.findBaseAddress(name) ? { name: name } : null;
}

function resolveExport(mod, name) {
    if (mod && typeof mod.findExportByName === 'function') {
        var p = mod.findExportByName(name);
        if (p !== null) return p;
    }
    if (typeof Module.findGlobalExportByName === 'function') {
        var g = Module.findGlobalExportByName(name);
        if (g !== null) return g;
    }
    if (typeof Module.findExportByName === 'function') {
        // legacy two-arg form
        try {
            var l = Module.findExportByName(MODULE, name);
            if (l !== null) return l;
        } catch (e) { /* ignore */ }
    }
    return null;
}

/* ---- hook installation ---- */

var installed = false;

function install(mod) {
    if (installed) return true;

    var need = [
        'nopoll_conn_new',
        'nopoll_conn_send_binary',
        'nopoll_conn_get_msg',
        'nopoll_msg_get_payload',
        'nopoll_msg_get_payload_size',
        'nopoll_msg_is_final',
        'nopoll_conn_close'
    ];

    var addr = {};
    var missing = [];
    for (var i = 0; i < need.length; i++) {
        var p = resolveExport(mod, need[i]);
        if (p === null) { missing.push(need[i]); } else { addr[need[i]] = p; }
    }
    if (missing.length > 0) {
        log('MISSING exports: ' + missing.join(', '));
        return false;
    }

    // Accessors we call (not hook) from inside the get_msg onLeave.
    // noPoll is cdecl; 'mscdecl' is the explicit name on x86/Windows but is
    // not accepted by every Frida build, so fall back to the platform default.
    function nf(ptr, ret, argTypes) {
        try {
            return new NativeFunction(ptr, ret, argTypes, 'mscdecl');
        } catch (e) {
            return new NativeFunction(ptr, ret, argTypes);
        }
    }

    var msgPayload = nf(addr['nopoll_msg_get_payload'], 'pointer', ['pointer']);
    var msgSize = nf(addr['nopoll_msg_get_payload_size'], 'int', ['pointer']);
    var msgIsFinal = nf(addr['nopoll_msg_is_final'], 'int', ['pointer']);

    function cstr(p) {
        try {
            return (p === null || p.isNull()) ? null : p.readUtf8String();
        } catch (e) {
            return '<unreadable>';
        }
    }

    /* -- connection setup: gives us host, port, path, subprotocol, origin -- */
    Interceptor.attach(addr['nopoll_conn_new'], {
        onEnter: function (args) {
            this.info = {
                host_ip: cstr(args[1]),
                host_port: cstr(args[2]),
                host_name: cstr(args[3]),
                get_url: cstr(args[4]),
                protocols: cstr(args[5]),
                origin: cstr(args[6])
            };
        },
        onLeave: function (retval) {
            this.info.conn = retval.toString();
            this.info.type = 'conn_new';
            this.info.ts = Date.now();
            send(this.info);
        }
    });

    /* -- outbound frames -- */
    Interceptor.attach(addr['nopoll_conn_send_binary'], {
        onEnter: function (args) {
            var len = args[2].toInt32();       // long -> 32-bit on win32
            if (len <= 0) return;

            // One-shot: dump the connection object so the session key can be
            // recovered offline (see dumpConnRegions). Wrapped so a bad read
            // can never disturb the real send.
            if (connDumpCount < CONN_DUMP_MAX) {
                connDumpCount++;
                try { dumpConnRegions(args[0], this.context); } catch (e) {
                    send({ type: 'log', msg: 'conn_dump failed: ' + e });
                }
            }

            /* Locate the crypto layer.
             * The payload reaching noPoll is already encrypted, so the caller
             * of send_binary is the encrypt-and-send routine inside Cubic.exe.
             * Its input buffer is the plaintext we actually want. Backtrace the
             * first few sends to get that address.
             */
            if (btBudget > 0) {
                btBudget--;
                var frames = [];
                ['ACCURATE', 'FUZZY'].forEach(function (mode) {
                    try {
                        var bt = Thread.backtrace(this.context, Backtracer[mode]);
                        frames.push({
                            mode: mode,
                            stack: bt.map(function (a) {
                                var s = DebugSymbol.fromAddress(a);
                                var m = Process.findModuleByAddress(a);
                                return {
                                    addr: a.toString(),
                                    module: m ? m.name : null,
                                    offset: m ? '+0x' + a.sub(m.base).toString(16) : null,
                                    sym: (s && s.name) ? s.name : null
                                };
                            })
                        });
                    } catch (e) { /* backtracer can fail on x86 w/o frame ptrs */ }
                }, this);
                send({ type: 'backtrace', ts: Date.now(), site: 'send_binary',
                       len: len, frames: frames });
            }
            var buf;
            try {
                buf = args[1].readByteArray(len);
            } catch (e) {
                send({ type: 'log', msg: 'tx read failed len=' + len });
                return;
            }
            send({
                type: 'frame',
                dir: 'tx',
                ts: Date.now(),
                len: len,
                fin: 1,
                conn: args[0].toString()
            }, buf);
        }
    });

    /* -- inbound frames -- */
    Interceptor.attach(addr['nopoll_conn_get_msg'], {
        onEnter: function (args) {
            this.conn = args[0];
        },
        onLeave: function (retval) {
            // Hot path: this is polled continuously and usually returns NULL.
            if (retval.isNull()) return;

            var size;
            try {
                size = msgSize(retval);
            } catch (e) {
                return;
            }
            if (size <= 0) return;

            var pay;
            try {
                pay = msgPayload(retval);
            } catch (e) {
                return;
            }
            if (pay.isNull()) return;

            var buf;
            try {
                buf = pay.readByteArray(size);
            } catch (e) {
                send({ type: 'log', msg: 'rx read failed size=' + size });
                return;
            }

            var fin = 1;
            try { fin = msgIsFinal(retval); } catch (e) { /* ignore */ }

            send({
                type: 'frame',
                dir: 'rx',
                ts: Date.now(),
                len: size,
                fin: fin,
                conn: this.conn.toString()
            }, buf);
        }
    });

    /* -- lifecycle -- */
    Interceptor.attach(addr['nopoll_conn_close'], {
        onEnter: function (args) {
            send({ type: 'conn_close', ts: Date.now(), conn: args[0].toString() });
        }
    });

    /* -- connection state, edge-triggered --
     * is_ok / is_ready are polled hard by the game loop, so we hook them on the
     * game's own thread (no cross-thread struct reads) and only emit when the
     * value actually changes. This tells us whether the WebSocket handshake
     * completed, vs. the client merely sitting idle waiting for login.
     */
    var lastState = {};

    function watchState(name, fnAddr) {
        Interceptor.attach(fnAddr, {
            onEnter: function (args) { this.conn = args[0].toString(); },
            onLeave: function (retval) {
                var key = name + '@' + this.conn;
                var v = retval.toInt32();
                if (lastState[key] === v) return;
                lastState[key] = v;
                send({
                    type: 'conn_state',
                    ts: Date.now(),
                    fn: name,
                    conn: this.conn,
                    value: v
                });
            }
        });
    }

    var okAddr = resolveExport(mod, 'nopoll_conn_is_ok');
    var readyAddr = resolveExport(mod, 'nopoll_conn_is_ready');
    if (okAddr !== null) watchState('is_ok', okAddr);
    if (readyAddr !== null) watchState('is_ready', readyAddr);

    installed = true;
    log('hooks installed on ' + MODULE);
    return true;
}

/* ---- wait for the DLL, then hook ----
 * libnopoll.dll is a static import so it is mapped before the entry point,
 * but under spawn+suspend we may run earlier than that. Poll briefly.
 */
(function main() {
    var mod = findModule(MODULE);
    if (mod !== null && install(mod)) return;

    log('waiting for ' + MODULE + ' ...');
    var tries = 0;
    var timer = setInterval(function () {
        tries++;
        var m = findModule(MODULE);
        if (m !== null && install(m)) {
            clearInterval(timer);
            return;
        }
        if (tries > 1500) {           // ~30s
            clearInterval(timer);
            log('ERROR: ' + MODULE + ' never appeared');
        }
    }, 20);
})();

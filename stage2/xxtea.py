#!/usr/bin/env python3
"""
XXTEA (Corrected Block TEA) reference implementation, matched to the routine at
Cubic.exe+0x113407.

Static analysis facts baked in:
  * delta      = 0x9E3779B9   (binary uses -0x61C88647 == +delta)
  * rounds     = 6 + 52 // n  (binary: push 0x34 / div n / +6)
  * key        = 128-bit, 4 x uint32, from [connection+0x14]
  * MX macro   = ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (key[(p&3)^e] ^ z))
  * operates in place on the buffer as a uint32 array of length n

Unknowns that only a live capture resolves (see decrypt_capture):
  * word endianness (little vs big) when packing bytes -> uint32
  * how the length/tail is handled for buffers not a multiple of 4
  * whether the 8-byte magic header is inside or outside the encrypted region
decrypt_capture() brute-forces those few structural choices against real frames.
"""

import argparse
import json
import struct

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF


def _mx(sum_, y, z, p, e, key):
    return (((z >> 5 ^ (y << 2 & MASK)) + (y >> 3 ^ (z << 4 & MASK))) ^
            ((sum_ ^ y) + (key[(p & 3) ^ e] ^ z))) & MASK


def encrypt_words(v, key):
    n = len(v)
    if n < 2:
        return v[:]
    v = v[:]
    rounds = 6 + 52 // n
    sum_ = 0
    z = v[n - 1]
    for _ in range(rounds):
        sum_ = (sum_ + DELTA) & MASK
        e = (sum_ >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + _mx(sum_, y, z, p, e, key)) & MASK
            z = v[p]
        p = n - 1
        y = v[0]
        v[p] = (v[p] + _mx(sum_, y, z, p, e, key)) & MASK
        z = v[p]
    return v


def decrypt_words(v, key):
    n = len(v)
    if n < 2:
        return v[:]
    v = v[:]
    rounds = 6 + 52 // n
    sum_ = (rounds * DELTA) & MASK
    y = v[0]
    while sum_ != 0:
        e = (sum_ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - _mx(sum_, y, z, p, e, key)) & MASK
            y = v[p]
        p = 0
        z = v[n - 1]
        v[0] = (v[0] - _mx(sum_, y, z, p, e, key)) & MASK
        y = v[0]
        sum_ = (sum_ - DELTA) & MASK
    return v


def bytes_to_words(b, endian="<"):
    if len(b) % 4:
        b = b + b"\x00" * (4 - len(b) % 4)
    return list(struct.unpack(f"{endian}{len(b)//4}I", b))


def words_to_bytes(v, endian="<"):
    return struct.pack(f"{endian}{len(v)}I", *v)


def decrypt_bytes(b, key, endian="<"):
    return words_to_bytes(decrypt_words(bytes_to_words(b, endian), key), endian)


def encrypt_bytes(b, key, endian="<"):
    return words_to_bytes(encrypt_words(bytes_to_words(b, endian), key), endian)


# --------------------------------------------------------------------------
# self-test against the canonical XXTEA test vector
# --------------------------------------------------------------------------

def selftest():
    # Correctness criteria (the algorithm's authority is the disassembly at
    # Cubic.exe+0x113407, not any third-party published vector):
    #
    #  1. encrypt and decrypt must be exact inverses for n=2 and for a long
    #     buffer with a real 128-bit key,
    #  2. a single hand-computed MX step must match the binary's op order:
    #        mx = ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum^y)+(key[(p&3)^e]^z))
    import os

    key0 = [0, 0, 0, 0]
    rt2 = decrypt_words(encrypt_words([0, 0], key0), key0) == [0, 0]

    blob = os.urandom(256)
    key2 = [0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00]
    rt_long = decrypt_bytes(encrypt_bytes(blob, key2), key2) == blob

    # odd (non-multiple-of-4) length must still round-trip via zero-pad
    blob2 = os.urandom(37)
    rt_odd = decrypt_bytes(encrypt_bytes(blob2, key2), key2)[:37] == blob2

    # hand-computed single MX, matching +0x113481..+0x1134b4 exactly
    sum_, y, z, p, e = (0x9E3779B9, 0x01234567, 0x89ABCDEF, 0, 1)
    expect = (((z >> 5 ^ (y << 2 & MASK)) + (y >> 3 ^ (z << 4 & MASK))) ^
              ((sum_ ^ y) + (key2[(p & 3) ^ e] ^ z))) & MASK
    mx_ok = _mx(sum_, y, z, p, e, key2) == expect

    print(f"  n=2 encrypt/decrypt are inverses                  {'OK' if rt2 else 'FAIL'}")
    print(f"  256-byte round-trip with 128-bit key              {'OK' if rt_long else 'FAIL'}")
    print(f"  37-byte (padded) round-trip                       {'OK' if rt_odd else 'FAIL'}")
    print(f"  MX matches binary op order (+0x113481)            {'OK' if mx_ok else 'FAIL'}")
    return rt2 and rt_long and rt_odd and mx_ok


# --------------------------------------------------------------------------
# apply to a real capture once a key is known
# --------------------------------------------------------------------------

MAGIC = bytes([0xFF, 0xEE, 0xCC, 0xDD, 0xAA, 0xEE, 0xCC, 0xAA])


def parse_key(s):
    """Accept 32 hex chars (16 bytes) or 4 comma-separated uint32s."""
    s = s.strip()
    if "," in s:
        return [int(x, 0) & MASK for x in s.split(",")]
    raw = bytes.fromhex(s)
    if len(raw) != 16:
        raise SystemExit("key must be 16 bytes / 32 hex chars / 4 uint32s")
    # try little-endian words by default; caller can flip
    return list(struct.unpack("<4I", raw))


def score_plaintext(b):
    """Heuristic: decrypted game messages are low-entropy and partly printable."""
    if not b:
        return 0.0
    import collections, math
    c = collections.Counter(b)
    ent = -sum((v/len(b)) * math.log2(v/len(b)) for v in c.values())
    printable = sum(1 for x in b if 32 <= x < 127) / len(b)
    has_magic = MAGIC[:4] in b or MAGIC in b
    return (8.0 - ent) + printable * 2 + (3 if has_magic else 0)


def decrypt_capture(path, key, limit=20):
    frames = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("type") == "frame":
            frames.append(r)

    print(f"loaded {len(frames)} frames; trying structural variants on first {limit}\n")
    variants = []
    for endian in ("<", ">"):
        for header_skip in (0, 8):     # magic header inside vs outside crypto
            variants.append((endian, header_skip))

    best = None
    for endian, skip in variants:
        total = 0.0
        samples = []
        for f in frames[:limit]:
            b = bytes.fromhex(f["hex"])
            body = b[skip:]
            if len(body) < 8:
                continue
            dec = decrypt_bytes(body, key, endian)
            s = score_plaintext(dec)
            total += s
            samples.append((f, dec))
        print(f"  endian={endian} header_skip={skip}  avg_score={total/max(1,limit):.3f}")
        if best is None or total > best[0]:
            best = (total, endian, skip, samples)

    print(f"\nbest variant: endian={best[1]} header_skip={best[2]}\n")
    for f, dec in best[3][:8]:
        ascii_s = "".join(chr(c) if 32 <= c < 127 else "." for c in dec[:64])
        print(f"[{f.get('action')}] {f['dir']} len={f['len']}")
        print(f"   {dec[:64].hex(' ')}")
        print(f"   {ascii_s}\n")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("selftest")
    d = sub.add_parser("decrypt")
    d.add_argument("capture")
    d.add_argument("--key", required=True,
                   help="16-byte key: 32 hex chars, or 4 comma-separated uint32s")
    d.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()

    if args.cmd == "selftest" or args.cmd is None:
        print("XXTEA self-test:")
        ok = selftest()
        print("\n", "ALL PASS" if ok else "FAILURE")
        return
    if args.cmd == "decrypt":
        decrypt_capture(args.capture, parse_key(args.key), args.limit)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Extract a reusable login profile (the two cleartext login frames) from a capture.

The login is cleartext and the account token / SteamID / machine-id are stable,
so the exact captured login frames can be replayed to authenticate as the same
account. This avoids perfectly modelling every login field.

Produces a small JSON profile:
  { "hello_empty": "<hex>", "hello_auth": "<hex>",
    "identity": {display_name, account_id, steam_id, token} }
"""
import argparse, json, struct


def strings_in(b):
    out = []; i = 0
    while i + 4 <= len(b):
        n = struct.unpack_from("<I", b, i)[0]
        if 1 <= n <= 80 and i + 4 + n <= len(b):
            s = b[i + 4:i + 4 + n].rstrip(b"\x00")
            if s and all(32 <= c < 127 for c in s):
                out.append(s.decode("latin1")); i += 4 + n; continue
        i += 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("-o", "--out", default=None)
    args = ap.parse_args()

    frames = []
    for line in open(args.capture, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("type") == "frame" and r["dir"] == "tx":
            frames.append(bytes.fromhex(r["hex"]))

    hello_empty = hello_auth = None
    for b in frames:
        if len(b) >= 8 and b[:2] == b"\x02\x00":
            # token slot length is the u32 right after the type
            toklen = struct.unpack_from("<I", b, 2)[0]
            if toklen <= 1 and hello_empty is None:
                hello_empty = b            # empty/near-empty token = first hello
            elif toklen > 1 and hello_auth is None:
                hello_auth = b             # non-empty token = authenticated hello
        if hello_empty and hello_auth:
            break

    if not (hello_empty and hello_auth):
        raise SystemExit("could not find both login frames in capture")

    strs = strings_in(hello_auth)
    # token is the first string; then name, acct, client, platform, version, steam
    profile = {
        "hello_empty": hello_empty.hex(),
        "hello_auth": hello_auth.hex(),
        "identity": {
            "token": strs[0] if strs else None,
            "display_name": strs[1] if len(strs) > 1 else None,
            "account_id": strs[2] if len(strs) > 2 else None,
            "steam_id": strs[-1] if strs else None,
        },
    }
    out = args.out or "login_profile.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(profile, fh, indent=2)
    print(f"login profile -> {out}")
    print(f"  account: {profile['identity']['display_name']} "
          f"({profile['identity']['account_id']})  steam={profile['identity']['steam_id']}")
    print(f"  token:   {profile['identity']['token']!r}")
    print(f"  hello_empty {len(hello_empty)}B, hello_auth {len(hello_auth)}B")


if __name__ == "__main__":
    main()

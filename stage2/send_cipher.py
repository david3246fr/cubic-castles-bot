#!/usr/bin/env python3
"""Cubic Castles' optional post-XXTEA client-to-server transform.

The server supplies ``key`` in the first length-prefixed field after the
compressed payload of its decrypted 0x0004/0x0001 message. A later field is a
human-readable server banner and must not be mistaken for the key. Once the
key has been received, the official client applies this transform to every
outgoing XXTEA frame.
"""

import struct


def _reverse_bits(value):
    value = ((value & 0x55) << 1) | ((value >> 1) & 0x55)
    value = ((value & 0x33) << 2) | ((value >> 2) & 0x33)
    return ((value << 4) | (value >> 4)) & 0xFF


# Cubic.exe's 256-byte table is bit reversal with the entries for 0 and 255
# exchanged.  Building it makes the relationship auditable while preserving
# the exact bytes in the executable at RVA 0x2c47a8 (build 2.1.33).
SBOX = bytes(0xFF if value == 0 else
             0x00 if value == 0xFF else
             _reverse_bits(value)
             for value in range(256))
INV_SBOX = bytes(SBOX.index(value) for value in range(256))

TRAILER_MAGIC = b"\xA0" * 4 + b"\x0A" * 4


def encode(inner_frame, key, counter):
    """Apply the official send-side transform to one post-XXTEA frame."""
    key = bytes(key)
    if not key:
        raise ValueError("outer-cipher key cannot be empty")
    data = bytearray(inner_frame)
    data += struct.pack("<I", counter & 0xFFFFFFFF)
    data += TRAILER_MAGIC
    for index, value in enumerate(data):
        data[index] = SBOX[(value - 0x78) & 0xFF] ^ key[index % len(key)]
    data.reverse()
    return bytes(data)


def decode(wire_frame, key):
    """Invert :func:`encode`; return ``(inner_frame, counter)``.

    A bad key or a frame not carrying this layer is rejected by checking the
    eight constant trailer bytes after inversion.
    """
    key = bytes(key)
    if not key:
        raise ValueError("outer-cipher key cannot be empty")
    if len(wire_frame) < 12:
        raise ValueError("outer-cipher frame is shorter than its trailer")
    data = bytearray(reversed(wire_frame))
    for index, value in enumerate(data):
        substituted = value ^ key[index % len(key)]
        data[index] = (INV_SBOX[substituted] + 0x78) & 0xFF
    if data[-8:] != TRAILER_MAGIC:
        raise ValueError("outer-cipher trailer check failed")
    counter = struct.unpack_from("<I", data, len(data) - 12)[0]
    return bytes(data[:-12]), counter


def parse_key_offer(body):
    """Extract the variable-length key from decrypted rx 0x0004/0x0001.

    Layout::

        u16 type=4, u16 stage=1,
        u32 compressed_length, compressed bytes,
        u32 key_length, key bytes,
        [u32 banner_length, banner bytes, ...]

    Returns ``None`` for any other or truncated body.
    """
    if len(body) < 12:
        return None
    msg_type, stage, blob_length = struct.unpack_from("<HHI", body)
    if msg_type != 0x0004 or stage != 1:
        return None
    key_length_offset = 8 + blob_length
    if key_length_offset + 4 <= len(body):
        key_length = struct.unpack_from("<I", body, key_length_offset)[0]
        key_offset = key_length_offset + 4
        # More fields can follow. In current production messages the next one
        # is a 24-byte "Betamax is watching you\0" banner. Requiring the key to
        # end the message made us select that banner in the fallback below,
        # producing plausible-looking 24-byte "keys" that the server ignored.
        if (0 <= key_length <= 100 and
                key_offset + key_length <= len(body)):
            return bytes(body[key_offset:key_offset + key_length])

    # Some older server variants report the compressed field's logical/
    # decompressed size rather than its serialized byte count. Keep the legacy
    # final-field recovery for those captures, but only after the authoritative
    # offset above has failed.
    for key_length in range(0, 101):
        key_length_offset = len(body) - key_length - 4
        if key_length_offset < 8:
            continue
        if struct.unpack_from("<I", body, key_length_offset)[0] == key_length:
            return bytes(body[key_length_offset + 4:])
    return None

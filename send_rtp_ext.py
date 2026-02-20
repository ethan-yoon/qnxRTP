#!/usr/bin/env python3
import argparse
import random
import socket
import struct
import time
from typing import List, Tuple

# RFC8285 profiles
PROFILE_ONE_BYTE = 0xBEDE
PROFILE_TWO_BYTE = 0x1000  # per RFC8285


def pad32(b: bytes) -> bytes:
    """Pad to 32-bit boundary with zero bytes."""
    return b + (b"\x00" * ((-len(b)) % 4))


# --------------------------
# RFC8285 One-Byte
# --------------------------
def build_8285_one_byte_elements(items: List[Tuple[int, bytes]]) -> bytes:
    """
    Build RFC8285 one-byte header extension elements.

    Each element:
      0x00: padding byte (allowed)
      1-byte header: 4-bit ID (1..14), 4-bit len (L-1), where L=1..16
      followed by L bytes of data
    ID=15 is reserved, ID=0 not used (0x00 is padding).
    """
    out = bytearray()
    for ext_id, value in items:
        if not (1 <= ext_id <= 14):
            raise ValueError("RFC8285 one-byte: id must be 1..14")
        if not (1 <= len(value) <= 16):
            raise ValueError("RFC8285 one-byte: len(value) must be 1..16 bytes")
        l = len(value) - 1
        out.append(((ext_id & 0x0F) << 4) | (l & 0x0F))
        out.extend(value)
    return bytes(out)


# --------------------------
# RFC8285 Two-Byte
# --------------------------
def build_8285_two_byte_elements(items: List[Tuple[int, bytes]]) -> bytes:
    """
    Build RFC8285 two-byte header extension elements.

    Each element:
      0x00: padding byte (allowed)
      1 byte: ID (1..255), 0 is reserved for padding
      1 byte: length (L) in bytes (0..255), followed by L bytes of data
    """
    out = bytearray()
    for ext_id, value in items:
        if not (1 <= ext_id <= 255):
            raise ValueError("RFC8285 two-byte: id must be 1..255")
        if len(value) > 255:
            raise ValueError("RFC8285 two-byte: len(value) must be <=255 bytes")
        out.append(ext_id & 0xFF)
        out.append(len(value) & 0xFF)
        out.extend(value)
    return bytes(out)


# --------------------------
# RTP packet builder
# --------------------------
def build_rtp_packet_with_extension(
    *,
    seq: int,
    ts: int,
    ssrc: int,
    pt: int,
    marker: int,
    ext_profile: int,
    ext_payload: bytes,
    payload: bytes,
) -> bytes:
    """
    RTP fixed header (12 bytes) + header extension + payload

    RFC3550 extension container:
      16-bit profile
      16-bit length in 32-bit words
      extension data (padded to 32-bit boundary)
    """
    V = 2
    P = 0
    X = 1
    CC = 0

    b0 = (V << 6) | (P << 5) | (X << 4) | (CC & 0x0F)
    b1 = ((1 if marker else 0) << 7) | (pt & 0x7F)

    rtp_hdr = struct.pack("!BBHII", b0, b1, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc & 0xFFFFFFFF)

    ext_data = pad32(ext_payload)
    ext_len_words = len(ext_data) // 4
    ext_hdr = struct.pack("!HH", ext_profile & 0xFFFF, ext_len_words & 0xFFFF)

    return rtp_hdr + ext_hdr + ext_data + payload


def make_extension(mode: str) -> Tuple[int, bytes]:
    """
    Returns (profile, ext_payload_bytes_without_32bit_padding)
    """
    mode = mode.lower()
    if mode == "rfc3550":
        # "old style": arbitrary profile + arbitrary blob (no 8285 structure)
        profile = 0x1234
        blob = b"RFC3550-RAW-EXT!"  # 16 bytes
        # You can put anything here; receiver will just show raw bytes.
        return profile, blob

    if mode in ("rfc8285-1", "8285-1", "one", "one-byte"):
        profile = PROFILE_ONE_BYTE
        # Example: 2 elements + a padding 0x00
        # id=1, 4 bytes; id=5, 8 bytes
        elems = build_8285_one_byte_elements([
            (1, bytes([0x11, 0x22, 0x33, 0x44])),
            (5, b"ABCD1234"),
        ])
        return profile, elems + b"\x00"

    if mode in ("rfc8285-2", "8285-2", "two", "two-byte"):
        profile = PROFILE_TWO_BYTE
        # Example: 2 elements + a padding 0x00
        # id=1 length 4; id=0x10 length 12
        elems = build_8285_two_byte_elements([
            (1, bytes([0xAA, 0xBB, 0xCC, 0xDD])),
            (0x10, b"HELLO-TWO-BYTE"),  # 13 bytes actually; ok (<=255)
        ])
        return profile, elems + b"\x00"

    raise ValueError(f"Unknown mode: {mode}. Use rfc3550 | rfc8285-1 | rfc8285-2")


def main():
    ap = argparse.ArgumentParser(
        description="Send RTP packets with header extensions: RFC3550 raw, RFC8285 one-byte, RFC8285 two-byte"
    )
    ap.add_argument("--ip", default="127.0.0.1", help="Destination IP (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=53551, help="Destination RTP port (default: 53551)")
    ap.add_argument(
        "--mode",
        default="rfc8285-1",
        choices=["rfc3550", "rfc8285-1", "rfc8285-2"],
        help="Extension mode",
    )
    ap.add_argument("--pt", type=int, default=96, help="RTP payload type (default: 96)")
    ap.add_argument("--pps", type=int, default=50, help="Packets per second (default: 50)")
    ap.add_argument("--count", type=int, default=300, help="Number of packets to send (default: 300)")
    ap.add_argument("--payload-bytes", type=int, default=20, help="Dummy payload size (default: 20)")
    ap.add_argument("--ssrc", type=lambda x: int(x, 0), default=None, help="SSRC (e.g. 0x11223344). Random if omitted")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    ssrc = args.ssrc if args.ssrc is not None else random.getrandbits(32)
    seq = random.getrandbits(16)
    ts = random.getrandbits(32)

    profile, ext_payload = make_extension(args.mode)
    payload = b"\x00" * max(0, args.payload_bytes)

    interval = 1.0 / max(1, args.pps)

    print(f"[+] dst={args.ip}:{args.port} mode={args.mode} pt={args.pt} pps={args.pps} count={args.count}")
    print(f"[+] ssrc=0x{ssrc:08x} seq_start={seq} ts_start={ts}")
    print(f"[+] ext_profile=0x{profile:04x} ext_len(unpadded)={len(ext_payload)} bytes, padded={len(pad32(ext_payload))} bytes")

    for i in range(args.count):
        pkt = build_rtp_packet_with_extension(
            seq=seq,
            ts=ts,
            ssrc=ssrc,
            pt=args.pt,
            marker=0,
            ext_profile=profile,
            ext_payload=ext_payload,
            payload=payload,
        )
        sock.sendto(pkt, (args.ip, args.port))
        seq = (seq + 1) & 0xFFFF
        ts = (ts + 3000) & 0xFFFFFFFF
        time.sleep(interval)

    sock.close()
    print("[+] done")


if __name__ == "__main__":
    main()

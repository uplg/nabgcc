#!/usr/bin/env python3
"""Listener for the Nabaztag diag ring UDP export (src/utils/diag.c).

The diag firmware, once associated to the known-good network, broadcasts the
console ring as UDP datagrams on port 9999 (broadcast MAC + 255.255.255.255),
one ship every ~4 s, 15 ships max. Each datagram:

  magic "NDG1" | seq u8 | nchunks u8 | offset u16le | clen u16le |
  total u32le | pad u16 | <clen ring bytes>

Run on the Mac while it is on the same network as the rabbit (the phone
hotspot: `networksetup -setairportnetwork en1 Remifasol blabliblou`):

  python3 scripts/diag-listen.py [--out /tmp/nabring.txt]

Every completed ship overwrites --out and is printed once; later (longer)
ships print only the delta.
"""
import argparse
import socket
import sys
import time

MAGIC = b"NDG1"
HDR = 16

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--out", default="/tmp/nabring.txt")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", args.port))
    print(f"listening on udp/{args.port}, ring will be saved to {args.out}",
          file=sys.stderr)

    chunks = {}   # offset -> bytes
    total = None
    printed = 0   # bytes already echoed to stdout

    while True:
        data, addr = sock.recvfrom(2048)
        if data[:4] == b"NDC1":
            # Deafness-campaign counters (-DDIAG_COUNTERS): one ASCII line
            # every 2 s. Timestamp it; the wedge is diagnosed by which
            # counters stop moving.
            stamp = time.strftime("%H:%M:%S")
            print(f"{stamp} {addr[0]} {data.decode('ascii', 'replace')}")
            sys.stdout.flush()
            continue
        if len(data) < HDR or data[:4] != MAGIC:
            continue
        seq = data[4]
        nchunks = data[5]
        offset = int.from_bytes(data[6:8], "little")
        clen = int.from_bytes(data[8:10], "little")
        newtotal = int.from_bytes(data[10:14], "little")
        payload = data[HDR:HDR + clen]
        if len(payload) != clen:
            continue

        if total != newtotal:
            total = newtotal
            print(f"\n--- ship from {addr[0]}: ring is {total} bytes, "
                  f"{nchunks} chunk(s) ---", file=sys.stderr)
        chunks[offset] = payload

        # do we have a contiguous [0, total) ?
        have = 0
        while have < total and have in chunks:
            have += len(chunks[have])
        if have >= total and total > 0:
            ring = b"".join(chunks[o] for o in sorted(chunks) if o < total)[:total]
            with open(args.out, "wb") as f:
                f.write(ring)
            text = ring.decode("latin-1")
            if len(text) > printed:
                sys.stdout.write(text[printed:])
                sys.stdout.flush()
                printed = len(text)
            print(f"\n--- complete ({total} bytes) -> {args.out} ---",
                  file=sys.stderr)

if __name__ == "__main__":
    main()

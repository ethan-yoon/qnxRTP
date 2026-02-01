import struct
import sys

if len(sys.argv) != 3:
    print("usage: python3 nal2hevc.py <in.bin> <out.hevc>")
    sys.exit(1)

inp, outp = sys.argv[1], sys.argv[2]

with open(inp, "rb") as f, open(outp, "wb") as g:
    while True:
        hdr = f.read(4)
        if not hdr:
            break
        if len(hdr) != 4:
            raise SystemExit("truncated length")
        n = struct.unpack(">I", hdr)[0]
        data = f.read(n)
        if len(data) != n:
            raise SystemExit("truncated payload")
        g.write(data)

print("wrote", outp)


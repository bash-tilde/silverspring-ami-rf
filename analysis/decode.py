"""Decode a frames.json through the full transport stack and validate.

Demonstrates the recovered protocol end-to-end: de-whiten, verify CRC-32,
parse the header grammar, read the channel from the PHY header. Runs on the
synthetic sample with no real-world data.

Usage:  python3 decode.py ../data/sample_frames.json
"""
import json, sys, os, collections
sys.path.insert(0, os.path.dirname(__file__))
from protocol import dewhiten, check_crc, PREFIX, channel_freq_mhz

def sid(p, o=5):
    if p[o:o+2] == [0xFF, 0xFE]:
        return "AP:%02X%02X" % (p[o+3], p[o+4]) if len(p) > o+4 else "AP:?"
    return "%02X%02X%02X" % (p[o], p[o+1], p[o+2])

def main(path):
    rows = json.load(open(path))
    ok = collections.Counter(); chans = collections.Counter()
    print(f"{'len':>4} {'chan':>5} {'freq MHz':>9} {'src':>8} {'CRC':>4}  header")
    for r in rows:
        p = dewhiten(r['psdu'])
        crc = check_crc(p)
        ok[crc] += 1
        N = 255 - int(r['sync'][16:24], 2)
        chans[N] += 1
        hdr = ' '.join(f"{b:02X}" for b in p[8:14])
        print(f"{r['ln']:>4} {N:>5} {channel_freq_mhz(N):>9.3f} {sid(p):>8} "
              f"{'OK' if crc else 'FAIL':>4}  {hdr}")
    print(f"\nframes: {sum(ok.values())}   CRC valid: {ok[True]}/{sum(ok.values())}")
    print(f"channels seen: {sorted(chans)}")
    assert ok[False] == 0, "some frames failed CRC — codec inconsistent"
    print("all frames de-whitened and CRC-validated ✓")

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else
         os.path.join(os.path.dirname(__file__), '..', 'data', 'sample_frames.json'))

"""Round-trip and self-consistency tests. Run: python3 test_codec.py"""
import os, sys, json
sys.path.insert(0, os.path.dirname(__file__))
from protocol import whiten, dewhiten, check_crc, trailer, K, PREFIX

def test_whiten_roundtrip():
    for ln in (12,14,22,29,55,111):
        p = PREFIX + [((i*37) ^ 0x5A) & 0xFF for i in range(ln-5-1)]
        p = p + [trailer(p, ln)]
        phase = [0xA5,0x5A,0x3C,0xC3,0x99]
        c = whiten(p, phase)
        # whitening must be non-trivial: bytes 5+ must actually change
        assert sum(1 for a,b in zip(p[5:],c[5:]) if a!=b) > 0, f"whitening is a no-op at len {ln}"
        assert dewhiten(c) == p, f"round-trip failed at len {ln}"

def test_crc_validates():
    for ln in (12,14,22,29,55,111):
        p = PREFIX + [((i*37) ^ 0x5A) & 0xFF for i in range(ln-5-1)]
        p = p + [trailer(p, ln)]
        assert check_crc(p), f"CRC self-check failed at len {ln}"
        assert check_crc(dewhiten(whiten(p, [0x11,0x22,0x33,0x44,0x55]))), f"CRC after whiten/dewhiten at len {ln}"

def test_sample_frames():
    path = os.path.join(os.path.dirname(__file__),'..','data','sample_frames.json')
    for r in json.load(open(path)):
        assert check_crc(dewhiten(r['psdu'])), "sample frame failed CRC"

if __name__ == '__main__':
    for name, fn in list(globals().items()):
        if name.startswith('test_'):
            fn(); print(f"  PASS {name}")
    print("all tests passed")

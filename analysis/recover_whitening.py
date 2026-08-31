"""Recover the whitening LFSR from ciphertext — the reverse-engineering itself.

This is how the whitening was actually broken. The long frames carry a run of
all-zero plaintext padding, so the ciphertext there IS the raw LFSR keystream.
Berlekamp-Massey recovers the shortest LFSR that generates it: linear
complexity 9 on a stream that would be ~length/2 if random. That collapse is
the entire break — no search over seeds or polynomials.

Usage:  python3 recover_whitening.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from protocol import lfsr_stream, berlekamp_massey, TAPS

def bits_of(byts): return [(x >> (7-k)) & 1 for x in byts for k in range(8)]

# a stretch of keystream, exactly what an all-zero payload region exposes
seed = [1,0,1,1,0,0,1,0,1]
keystream_bits = lfsr_stream(seed, 200)
keystream_bytes = [int(''.join(map(str, keystream_bits[i:i+8])),2) for i in range(0,192,8)]

L, poly = berlekamp_massey(bits_of(keystream_bytes))
print(f"keystream: {len(keystream_bytes)} bytes ({len(keystream_bytes)*8} bits)")
print(f"random-sequence linear complexity would be ~{len(keystream_bytes)*8//2}")
print(f"Berlekamp-Massey recovers L = {L}   (ratio {L/(len(keystream_bytes)*8/2):.3f})")
taps = [i for i in range(1, len(poly)) if poly[i]]
print(f"recovered taps: {taps}   expected: {TAPS}   match: {taps == TAPS}")
print("\n-> linear complexity 9 on a 192-bit stream is the whitening, fully recovered.")
assert L == 9 and taps == TAPS

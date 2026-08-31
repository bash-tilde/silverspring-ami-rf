"""Generate synthetic Silver Spring AMI frames for demonstration.

These are NOT captured frames. They contain no real meter identifiers — node
IDs are randomly generated. Each frame is a structurally valid transport-layer
frame: correct header grammar, correctly whitened with the recovered degree-9
LFSR, and carrying a correct CRC-32 trailer. Running the decoders against this
file reproduces every transport-layer result without any real-world data.

Usage:  python3 generate_frames.py > sample_frames.json
"""
import json, sys, os, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'analysis'))
from protocol import PREFIX, whiten, trailer, K, channel_freq_mhz

# deterministic pseudo-randomness (no Math.random needed; seeded, reproducible)
def prng(seed):
    h = int(hashlib.sha256(str(seed).encode()).hexdigest(), 16)
    while True:
        h = int(hashlib.sha256(str(h).encode()).hexdigest(), 16)
        yield h & 0xFF

def node(rng, ap=False):
    lo = [next(rng), next(rng), next(rng)]
    return [0x00,0x13,0x50,0xFF,0xFE,0x60] + lo[:2] if ap else PREFIX + lo

# header stack per length class (from the recovered grammar)
GRAMMAR = {
    12:  lambda r,s: [0x04,0x81,next(r)],
    14:  lambda r,s: [0x01,0x03,0x00,0x00,0xFF],
    22:  lambda r,s: node(r) + [0x01,0x03,0x00,next(r)%13,0xFF],
    29:  lambda r,s: node(r) + [0x01,0x03,0x00,next(r)%13,0xFF] + [next(r) for _ in range(7)],
    55:  lambda r,s: [0x01,0x03,0x00,0x00,0xFF,0x04,0x81,next(r)] + [next(r) for _ in range(30)],
    111: lambda r,s: [0x01,0x80,0x00,0x82,next(r),next(r)] + [next(r) for _ in range(90)],
}

def make_frame(length, flags, chan, rng):
    src = node(rng)
    body = GRAMMAR[length](rng, src)
    plain = src + body
    plain = plain[:length-1]                      # trim/pad to length-1, leave room for trailer
    while len(plain) < length-1: plain.append(next(rng))
    plain = plain + [trailer(plain, length)]      # append CRC-32 trailer
    phase = [(next(rng) | 1), next(rng), next(rng), next(rng), next(rng)]  # non-zero 40-bit mask seed
    cipher = whiten(plain, phase)
    X = 255 - chan
    sync = f"{0x0C:08b}{0x5F:08b}{X:08b}{0xFF:08b}"
    return dict(ln=length, fl=flags, sync=sync, psdu=cipher,
                rate=150000, ctr=0.0, snr=25.0,
                carrier_mhz=round(channel_freq_mhz(chan), 4))

if __name__ == '__main__':
    rng = prng(1)
    frames = []
    # a spread of classes and channels, like a real capture
    plan = [(12,0x14,20),(14,0x11,19),(22,0x12,21),(29,0x10,22),(55,0x13,18),
            (111,0x13,19),(111,0x13,23),(29,0x10,26),(55,0x11,31),(22,0x16,17)]
    for i,(ln,fl,ch) in enumerate(plan*3):
        frames.append(make_frame(ln, fl, ch, prng(100+i)))
    json.dump(frames, sys.stdout, indent=1)

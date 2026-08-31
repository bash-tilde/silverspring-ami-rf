"""Silver Spring / Aclara AMI mesh — transport-layer codec.

Everything here was recovered by passive reverse-engineering of a residential
electric meter's 900 MHz mesh radio (see docs/protocol.md). It decodes the
TRANSPORT layer only: framing, de-whitening, CRC, addressing, channel. The
application payload is AES-CCM* encrypted and is NOT recoverable — this library
does not attempt to break it.

  whitening : degree-9 LFSR, taps x^9+x^8+x^5+x^2+1, recovered by Berlekamp-Massey
  integrity : CRC-32 (poly 0x04C11DB7), trailer = MSB(crc) XOR K[len]
  framing   : length-keyed header grammar, channel carried in the clear
"""
from functools import reduce

TAPS   = [1, 2, 5, 8, 9]                       # b[n] = b[n-1]^b[n-2]^b[n-5]^b[n-8]^b[n-9]
PREFIX = [0x00, 0x13, 0x50, 0x05, 0x00]        # Silver Spring serial prefix (known plaintext)
K = {9:0x78, 12:0x0E, 14:0x5B, 16:0x7A, 21:0xEB, 22:0xE8, 29:0x05,
     55:0xA6, 111:0x7D, 112:0x2D, 134:0x6E, 213:0x60}   # per-length CRC offset
_X = lambda l: reduce(lambda a, b: a ^ b, l)

# ---- degree-9 LFSR whitening -----------------------------------------
def lfsr_stream(seed_bits, nbits):
    b = list(seed_bits)
    while len(b) < nbits:
        b.append(_X([b[-i] for i in TAPS]))
    return b

def _bits(byts):   return [(x >> (7 - k)) & 1 for x in byts for k in range(8)]
def _bytes(bits):  return [int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits)//8*8, 8)]

def mask_for(cipher):
    """The whitening mask for a frame, recovered from its own first 5 bytes.
    Because plaintext[0:5] is the constant PREFIX, mask[0:5] = cipher[0:5] ^ PREFIX
    gives 40 bits — far more than the 9 needed to seed the LFSR."""
    seed = _bits([c ^ p for c, p in zip(cipher[:5], PREFIX)])
    return _bytes(lfsr_stream(seed, len(cipher) * 8))

def dewhiten(cipher):
    return [a ^ b for a, b in zip(cipher, mask_for(cipher))]

def whiten(plain):                              # inverse, for the frame generator
    seed = _bits([p ^ q for p, q in zip(plain[:5], PREFIX)])
    m = _bytes(lfsr_stream(seed, len(plain) * 8))
    return [a ^ b for a, b in zip(plain, m)]

# ---- CRC-32 trailer --------------------------------------------------
def crc32(data, poly=0x04C11DB7, c=0):
    for b in data:
        c ^= b << 24
        for _ in range(8):
            c = ((c << 1) ^ poly) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
    return c

def trailer(plain_without_trailer, length):
    return ((crc32(plain_without_trailer) >> 24) & 0xFF) ^ K[length]

def check_crc(plain):
    return len(plain) in K and trailer(plain[:-1], len(plain)) == plain[-1]

# ---- channel plan ----------------------------------------------------
def channel_freq_mhz(N):                        # N carried in the PHY header (0C 5F X FF, N=255-X)
    return 902.2990 + 0.299991 * N              # 87 channels, measured

# ---- Berlekamp-Massey (the tool that recovered the whitening) --------
def berlekamp_massey(bits):
    n = len(bits); c = [0]*n; b = [0]*n; c[0] = b[0] = 1; L = 0; m = -1
    for N in range(n):
        d = bits[N]
        for i in range(1, L+1): d ^= c[i] & bits[N-i]
        if d:
            t = c[:]
            for i in range(n - (N - m)): c[i + N - m] ^= b[i]
            if 2*L <= N: L = N + 1 - L; m = N; b = t
    return L, c[:L+1]

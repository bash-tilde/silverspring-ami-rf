# silverspring-ami-rf

Passive reverse-engineering of a **Silver Spring Networks / Itron AMI mesh** —
the 900 MHz radio protocol used by many residential electric meters (here, an
Aclara I-210+c carrying a Silver Spring NIC 511 module).

Starting from nothing but an RTL-SDR and raw IQ, this project recovers the
entire **transport layer** of an undocumented proprietary mesh: modulation,
framing, data whitening, integrity check, addressing, channel plan and the
frequency-hopping sequence. The application payload is AES-CCM* encrypted and is
**not** recovered — the work stops cleanly at that wall and documents exactly why.

## Scope and ethics

This is **passive receive-only research on my own meter.**

- Every result comes from demodulating radio signals already present in the air.
- **Nothing was transmitted.** No frames were injected into the utility mesh.
- **No cryptography was attacked.** The encrypted payload is left encrypted; no
  key extraction, firmware dumping, or physical tampering was attempted.
- Real meter identifiers (mine and neighbouring meters') and personal account
  data are **excluded from this repository**. All frames included here are
  **synthetic** — structurally valid, but generated, containing no real IDs.

Decoding radio you lawfully receive is the whole of the activity. The point at
which the protocol becomes closed (authenticated, encrypted mesh traffic) is
respected as the stopping point.

## What was recovered

| Layer | Result |
|---|---|
| **Modulation** | 2-GFSK, h≈0.5, 100/150/200 kBd, per-frame |
| **PHY header** | `0C 5F <channel> FF` — channel number carried in the clear |
| **Channel plan** | 87 channels, `f(N) = 902.2990 + 0.299991·N` MHz (measured; contradicts the published 64-channel figure) |
| **Whitening** | degree-9 LFSR, taps x⁹+x⁸+x⁵+x²+1, recovered by **Berlekamp–Massey** |
| **Integrity** | **CRC-32** (poly 0x04C11DB7), trailer = MSB(crc) ⊕ K[len]; validates 386/392 real frames |
| **Framing** | length-keyed header grammar, every byte of 12 length classes accounted for |
| **Flags byte** | `base(channel) ⊕ frame-type` (broadcast / unicast / beacon) |
| **Beacon timing** | exact 120.000 s lattice, phase σ = 0.25 s over 450+ cycles |
| **Hop sequence** | channel = f(slot mod 83), 153/153 causal forward predictions |
| **Topology** | dual-homed relay → two EUI-64 access points → head-end |
| **Payload** | AES-CCM* encrypted — **not** recovered (confirmed via keystream-independence test) |

## Techniques

DSP demodulation and timing recovery · **Berlekamp–Massey** LFSR recovery ·
GF(2) linear-algebra CRC identification · known-plaintext whitening recovery ·
statistical hypothesis testing with permutation nulls · Poisson cadence modelling ·
multi-receiver capture orchestration.

Methodology note: several early findings were **retracted** when larger samples
or controls contradicted them (a spurious byte "counter", a burst-rate
correlation, a mis-attributed modulation mode). The retractions are kept in the
write-up — the discipline of disproving your own results is part of the work.

## Quick start

Requires only Python 3 (stdlib). No SDR or captured data needed — the demo runs
on synthetic frames.

```
python3 data/generate_frames.py > data/sample_frames.json   # generate valid frames
python3 analysis/decode.py                                   # de-whiten + CRC + parse
python3 analysis/recover_whitening.py                        # Berlekamp–Massey break
python3 analysis/test_codec.py                               # round-trip tests
```

## Structure

```
analysis/
  protocol.py            transport codec: whitening LFSR + CRC-32 + channel plan
  decode.py              end-to-end frame decoder (de-whiten, CRC, grammar)
  recover_whitening.py   Berlekamp–Massey recovery of the LFSR — the actual break
  test_codec.py          round-trip / self-consistency tests
data/
  generate_frames.py     synthetic frame generator (no real identifiers)
  sample_frames.json     generated sample
docs/
  protocol.md            full technical write-up
```

## Prior art

The closest published work is the [RECESSIM Silver Spring Networks page](https://wiki.recessim.com/view/Silver_Spring_Networks_Protocol),
a stub recording an unverified sync word and an incorrect channel count, with no
whitening, CRC or framing. This project supersedes it on those points. The
metering payload being encrypted matches the general AMI security literature:
the only demonstrated path *into* the payload is firmware/key extraction from the
hardware, never a break of the radio ciphertext.

## License

MIT — see [LICENSE](LICENSE).

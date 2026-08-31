/** @file
    Silver Spring Networks / Aclara AMI mesh — transport-layer decoder.

    Copyright (C) 2026 bash-tilde

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    SPDX-License-Identifier: GPL-2.0-or-later

    Decodes the TRANSPORT layer of the Silver Spring Networks 900 MHz mesh
    (as used by e.g. Aclara I-210+c meters with a NIC 511 module). It emits
    the source/destination node identifiers, channel, frame type and length,
    with a validated CRC-32. The application payload is AES-CCM* encrypted and
    is NOT decoded — this decoder reads addressing and framing only.

    Protocol (reverse-engineered passively; see
    https://github.com/bash-tilde/silverspring-ami-rf):

        preamble 0x55.. | 0C 5F <X> FF | PHR(2, inverted) | PSDU(whitened)

      - sync      0C 5F .. FF ; byte 2 (X) carries the channel, N = 255 - X
      - PHR       2 bytes, bitwise-inverted: [length][flags]
      - whitening degree-9 LFSR, b[n]=b[n-1]^b[n-2]^b[n-5]^b[n-8]^b[n-9]
                  the mask is recoverable from the frame's own first 5 bytes,
                  because plaintext[0:5] is the constant prefix 00 13 50 05 00
      - integrity trailing byte = MSB(CRC-32/0x04C11DB7 over de-whitened
                  frame[:-1]) XOR K[length]

    NOTE: the whitening (LFSR) and CRC-32 core below are verified byte-for-byte
    against the Python reference in analysis/. This is otherwise a scaffold: the
    sync bit-alignment, PHR inversion and multi-rate handling (100/150/200 kBd)
    should be verified against live captures before merging. It is registered
    at ~150 kbps, the predominant rate.
*/

#include "decoder.h"

static uint8_t const SS_PREFIX[5] = {0x00, 0x13, 0x50, 0x05, 0x00};

// per-length CRC offset K[len]; 0xFFFF = unknown length
static uint8_t ss_crc_k(int len)
{
    switch (len) {
        case 9:   return 0x78; case 12:  return 0x0E; case 14:  return 0x5B;
        case 16:  return 0x7A; case 21:  return 0xEB; case 22:  return 0xE8;
        case 29:  return 0x05; case 55:  return 0xA6; case 111: return 0x7D;
        case 112: return 0x2D; case 134: return 0x6E; case 213: return 0x60;
        default:  return 0xFF; // sentinel: unrecognised class
    }
}

// CRC-32, poly 0x04C11DB7, MSB-first, init 0
static uint32_t ss_crc32(uint8_t const *data, int len)
{
    uint32_t c = 0;
    for (int i = 0; i < len; i++) {
        c ^= (uint32_t)data[i] << 24;
        for (int b = 0; b < 8; b++)
            c = (c & 0x80000000) ? ((c << 1) ^ 0x04C11DB7) : (c << 1);
    }
    return c;
}

// De-whiten in place: mask seeded from cipher[0:5] ^ prefix, extended by the LFSR.
static void ss_dewhiten(uint8_t *buf, int len)
{
    int nbits = len * 8;
    uint8_t *m = malloc(nbits);
    if (!m) return;
    // first 40 mask bits = (cipher[0:5] ^ prefix)
    for (int i = 0; i < 5 && i < len; i++) {
        uint8_t v = buf[i] ^ SS_PREFIX[i];
        for (int k = 0; k < 8; k++)
            m[i * 8 + k] = (v >> (7 - k)) & 1;
    }
    // extend by b[n] = b[n-1]^b[n-2]^b[n-5]^b[n-8]^b[n-9]
    for (int n = 40; n < nbits; n++)
        m[n] = m[n-1] ^ m[n-2] ^ m[n-5] ^ m[n-8] ^ m[n-9];
    // apply
    for (int i = 0; i < len; i++) {
        uint8_t mb = 0;
        for (int k = 0; k < 8; k++) mb = (mb << 1) | m[i * 8 + k];
        buf[i] ^= mb;
    }
    free(m);
}

static int silverspring_ssn_decode(r_device *decoder, bitbuffer_t *bitbuffer)
{
    // sync: 0C 5F
    uint8_t const sync[] = {0x0c, 0x5f};
    int decoded = 0;

    for (unsigned row = 0; row < bitbuffer->num_rows; row++) {
        unsigned bits = bitbuffer->bits_per_row[row];
        if (bits < 8 * 12) continue; // shortest useful frame

        unsigned pos = bitbuffer_search(bitbuffer, row, 0, sync, 16);
        if (pos >= bits) continue;    // no sync in this row
        pos += 16;                    // consume 0C 5F

        uint8_t hdr[4];               // X, FF, PHR0, PHR1
        if (pos + 32 > bits) continue;
        bitbuffer_extract_bytes(bitbuffer, row, pos, hdr, 32);
        pos += 32;

        int channel = 255 - hdr[0];
        int length  = 0xFF ^ hdr[2];  // PHR high byte, inverted
        int flags   = 0xFF ^ hdr[3];  // PHR low byte, inverted
        uint8_t koff = ss_crc_k(length);
        if (koff == 0xFF) continue;   // unrecognised length class
        if (pos + length * 8 > bits) continue;

        uint8_t psdu[256];
        bitbuffer_extract_bytes(bitbuffer, row, pos, psdu, length * 8);
        ss_dewhiten(psdu, length);

        // integrity: trailing byte == MSB(crc32(psdu[:-1])) ^ K[len]
        uint8_t trailer = ((ss_crc32(psdu, length - 1) >> 24) & 0xFF) ^ koff;
        if (trailer != psdu[length - 1])
            return DECODE_FAIL_MIC;

        // prefix sanity
        if (memcmp(psdu, SS_PREFIX, 5) != 0)
            continue;

        char src[7];
        snprintf(src, sizeof(src), "%02X%02X%02X", psdu[5], psdu[6], psdu[7]);

        // destination present when bytes 8..11 == 00 13 50 05
        char dst[7] = "";
        int have_dst = (length >= 16 && psdu[8] == 0x00 && psdu[9] == 0x13 &&
                        psdu[10] == 0x50 && psdu[11] == 0x05);
        if (have_dst)
            snprintf(dst, sizeof(dst), "%02X%02X%02X", psdu[13], psdu[14], psdu[15]);

        char const *ftype = (length == 111) ? "beacon"
                          : have_dst        ? "unicast"
                                            : "broadcast";

        /* clang-format off */
        data_t *data = data_make(
                "model",      "",            DATA_STRING, "SilverSpring-SSN",
                "id",         "Source node", DATA_STRING, src,
                "dst",        "Dest node",   DATA_COND, have_dst, DATA_STRING, dst,
                "channel",    "Channel",     DATA_INT,    channel,
                "frame_type", "Frame type",  DATA_STRING, ftype,
                "len",        "PSDU length", DATA_INT,    length,
                "flags",      "Flags",       DATA_FORMAT, "%02x", DATA_INT, flags,
                "mic",        "Integrity",   DATA_STRING, "CRC",
                NULL);
        /* clang-format on */
        decoder_output_data(decoder, data);
        decoded++;
    }
    return decoded;
}

static char const *const output_fields[] = {
        "model",
        "id",
        "dst",
        "channel",
        "frame_type",
        "len",
        "flags",
        "mic",
        NULL,
};

r_device const silverspring_ssn = {
        .name        = "Silver Spring Networks / Aclara AMI mesh (transport layer)",
        .modulation  = FSK_PULSE_PCM,
        .short_width = 7,    // ~150 kbps -> 6.67 us/bit
        .long_width  = 7,
        .reset_limit = 2000,
        .decode_fn   = &silverspring_ssn_decode,
        .fields      = output_fields,
};

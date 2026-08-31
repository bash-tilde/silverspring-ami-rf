# Upstream contributions

Drafts prepared for contribution to existing open projects. These are staging
copies kept for the record; the actual contribution happens on each project.

## `recessim-wiki-draft.mediawiki`

MediaWiki content for the [RECESSIM Silver Spring Networks Protocol page](https://wiki.recessim.com/view/Silver_Spring_Networks_Protocol),
which currently records an unverified sync word and no whitening/CRC/framing.
Written to *append* below their existing content and reconcile the channel-plan
difference (their FCC data is an older meter model). Contributed via the wiki
(account + Discord coordination), not a pull request.

## `rtl_433/silverspring_ssn.c`

A transport-layer decoder for [rtl_433](https://github.com/merbanan/rtl_433).
Note rtl_433 already has `silver_spring_mesh.c` (Benjamin Larsson) for a
drive-by/water-meter variant; this targets the **distinct fixed-AMI variant**
(degree-9 scrambler, `0C 5F` framing) that the existing decoder does not handle
— verified: the existing 8-bit scrambler descrambles none of these frames.
Emits source/destination node, channel, frame type, length and CRC status; the
encrypted payload is not decoded.

**Licensing:** this file is offered under **GPL-2.0-or-later** (rtl_433's
license), unlike the MIT license of the rest of this repository — as the author
this is a deliberate dual-offering so the code can be upstreamed.

**Status:** scaffold. The whitening (degree-9 LFSR) and CRC-32 core are verified
byte-for-byte against the Python reference in `analysis/`. The sync bit-alignment,
PHR inversion and multi-rate handling (100/150/200 kBd) need testing against live
captures — which requires the SDR — before opening a PR.

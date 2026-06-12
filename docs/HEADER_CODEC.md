# Header-only synchronization wire format ("header codec")

This document specifies a compressed wire format for batches of consecutive Monero
block headers, designed for header-only synchronization where bandwidth is the primary
concern. It compresses 1000 typical mainnet headers from ~76,500 bytes (raw) to a
measured average of **37,684 bytes** (37.68 bytes per header) — within 0.1% of the
order-0 entropy of the data — while letting the receiver reconstruct every header
byte-exactly and recompute every block id.

For comparison, the block id lists exchanged by today's `NOTIFY_RESPONSE_CHAIN_ENTRY`
cost 32 bytes per block and prove nothing; this format costs ~5.7 extra bytes per
block and carries everything needed to verify proof-of-work.

The reference implementation lives in `src/common/header_codec.{h,cpp}` with hardcoded
calibration tables in `src/common/header_codec_tables.h`. The calibration/benchmark
tool is `monero-blockchain-header-stats` (`src/blockchain_utilities/`), and unit tests
are in `tests/unit_tests/header_codec.cpp`.

Throughout this document, MUST denotes a requirement for interoperability or safety
and SHOULD a recommendation; sections marked *informative* do not affect the wire
format.

## Comparison with general-purpose compressors (informative)

How much is left on the table by using a ~200-line static codec instead of a
state-of-the-art general-purpose compressor? Measured 2026-06-12 on the most recent
100,000 mainnet headers at calibration time (heights [3,594,498, 3,694,497]; the
per-stage data files are reproducible with `monero-blockchain-header-stats
--dump-stages`). Two contenders, both at maximum effort:

* **brotli 1.2.0**, quality 11 (the CLI default — brotli's strongest mode, with
  order-2 context modeling, block splitting and per-block entropy tables);
* **7-Zip 23.01 LZMA2**, hand-tuned for this data:
  `-mx=9 -md=64m -mfb=273 -mmt=1 -myx=9 -mmf=bt4 -mmc=10000 -mlc=2 -mlp=0 -mpb=2`
  (exhaustive bt4 match finder; container overhead of 162 bytes excluded below).

Both compress the codec's own transposed delta stream (the input to the entropy stage,
i.e. after the §3.1 delta coding, nonce bit grouping and §3.2 plane transposition), so
the comparison isolates exactly one question: how does the §3.3/§3.4 three-region
static-rANS scheme fare against adaptive LZ + context modeling on identical data?

**Experiment 1 — one monolithic stream.** All 100,000 headers as a single 5,400,000-byte
stream (a single `compress_records` call for this codec; one compressor invocation for
the others). This is the most favorable possible setting for adaptive coders: a
continuous input ~100x larger than the format's transfer unit, with unlimited room to
learn the data.

| encoder                              | output bytes  | bytes/header | vs this codec |
|--------------------------------------|---------------|--------------|---------------|
| LZMA2, hand-tuned (stream only)      | 3,768,923     | 37.689       | +6,247        |
| **this codec** (one stream)          | **3,762,676** | **37.627**   | —             |
| brotli q11, window 2^24              | 3,755,607     | 37.556       | −7,069 (0.19%)|

The static codec beats exhaustively tuned LZMA2 outright and concedes 0.19% — 0.07
bytes/header — to brotli's maximum-effort mode. (LZMA2 knob check: `pb=0` suits this
non-periodic data slightly better than `pb=2`, 3,767,482 vs 3,767,805 via xz raw
streams — immaterial. LZMA2's loss is structural: its always-adaptive literal coder
has no stored-block mode, so it pays a small per-literal tax across the ~3.3 MB
incompressible tail, which brotli sidesteps with uncompressed blocks and this format
sidesteps with the raw tail.)

**Experiment 2 — where brotli's 0.19% lives.** On the monolith, this codec's encoder
chose `zero_run` = 1,500,004 (planes 0–14 are all-zero across the entire window, plus
4 bytes of plane 15), a rANS region of stream bytes [1,500,004, 2,099,088) coded into
a 461,758-byte cblob, and a 3,300,912-byte raw tail. Running brotli q11 on each region
separately:

| region (stream bytes)                  | input     | brotli q11 | this codec | delta  |
|----------------------------------------|-----------|------------|------------|--------|
| zero run [0, 1,500,004)                | 1,500,004 | 14         | ~3 (varint)| —      |
| rANS region [1,500,004, 2,099,088)     | 599,084   | 454,508    | 461,758    | −7,250 |
| raw tail [2,099,088, 5,400,000)        | 3,300,912 | 3,300,924  | 3,300,912  | +12    |

Brotli's entire advantage sits in the rANS region (−1.6% there): adaptive context
modeling on the timestamp/nonce/tx-count planes, i.e. structure *beyond* order-0
statistics. The raw tail is incompressible even for brotli (it loses 12 bytes trying),
confirming the split policy leaves nothing usable behind; brotli on this codec's full
encoded output gains nothing either (+13 bytes), i.e. the output is at entropy for
brotli's model class too. The sum of brotli's per-region results (3,755,446) beats
brotli run on the whole stream (3,755,607): the codec's region boundaries are better
than brotli's own block splitter.

**Experiment 3 — at the format's transfer granularity.** The same window cut into 100
chunks of 1000 headers (each chunk's first header seeds the deltas, as in the
container; 999 records coded per chunk; codec sections only, container overhead
excluded for all contenders identically). Two brotli configurations: compressing each
chunk's whole 53,946-byte transposed stream, and a hybrid keeping this format's exact
`[zero_run][size][middle][raw tail]` layout but with brotli q11 as the middle-region
coder — including re-optimizing the split for brotli over the same candidate set
(§3.5) plus the all-raw fallback.

| encoder, per 1000-header chunk          | total (100 chunks) | mean/chunk   | vs this codec |
|-----------------------------------------|--------------------|--------------|---------------|
| **this codec** (production encoder)     | **3,759,644**      | **37,596.4** | —             |
| brotli q11, middle region only (hybrid) | 3,791,494          | 37,914.9     | +318.5 (0.85%)|
| brotli q11, whole chunk stream          | 3,797,089          | 37,970.9     | +374.5 (1.0%) |

The hybrid loses **100 of 100 chunks** — brotli is worse on every single chunk even
with the zero-run elision and raw tail donated, and its split re-optimized per chunk.
At ~6 KB of middle region per chunk, an adaptive coder's per-stream model costs
(entropy table descriptions, context maps, and the learning portion of the stream)
exceed everything its richer modeling recovers; the static tables baked into this
format are amortized across all chunks ever transmitted instead.

**Conclusions.** (1) The codec operates at the order-0 entropy limit of its model:
nothing measurable is lost to the rANS approximation, the plane ordering, or the split
policy. (2) The total headroom available to *any* compressor beyond this format is
~0.19% (0.07 bytes/header), requires context modeling, and materializes only on
~100,000-header continuous streams — at the 1000-header transfer unit the situation
inverts and the static codec wins by ~1% against brotli's strongest mode, on every
chunk, while encoding ~80x faster (measured 53 ms vs 4.4 s for the 100 chunks above,
both sides running the full 8-candidate split search, this codec additionally
round-trip-verifying every chunk) and decoding with a few hundred lines of
dependency-free code. (3) Closing the residual gap at chunk granularity would
require *static* context modeling (e.g. baked order-1 tables for a few planes, with
table-size costs in the format binary); adaptive general-purpose compression is
dominated at this granularity and adds nothing.

## 1. Background and definitions

### 1.1 Headers (block hashing blobs)

A *header* in this document is Monero's block hashing blob — the exact byte string
hashed for proof-of-work and for the block id (see
`cryptonote::get_block_hashing_blob`). Its layout is:

| field            | encoding        | notes                                          |
|------------------|-----------------|------------------------------------------------|
| `major_version`  | varint          | value fits in 8 bits; 1 byte in practice       |
| `minor_version`  | varint          | value fits in 8 bits; 1 byte in practice       |
| `timestamp`      | varint          | 64-bit unsigned; 5 bytes for current times     |
| `prev_id`        | 32 bytes        | id of the previous block                       |
| `nonce`          | 4 bytes         | 32-bit unsigned, little endian                 |
| `merkle_root`    | 32 bytes        | tree hash of all txs incl. the coinbase        |
| `tx_count`       | varint          | number of txs *including* the coinbase         |

Typical mainnet headers are 76–77 bytes. The blob is self-delimiting: a parser
consuming the fields above knows exactly where the header ends.

### 1.2 Varints

All varints in this format are Monero's standard base-128 little-endian varints: each
byte carries 7 payload bits (least significant group first); the high bit set means
another byte follows. Encoders MUST emit the canonical (minimal-length) form. Decoders
MUST reject:

* truncated varints (input ends on a byte with the continuation bit set),
* non-canonical encodings (any continuation followed by a `0x00` byte),
* values exceeding 64 bits (more than 10 bytes, or a 10th byte greater than `0x01`).

### 1.3 Block ids

The block id of a header is

```
id = keccak1600(varint(len(blob)) || blob)[0..31]
```

i.e. Monero's `cn_fast_hash` (legacy Keccak with `0x01` padding, *not* NIST SHA-3) of
the hashing blob prefixed with its serialized length, truncated to the first 32 bytes
of the 200-byte state. This matches `cryptonote::get_object_hash` applied to the
hashing blob, which is how `calculate_block_hash` derives block ids.

Because headers in a chunk are consecutive, `prev_id` of every header except the first
equals the id of the preceding header and is **never transmitted**: the receiver
recomputes the id chain while decoding. This both saves 32 bytes per header and makes
the reconstruction self-checking — a tampered chunk yields headers whose PoW cannot
verify.

### 1.4 Records

Each header except the first in a chunk is reduced to a fixed 54-byte *record*: the
header with varints widened to little-endian integers and `prev_id` removed.

| offset | size | field                              |
|--------|------|------------------------------------|
| 0      | 1    | `major_version`                    |
| 1      | 1    | `minor_version`                    |
| 2      | 8    | `timestamp`, little endian         |
| 10     | 4    | `nonce`, little endian             |
| 14     | 32   | `merkle_root`                      |
| 46     | 8    | `tx_count`, little endian          |

(The *normalized* form including `prev_id` between `timestamp` and `nonce` is 86
bytes; it never appears on the wire.)

## 2. Chunk container

A chunk transports `N >= 2` consecutive headers. All multi-byte integers are varints
(section 1.2) unless stated otherwise.

| field          | encoding   | description                                              |
|----------------|------------|----------------------------------------------------------|
| `version`      | 1 byte     | format version; this document describes version `1`      |
| `height`       | varint     | height of the first header in the chunk                  |
| `cumdiff_low`  | varint     | low 64 bits of the cumulative chain difficulty up to and including the first header's block |
| `cumdiff_high` | varint     | high 64 bits of the same 128-bit value                   |
| `N`            | varint     | total number of headers, including the first             |
| `header0`      | raw header | the first header verbatim, including its `prev_id`; self-delimiting, no length prefix |
| `zero_run`     | varint     | length of the leading zero region of the transposed stream (section 3.3) |
| `csize`        | varint     | byte length of the entropy-coded region                  |
| `cblob`        | `csize` bytes | rANS-coded data (section 3.4)                         |
| `raw_tail`     | rest       | uncoded stream bytes, extending to the end of the container |

The container has no internal length field for `raw_tail`: its length is implied by
the enclosing transport (levin payload size, RPC field length, etc.), which MUST
delimit the chunk exactly.

`height` and the cumulative difficulty are carried for the consumer's benefit (chain
selection, sanity checks); the codec itself neither validates nor depends on them.

## 3. Record codec

The record codec is a pure byte transform. Given a 54-byte *seed* and `M = N - 1`
records it produces the `zero_run | csize | cblob | raw_tail` section of the
container, and the inverse reconstructs the records exactly. It round-trips **any**
byte payload whose size is a multiple of 54 — payloads that are not real Monero
headers simply compress poorly. For chunks, the seed is the record form of `header0`.

Pipeline: delta-code each record against its predecessor, transpose the result into
byte planes ordered by increasing empirical entropy, then send the stream as
`[leading zeros][rANS region][raw tail]`.

### 3.1 Delta coding

Record `i` is delta-coded against original record `i-1` (record 0 against the seed).
Format version 1 uses the `zigzag_ts` variant:

* `timestamp` (offsets 2..9): interpreted as a 64-bit little-endian unsigned integer;
  the stored value is `zigzag(cur - prev)` (subtraction modulo 2^64), again 64-bit
  little endian, where

  ```
  zigzag(d)   = (d << 1) ^ (0 - (d >> 63))        all modulo 2^64
  unzigzag(z) = (z >> 1) ^ (0 - (z & 1))
  ```

  mapping 0, 1, -1, 2, -2, ... to 0, 1, 2, 3, 4, ... Timestamps are not monotonic, so
  deltas are signed; zigzag keeps small magnitudes in the low byte regardless of sign.

* every other byte `j`: stored value is `cur[j] XOR prev[j]`.

Decoding mirrors this: XOR bytes with the previous *reconstructed* record, and
`timestamp = prev_timestamp + unzigzag(stored)` modulo 2^64.

*Informative:* the variant was chosen by measurement (section 7). Zigzag deltas beat
XOR for timestamps by ~1.6 bits/header; for `tx_count` XOR beats zigzag (consecutive
counts are nearly independent, so subtraction spreads the distribution), hence the
hybrid. The variant is fixed per format version, not signalled per chunk.

After delta coding and before transposition, the 32 bits of the nonce field of each
delta record (offsets 10..13, interpreted as a 32-bit little-endian value) are
permuted by the fixed `NONCE_BIT_ORDER` table: bit `k` of the permuted value takes
source bit `NONCE_BIT_ORDER[k]` (bit 0 = LSB of byte 0). Decoders apply the inverse
permutation after untransposing. Because a bit permutation commutes with XOR, this
equals permuting the nonces themselves. Miners scan the nonce space in structured
patterns (incremental scanning, xmrig-proxy range assignment), so nonce delta bits
have wildly different flip probabilities *and* strong correlations; the version 1
table (section 6) groups correlated, biased bits into the two most significant
permuted bytes, which lowers their joint entropy and lets the entropy coder exploit
it, while the noisy bits are concentrated in permuted bytes 0..1 that end up in the
raw region anyway. The grouping was found by direct search minimizing the sum of
measured joint byte entropies (section 7).

### 3.2 Plane transposition

The `M` delta-coded records are transposed into 54 *planes* of `M` bytes. Planes are
emitted in the fixed order given by the `ORDER` table (section 6), which sorts record
byte positions by ascending probability of a nonzero delta, measured on real mainnet
data. The transposed stream of length `54 * M` is:

```
stream[r * M + j] = delta_record[j][ORDER[r]]     r in [0, 54), j in [0, M)
```

After this step the stream starts with planes that are almost always zero
(`major_version`, `minor_version`, timestamp bytes 2..7, `tx_count` bytes 1..7),
continues with low-entropy planes (timestamp bytes 0..1, `tx_count` byte 0, the high
nonce bytes — which are strongly biased because miners scan nonces from low values),
and ends with effectively random planes (the merkle root, the low nonce bytes).

### 3.3 Three-region stream layout

The transposed stream is sent as three consecutive regions:

```
[0, zero_run)          all zero bytes  -> transmitted as just the count
[zero_run, split)      entropy-coded   -> cblob, csize bytes
[split, 54 * M)        raw             -> raw_tail, verbatim
```

The decoder never sees `split` explicitly; it derives everything:

```
stream_len = 54 * M
raw_len    = container bytes remaining after cblob
split      = stream_len - raw_len
region_len = split - zero_run        (number of symbols to decode from cblob)
```

The encoder SHOULD set `zero_run` to the maximal leading run of zero bytes. Any
smaller value also decodes correctly (the difference is just compressed less
efficiently), so decoders MUST NOT assume maximality.

### 3.4 Entropy coding (static rANS)

The coded region uses a byte-oriented rANS coder with static per-plane frequency
tables.

Constants:

```
SCALE_BITS = 14          FREQ_SCALE = 1 << 14 = 16384
L          = 1 << 23     (state lower bound; state is in [L, 256 * L))
```

Tables: for each record byte position `pos` there is a frequency table
`FREQ[pos][256]` with every entry `>= 1` and `sum == FREQ_SCALE`, plus the implied
cumulative table `CUM[pos][s] = FREQ[pos][0] + ... + FREQ[pos][s-1]`. The stream
position `p` uses the table of its plane's record byte position, `FREQ[ORDER[p / M]]`.

**Decoding** (normative). Let `in` be `cblob` of length `csize`.

```
if region_len == 0: csize MUST be 0; skip this step entirely
x  = in[0]<<24 | in[1]<<16 | in[2]<<8 | in[3]      (big endian; csize MUST be >= 4)
ip = 4
for p in [zero_run, split):
    tab  = table for position ORDER[p / M]
    slot = x & (FREQ_SCALE - 1)
    s    = the unique symbol with CUM[s] <= slot < CUM[s] + FREQ[s]
    x    = FREQ[s] * (x >> SCALE_BITS) + slot - CUM[s]
    while x < L:
        fail if ip == csize
        x = (x << 8) | in[ip++]
    stream[p] = s
fail unless ip == csize and x == L
```

The two final checks hold for every well-formed stream and MUST be enforced; they
reject most corrupted or truncated containers outright.

**Encoding** (informative; any encoder producing streams the above accepts is
conformant). Process symbols in *reverse* stream order with `x` initialized to `L`;
for each symbol with frequency `f` and cumulative `c`:

```
x_max = ((L >> SCALE_BITS) << 8) * f
while x >= x_max: emit byte (x & 0xff); x >>= 8
x = (x / f) << SCALE_BITS | ... precisely: x = (x / f) * FREQ_SCALE + (x % f) + c
```

then emit the final 32-bit state and reverse the emitted byte sequence, so that the
state lands big-endian in `cblob[0..3]` and the renormalization bytes follow in decode
order. Worst-case expansion is bounded by 14 bits per symbol plus the 4-byte state.

### 3.5 Encoder split selection (informative)

The decoder accepts any consistent `(zero_run, split)`; choosing `split` is encoder
policy. The reference encoder tries `round((SPLIT_RATIO + offset) * stream_len)` for
each of the `SPLIT_OFFSETS` candidates, clamped to `[zero_run, stream_len]`, plus the
all-raw fallback `split = zero_run`, and keeps whichever yields the smallest output.
The fallback guarantees the codec never loses more than a few bytes on payloads that
defeat the tables (e.g. random data). The offsets are calibrated by greedy coverage
over a fine sweep of real chunks (section 7); measured against a 101-point
0.1-percentage-point grid, the calibrated 7-candidate set loses only ~0.25 bytes per
1000-header chunk. Each candidate costs one rANS encode of the coded region
(~0.3 ms), so an encoder wanting the last fraction of a byte can simply try a denser
grid.

## 4. Chunk encoding and decoding

**Encoding.** Given `N >= 2` consecutive raw headers: parse each (rejecting
non-canonical varints, `major_version`/`minor_version` above 255, or trailing bytes),
verify that re-serialization reproduces the input bytes exactly and that each
`prev_id` equals the computed id of the preceding header (the reference implementation
refuses to encode otherwise — a violated chain cannot be reconstructed and would break
losslessness silently). Then emit the container fields, `header0` verbatim, and the
record codec output for records 1..N-1 with header 0's record as the seed.

**Decoding.** Parse the container fields (enforcing `version == 1`, `2 <= N <=`
an application-chosen cap, defaulting to 100,000 in the reference implementation),
parse `header0`, run the record codec in reverse, then reconstruct headers
sequentially: header `i` is its decoded record plus `prev_id = id(header i-1)`,
re-serialized to raw varint form; ids are computed per section 1.3 as the chain is
rebuilt. The first header is reproduced from its verbatim bytes.

All decoder size checks MUST be performed before allocating (`zero_run <= 54 * M`,
`csize <=` remaining container bytes, `raw_len <= 54 * M - zero_run`,
`region_len == 0 => csize == 0`); together with the `N` cap this bounds decoder memory
at roughly `190 * N` bytes with no amplification: every region's size is known exactly
before it is decoded.

## 5. Verification contract and scope

The codec validates *bytes*, never *semantics*. PoW, difficulty, timestamps, chain
selection and the trustworthiness of `height`/cumulative difficulty are entirely the
caller's responsibility. A malicious peer can produce a chunk that decodes
successfully into garbage headers; that garbage fails PoW verification downstream,
which is the actual integrity gate. Conversely, any decoded chunk is internally
consistent by construction: the prev_id chain holds because it was recomputed, not
transmitted.

**Height restriction.** Version 1 chunks MUST only be used for heights at or above
the first RandomX block, **1978433** (mainnet). Two reasons:

* The id of mainnet block 202612 is *not* the hash of its hashing blob — it is a
  hardcoded exception in `calculate_block_hash` (see the block 202612 special case in
  `cryptonote_format_utils.cpp`). The keccak id chain of section 1.3 therefore breaks
  between heights 202612 and 202613, and reconstruction below the RandomX era would
  require replicating that exception.
* The calibration tables are measured on recent mainnet data; older eras (and other
  networks) have different statistics. They would still decode correctly — only less
  efficiently — but restricting the range keeps the format honest about what it was
  designed and tested for.

The same tables are used for testnet and stagenet (correct, merely suboptimal there).

## 6. Hardcoded tables (format version 1)

Format version 1 fixes, in `src/common/header_codec_tables.h`:

* `V1_VARIANT = 1` — the `zigzag_ts` delta variant (section 3.1);
* `V1_SPLIT_RATIO = 0.386720` — the encoder's split point estimate (section 3.5);
* `V1_SPLIT_OFFSETS[7] = {-0.034, -0.028, -0.022, -0.016, -0.002, +0.002, +0.008}` —
  the encoder's candidate offsets around the split ratio (section 3.5), greedy
  coverage selection over the calibration chunks;
* `V1_NONCE_BIT_ORDER[32]` — the nonce bit permutation (section 3.1):

  ```
  6 5 0 4 2 9 10 11 7 8 3 1 15 16 17 12 28 29 30 31 24 26 25 27 18 19 13 20 14 21 22 23
  ```

  Permuted bytes 2 and 3 collect the 16 most biased source bits with their
  correlation clusters kept intact — byte 2 is exactly the natural byte 3 (bits
  24..31, the xmrig-proxy byte, joint entropy 6.95 bits), byte 3 groups bits
  {13, 14, 18..23} (joint entropy 6.49 bits, including bit 23 with P(flip) = 0.073) —
  while the near-random bits 0..12, 15..17 fill permuted bytes 0..1;
* `V1_ORDER[54]` — the plane order (record byte positions, see section 1.4 for the
  position map; nonce positions refer to the bit-permuted nonce):

  ```
   0  1  4  5  6  7  8  9 48 49 50 51 52 53 47  3 13  2 12 46 11 10
  26 45 30 35 27 43 23 41 20 18 34 24 14 28 21 38 15 39 44 33 29 17
  16 31 37 22 32 42 19 25 36 40
  ```

  i.e. `major`, `minor`, timestamp bytes 2..7, `tx_count` bytes 2..7, `tx_count`
  byte 1, timestamp byte 1, then permuted-nonce byte 3, timestamp byte 0,
  permuted-nonce byte 2, `tx_count` byte 0, permuted-nonce bytes 1 and 0, then the
  32 merkle planes;

* `V1_FREQ[54][256]` — the rANS frequency tables (quantized so every entry is `>= 1`
  and each row sums to exactly 16384). These ~27k values are data, not derivable from
  this document; implementations MUST ship them.

The tables were generated from **1,000,000 mainnet headers, heights
[2694498, 3694497]** (tip id
`a12bc51a746f29de0a6963a0331f66dece6f0f4e15603ae0d8d737fb91e6e84a`), with split-ratio
calibration at chunk size 1000. To regenerate (this is a format-impacting act — bump
the version, and regenerate the documented test vectors and the pinned unit test):

```
monero-blockchain-header-stats --data-dir <dir> --emit-tables src/common/header_codec_tables.h
```

The tool prints per-position statistics, calibrates and cross-compares all variants
(see section 7), writes the winning tables, and with `--eval-baked` re-verifies the
baked parameters through the production API against the database. `--self-test` runs a
database-free round-trip battery.

## 7. Measured performance (informative)

Methodology: the 1M-header sample is split in half; tables and split ratios are
calibrated on the older 500k headers and all benchmarks run on the newer 500k
(500 chunks of 1000 headers), so the figures below are out-of-sample. Sizes are
complete containers, including the ~90-byte fixed overhead (version, height, 128-bit
cumulative difficulty, N, raw header 0). Every benchmarked chunk was round-tripped and
every reconstructed block id checked against the database; the loader also verified
id computation, parsing, serialization and chain linkage on all 1,000,000 headers,
with zero failures.

Mean container bytes per 1000-header chunk:

With the natural (identity) nonce bit order:

| delta variant       | rANS, P(nonzero) order | rANS, entropy order | raw deflate -9 (best order) |
|---------------------|------------------------|---------------------|------------------------------|
| `zigzag_ts`         | 37,708.5               | 37,708.5            | 38,231.7                     |
| `xor_all`           | 37,921.9               | 37,918.8            | 38,307.3                     |
| `zigzag_ts_txcount` | 37,767.6               | 37,767.7            | 38,284.4                     |

Adding the calibrated nonce bit grouping (section 3.1) improves the winning variant
to **37,695.8** (rANS, entropy order — the version 1 combination) / 37,696.0 (rANS,
P(nonzero) order).

The baked v1 parameters (tables regenerated on the full sample) measured through the
production `compress_chunk` API: **mean 37,683.8, median 37,683, p95 37,754 bytes**
per 1000-header chunk — 37.68 bytes per header, a 2.03x reduction over raw headers.

Why this is close to optimal for this model class: the measured order-0 entropy of
`zigzag_ts` deltas with the v1 nonce bit grouping is 300.82 bits/header (300.92 with
the natural nonce layout), an entropy floor of ~37,565 payload bytes plus ~100 bytes
of overhead per 1000-header chunk. The codec lands within ~20 bytes (0.05%) of that
floor; the residual is rANS quantization, the minimum-frequency-1 robustness floor,
and the 4-byte state flush. Going materially below ~37.6k would
require context modeling (conditioning across byte positions), not better entropy
coding. The static rANS coder beats raw deflate at maximum compression by 520–600
bytes per chunk in every configuration because deflate's Huffman stage cannot code
fractional bits on the strongly biased planes.

Per-field entropy after `zigzag_ts` delta coding (bits, full sample): timestamp
6.91 + 1.44 + 0.00... (bytes 0,1,2..7); nonce 8.00 + 7.80 + 6.78 + 6.95 = 29.52 of
32 in the natural byte layout (the bias of bytes 2–3 reflects miners scanning nonces
from low values, with xmrig-proxy filling byte 3), regrouped by `V1_NONCE_BIT_ORDER`
to 8.00 + 7.99 + 6.95 + 6.49 = 29.42; merkle root 32 x 8.00; `tx_count` 7.05 +
0.003; `major`/`minor` exactly 0 in the sampled range.

**Nonce bit reordering.** Per-bit flip probabilities of the nonce XOR delta show
rich structure (bits 0–11 fully random; bit 23 at P(flip) = 0.073, the most biased;
clusters of bits with near-identical flip probabilities, e.g. bits 24–27 all at
~0.310 and bits 28–31 at ~0.40–0.42, indicating bits that flip *together*). Two
regroupings were measured:

* Sorting bits by *marginal* per-bit entropy (highest into byte 0, lowest into
  byte 3) was **rejected**: it increases the wire size by ~22 bytes per 1000-header
  chunk (e.g. `zigzag_ts` 37,708.5 -> 37,730.5). Per-bit entropies sum to 30.19
  bits, but the byte-wise coder captures intra-byte bit correlations — the natural
  layout already recovers 30.19 − 29.52 = 0.67 bits/header of joint structure
  because the correlated clusters are contiguous in the nonce, and marginal sorting
  scatters them (only 0.50 bits survive).
* Minimizing the sum of measured *joint* byte entropies directly (the
  `monero-nonce-bit-order-search` tool: 20-thread simulated annealing with basin
  hopping over bit-to-byte assignments, exact histogram evaluation on all 999,999
  deltas) found the grouping baked as `V1_NONCE_BIT_ORDER`: 29.4245 bits total
  (0.77 bits of joint structure captured), −0.0995 bits/header vs the natural
  layout. The optimum was found within the first minute of a 30-minute run and
  survived 8.6 million subsequent candidate evaluations; re-running with the
  objective restricted to the three coded bytes (the highest-entropy permuted byte
  lands in the raw region, where its exact entropy is irrelevant) reproduced the
  same grouping of the 16 biased bits, confirming robustness. On the wire this is
  worth −12.7 bytes per 1000-header chunk (`zigzag_ts` 37,708.5 -> 37,695.8,
  matching the −12.4 predicted at the entropy bound).

**Split candidate calibration.** A sweep of every split
`(SPLIT_RATIO + k/100) * stream_len` for `k in {-5.0..+5.0}` in 0.1-point steps over
1000 full-sample chunks (true rANS encodes) showed a very flat cost surface: 905 of
1000 chunks had multiple tied winning candidates, and the full 101-point grid beats
the original evenly spaced ±3-point set by only 0.51 bytes/chunk — the achievable
ceiling for any 7-candidate policy. Win counts are misleading on such plateaus
(the most-winning candidates cluster together: the top 7 by wins, {+0.1..+0.7},
measured *worse* than the evenly spaced set by losing tail coverage). The baked
`V1_SPLIT_OFFSETS` therefore come from greedy coverage selection — repeatedly adding
the offset that most reduces the mean per-chunk minimum cost — recovering ~0.26 of
the 0.51-byte ceiling.

## 8. Reference implementation

* `src/common/header_codec.h` — public API and a condensed version of this
  specification; `src/common/header_codec.cpp` — implementation (the rANS coder is
  ~120 lines); `src/common/header_codec_tables.h` — generated tables (section 6).
* API: `compress_chunk` / `decompress_chunk` (chunk container, returns reconstructed
  raw headers and optionally all block ids), `compress_records` /
  `decompress_records` (the pure byte codec, parameterizable for experiments), plus
  the parsing/serialization helpers and pipeline stages used by the calibration tool.
* `monero-blockchain-header-stats` — calibration, benchmarking, table generation
  (section 6); `--dump-nonces` exports the sampled nonce values for offline
  experiments and `--bit-order` injects a custom nonce bit permutation into the
  benchmarks.
* `monero-nonce-bit-order-search` — standalone search for the `NONCE_BIT_ORDER`
  table (section 7): multi-threaded simulated annealing over bit-to-byte
  assignments on a nonce dump, minimizing the sum of measured joint byte entropies
  (`--free-bytes` excludes leading raw-region bytes from the objective).
* `tests/unit_tests/header_codec.cpp` — round trips (arbitrary bytes, all variants,
  extreme zigzag deltas), byte-exact equivalence of the parser/serializer with
  `cryptonote` serialization, id semantics vs `get_object_hash`, malformed-input
  rejection (truncations, bit flips, garbage, non-canonical varints, broken chains,
  header-count caps), and the test vectors below pinned byte-for-byte.

The codec has no dependencies beyond `cncrypto` (for `cn_fast_hash`); zlib is used
only by the benchmark tool for the deflate comparison.

## 9. Test vectors

### 9.1 Vector A — container walk-through (3 headers, all-raw fallback)

Input headers (`major = minor = 16` throughout; `prev_id` of header 0 is 32 zero
bytes; headers 1 and 2 chain via computed ids):

| #  | timestamp  | nonce        | merkle_root | tx_count |
|----|------------|--------------|-------------|----------|
| 0  | 1700000000 | `0x00000001` | 32 x `0x11` | 1        |
| 1  | 1700000120 | `0x12345678` | 32 x `0x22` | 200      |
| 2  | 1700000003 | `0x00abcdef` | 32 x `0x33` | 2        |

Note timestamp 2 goes *backwards* (delta −117) and `tx_count = 200` takes a 2-byte
varint. Raw header 0 (76 bytes):

```
101080e2cfaa06 0000000000000000000000000000000000000000000000000000000000000000
01000000 1111111111111111111111111111111111111111111111111111111111111111 01
```

Block ids:

```
id0 = d48ebc4f36e2d4ca37f65e4cab950960a6a366072e01b4f92472aa8e9e8a9233
id1 = 855f5b2e80eabe5b184d51a72af50c7fc3f29a2535cf07acf8499c8077f8c57c
id2 = 01e5a81c6253cbbba0c22bc3a68a51fb4c1a171841d3678415341cd470b679c7
```

Chunk for `height = 3000000`, cumulative difficulty `1000000` (164 bytes), annotated:

```
01              version 1
c08db701        height = 3000000
c0843d          cumdiff_low = 1000000
00              cumdiff_high = 0
03              N = 3
101080e2cfaa06 ... 01    header 0 verbatim (76 bytes, above)
20              zero_run = 32
00              csize = 0  (all-raw fallback: with M = 2 the rANS state flush
                            outweighs any coding gain, so everything after the
                            zero run is sent raw)
then raw_tail = 76 bytes, the transposed planes from rank 16 on (width M = 2).
The nonce XOR deltas are 0x00000001^0x12345678 = 0x12345679 and
0x12345678^0x00abcdef = 0x129f9b97; after the NONCE_BIT_ORDER permutation they
become 0x3941846f and 0x8b41fbbc, whose bytes appear in the planes below:
398b            nonce'[3]: permuted delta bytes 3
f0e9            ts[0]: zigzag(+120) = 0xf0, zigzag(-117) = 0xe9
4141            nonce'[2]
c9ca            txcnt[0]: 1^200, 200^2          (XOR: tx_count is not zigzagged)
84fb            nonce'[1]
6fbc            nonce'[0]
3311 x 32       merkle planes: 0x11^0x22, 0x22^0x33
```

The 32-byte zero run covers ranks 0..15 (two bytes each): `major`, `minor`, timestamp
bytes 2..7, `tx_count` bytes 2..7 and 1, timestamp byte 1 — all zero deltas here.

Full chunk hex:

```
01c08db701c0843d0003101080e2cfaa0600000000000000000000000000000000000000000000
000000000000000000000100000011111111111111111111111111111111111111111111111111
11111111111111012000398bf0e94141c9ca84fb6fbc3311331133113311331133113311331133
113311331133113311331133113311331133113311331133113311331133113311331133113311
3311331133113311
```

### 9.2 Vector B — nonempty rANS region (8 headers)

`major = minor = 16` throughout; `prev_id` of header 0 is 32 x `0xaa`;
`merkle_root[i][j] = (i*37 + j*11 + 5) & 0xff`; nonces follow the realistic
low-scanning pattern:

| #  | timestamp  | nonce        | tx_count |
|----|------------|--------------|----------|
| 0  | 1700000000 | `0x000a3b1c` | 47       |
| 1  | 1700000097 | `0x0007d1e8` | 102      |
| 2  | 1700000239 | `0x0001493f` | 33       |
| 3  | 1700000299 | `0x00000b52` | 88       |
| 4  | 1700000502 | `0x00112d07` | 156      |
| 5  | 1700000471 | `0x0003428b` | 61       |
| 6  | 1700000589 | `0x0299c477` | 29       |
| 7  | 1700000765 | `0x00049d10` | 74       |

Chunk for `height = 3500000`, cumulative difficulty `0x0123456789abcdef`
(361 bytes; `zero_run = 106`, `csize = 22`, 27 stream bytes rANS-coded,
`raw_tail = 245`):

```
01e0cfd501ef9bafcdf8acd191010008101080e2cfaa06aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c3b0a0005101b26313c47525d68737e89949faab5c0cb
d6e1ecf7020d18232e39444f5a2f6a1609f6e9d9d1f891064f8cf6591d22b23d3f65df1eb40049
4779c4a1205731d924204755aabb9d377df07b97277d2be55f25eb25db6d27fd2b656f25db6d27
fd2bfd276ddb256f252d67dd2b653fe52de73d6b25df65e53f652bdd672d7d2be55f25eb3d2bfd
276ddb256f672ddb652fe53be72d7b25ef255beb255fe52b7d272f653bed275deb5b2de73d6b25
df25eb5d27ed3b653f652bdd672dfb256f25db6d27fd255fe52b7d27ed3bed275deb257f2ddb65
2fe53b6d653bed275deb256d3be52f65db2d5b25ef257b2de725ef257b2de75d256b3de72d5be5
df256b3de72d5b3be52f65db2d6767dd2b653fe52b5de72d7b25ef25dd6b25ff256bddeb5d27ed
3b652f6b25ff256bdd27
```

Id of the last header, as recomputed by the decoder:

```
id7 = 5d82cfacebeea25421af3a7b3d1ec724c5fcb5dd309ffeb69dfd3786723235e3
```

Both vectors are pinned byte-for-byte in `tests/unit_tests/header_codec.cpp`
(`header_codec.documented_test_vectors`).

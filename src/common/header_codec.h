// Copyright (c) 2014-2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "crypto/hash.h"

// Compressed wire format for batches ("chunks") of consecutive Monero block headers,
// where header = the block hashing blob (see cryptonote::get_block_hashing_blob):
//
//   varint major_version | varint minor_version | varint timestamp |
//   prev_id (32 bytes)   | nonce (4 bytes LE)   | tx merkle root (32 bytes) |
//   varint tx_count (including the coinbase transaction)
//
// The block id is cn_fast_hash(varint(blob_size) || blob), which lets a receiver of a
// chunk of consecutive headers recompute every prev_id from the previous header, so
// prev_id is never transmitted (except in the first header of a chunk).
//
// Chunk container (version 1):
//
//   u8      version            currently 1
//   varint  height             height of the first header in the chunk
//   varint  cumdiff_low        128-bit cumulative chain difficulty up to and
//   varint  cumdiff_high       ... including the first header's block
//   varint  N                  total number of headers in the chunk, N >= 2
//   bytes   header0            first header, raw hashing-blob form (self-delimiting)
//   varint  zero_run           output of the record codec (see below) starts here
//   varint  csize
//   bytes   cblob (csize)
//   bytes   raw_tail           extends to the end of the container, its length is
//                              implied by the container size
//
// Record codec: each header except the first is reduced to a 54-byte record
// (normalized form minus prev_id):
//
//   offset 0      major_version
//   offset 1      minor_version
//   offset 2..9   timestamp, 64-bit LE
//   offset 10..13 nonce, 32-bit LE
//   offset 14..45 tx merkle root
//   offset 46..53 tx_count, 64-bit LE
//
// Records are delta-coded against the previous header's record (the first record
// against the seed = header0's record): XOR for most bytes; for some format variants
// the timestamp (and tx_count) fields instead store zigzag(cur - prev) as 64-bit LE.
// The 32 bits of the nonce XOR delta are then permuted by a hardcoded order that
// concentrates the high-entropy bits in byte 0 and the low-entropy bits in byte 3
// (miners scan nonces in structured patterns, so per-bit flip probabilities differ
// wildly; grouping similar bits makes whole bytes compressible). Delta-coded records
// are then transposed into 54 byte planes emitted in a hardcoded order of increasing
// empirical entropy (calibrated from real mainnet headers), giving
// a stream that starts with a long run of zero bytes, continues with compressible
// bytes and ends with high-entropy bytes. The stream is encoded as three parts:
//   - the maximal leading run of zero bytes, transmitted as just its length;
//   - a region [zero_run, split) entropy-coded with a static per-plane rANS coder
//     (hardcoded frequency tables, 14-bit scale, 32-bit state, byte renormalization,
//     the first 4 bytes of cblob hold the final state, big-endian);
//   - the remaining bytes [split, end) transmitted raw.
// The split point is chosen by the encoder (the decoder derives all region sizes from
// the container fields), by trying a hardcoded ratio of the stream length plus each
// hardcoded candidate offset plus the all-raw fallback, keeping the smallest output.
//
// The record codec is a pure byte transform: it round-trips any payload whose size is
// a multiple of 54 bytes, just less efficiently if it is not a sequence of Monero
// headers. It validates nothing about header semantics: PoW, difficulty and chain
// checks (including enforcing a minimum height for which peers may serve chunks) are
// the caller's responsibility. A malicious chunk can decode into garbage headers;
// that garbage fails PoW verification downstream.
namespace tools { namespace header_codec {

constexpr size_t RECORD_BYTES = 54;       // normalized header minus prev_id
constexpr size_t NORMALIZED_BYTES = 86;   // normalized header including prev_id
constexpr unsigned SCALE_BITS = 14;
constexpr uint32_t FREQ_SCALE = 1u << SCALE_BITS; // sum of each per-plane frequency table
constexpr uint8_t FORMAT_VERSION = 1;
constexpr size_t DEFAULT_MAX_HEADERS = 100000; // decoder allocation cap, callers may override;
                                               // a malicious chunk of ~100 bytes can decode to
                                               // ~260 bytes of working set per allowed header, so
                                               // this cap is the decoder's peak-memory budget

// Offsets of the integer fields within a record (see layout above)
constexpr size_t REC_OFF_TIMESTAMP = 2;
constexpr size_t REC_OFF_NONCE = 10;
constexpr size_t REC_OFF_MERKLE = 14;
constexpr size_t REC_OFF_TX_COUNT = 46;

enum class delta_variant : uint8_t
{
  xor_all = 0,           // every byte XORed with the previous record
  zigzag_ts = 1,         // timestamp stored as zigzag(cur - prev), rest XORed
  zigzag_ts_txcount = 2, // timestamp and tx_count stored as zigzag deltas, rest XORed
};

constexpr size_t SPLIT_CANDIDATES = 7;

struct codec_params
{
  delta_variant variant;
  double split_ratio;                     // encoder-only: hardcoded split point estimate
  double split_offsets[SPLIT_CANDIDATES]; // encoder-only: candidate splits are
                                          // (split_ratio + offset) * stream_len, plus the
                                          // all-raw fallback; calibrated from win counts
  uint8_t nonce_bit_order[32];            // bit k of the permuted nonce delta takes source bit
                                          // nonce_bit_order[k] (bit 0 = LSB of byte 0); a permutation
  uint8_t order[RECORD_BYTES];            // plane rank -> record byte offset, a permutation
  uint16_t freq[RECORD_BYTES][256];       // per record byte offset, each row sums to FREQ_SCALE, all >= 1
};

//! Parameters baked into format version 1 (see header_codec_tables.h)
const codec_params& v1_params();

//! Check a params object satisfies the invariants above (used on the hardcoded tables too)
bool validate_params(const codec_params& p);

// ---- raw header (hashing blob) parsing -------------------------------------------

struct parsed_header
{
  uint64_t major_version; // <= 0xff
  uint64_t minor_version; // <= 0xff
  uint64_t timestamp;
  crypto::hash prev_id;
  uint32_t nonce;
  crypto::hash merkle_root;
  uint64_t tx_count;
};

//! Strict parse of a raw hashing blob prefix; canonical varints only.
//! On success sets consumed to the number of bytes read (the blob is self-delimiting).
bool parse_raw_header(const uint8_t* data, size_t size, parsed_header& header, size_t& consumed);
//! Canonical inverse of parse_raw_header; appends to out
void serialize_raw_header(const parsed_header& header, std::string& out);
//! Record (54-byte residual) of a header; drops prev_id
void to_record(const parsed_header& header, uint8_t record[RECORD_BYTES]);
//! Rebuild a header from a record plus an externally supplied prev_id
void from_record(const uint8_t record[RECORD_BYTES], const crypto::hash& prev_id, parsed_header& header);
//! Block id of a raw hashing blob: cn_fast_hash(varint(size) || blob)
crypto::hash hashing_blob_id(const uint8_t* blob, size_t size);

// ---- low-level record codec (arbitrary payloads) ----------------------------------
// All stage functions require out != in. count is the number of 54-byte records.

void delta_encode(const uint8_t seed[RECORD_BYTES], const uint8_t* records, size_t count, uint8_t* out, delta_variant variant);
void delta_decode(const uint8_t seed[RECORD_BYTES], const uint8_t* deltas, size_t count, uint8_t* out, delta_variant variant);
//! In-place bit permutation of the nonce field (offsets 10..13) of delta-coded records;
//! applied between the delta and transpose stages (it commutes with XOR, so permuting
//! deltas equals permuting the nonces themselves)
void permute_nonce_bits(uint8_t* records, size_t count, const uint8_t order[32]);
void unpermute_nonce_bits(uint8_t* records, size_t count, const uint8_t order[32]);
void transpose(const uint8_t* records, size_t count, const uint8_t order[RECORD_BYTES], uint8_t* out);
void untranspose(const uint8_t* stream, size_t count, const uint8_t order[RECORD_BYTES], uint8_t* out);

//! Entropy-code stream[begin, end) of a transposed stream of `count`-wide planes with
//! the per-plane rANS tables (the encoder side of the cblob region); exposed for
//! split-point calibration tooling. Returns an empty string on invalid params.
std::string entropy_code_region(const uint8_t* stream, size_t begin, size_t end, size_t count, const codec_params& params);

//! Full pipeline: delta -> transpose -> [zero_run][rANS][raw tail]. count >= 1.
//! Returns an empty string on invalid arguments (valid output is never empty).
std::string compress_records(const uint8_t seed[RECORD_BYTES], const uint8_t* records, size_t count, const codec_params& params);
//! Inverse of compress_records; in/size must span the codec output exactly
bool decompress_records(const uint8_t* in, size_t size, size_t count, const uint8_t seed[RECORD_BYTES], const codec_params& params, std::vector<uint8_t>& records_out);

//! Quantize a byte histogram into a frequency table summing to FREQ_SCALE with all entries >= 1
void quantize_freqs(const uint64_t hist[256], uint16_t freq_out[256]);

// ---- chunk container ---------------------------------------------------------------

struct chunk_info
{
  uint64_t height;                    // height of the first header in the chunk
  uint64_t cumulative_difficulty_low; // cumulative difficulty including the first block
  uint64_t cumulative_difficulty_high;
};

//! hashing_blobs must hold >= 2 consecutive raw hashing blobs (each header's prev_id
//! equal to the block id of the previous blob); this is verified and byte-exact
//! reconstruction is guaranteed for inputs that pass.
bool compress_chunk(const std::vector<std::string>& hashing_blobs, const chunk_info& info, std::string& out);
//! Reconstructs the raw hashing blobs of a chunk; optionally returns all block ids
//! (ids[i] is the id of hashing_blobs[i], computed while chaining prev_ids).
//! On failure the outputs are unspecified (info may be partially written); they are
//! only meaningful when the function returns true.
bool decompress_chunk(const std::string& in, chunk_info& info, std::vector<std::string>& hashing_blobs, std::vector<crypto::hash>* block_ids = NULL, size_t max_headers = DEFAULT_MAX_HEADERS);

}}

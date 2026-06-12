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

#include <cstring>
#include <limits>
#include <random>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "string_tools.h"
#include "common/header_codec.h"
#include "common/varint.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "serialization/string.h" // do_serialize(ar, std::string) for get_object_hash on a blobdata

namespace hc = tools::header_codec;

namespace
{

constexpr size_t REC = hc::RECORD_BYTES;

hc::parsed_header random_header(std::mt19937_64& rng)
{
  hc::parsed_header h;
  h.major_version = 16;
  h.minor_version = 16;
  h.timestamp = 1700000000 + rng() % 10000000;
  for (auto& c : h.prev_id.data) c = rng() & 0xff;
  h.nonce = static_cast<uint32_t>(rng());
  for (auto& c : h.merkle_root.data) c = rng() & 0xff;
  h.tx_count = 1 + rng() % 300;
  return h;
}

// consecutive headers whose prev_id chain is valid
std::vector<std::string> synthetic_chain(std::mt19937_64& rng, size_t n)
{
  std::vector<std::string> blobs;
  crypto::hash prev;
  for (auto& c : prev.data) c = rng() & 0xff;
  for (size_t i = 0; i < n; ++i)
  {
    hc::parsed_header h = random_header(rng);
    h.prev_id = prev;
    std::string blob;
    hc::serialize_raw_header(h, blob);
    prev = hc::hashing_blob_id(reinterpret_cast<const uint8_t*>(blob.data()), blob.size());
    blobs.push_back(std::move(blob));
  }
  return blobs;
}

hc::codec_params test_params(std::mt19937_64& rng, hc::delta_variant v)
{
  hc::codec_params p;
  p.variant = v;
  p.split_ratio = double(rng() % 1001) / 1000.0;
  for (size_t k = 0; k < hc::SPLIT_CANDIDATES; ++k)
    p.split_offsets[k] = double(int(rng() % 2001) - 1000) / 10000.0; // [-0.1, 0.1]
  for (unsigned k = 0; k < 32; ++k) p.nonce_bit_order[k] = k;
  if (rng() % 2)
    std::shuffle(p.nonce_bit_order, p.nonce_bit_order + 32, rng);
  for (size_t i = 0; i < REC; ++i) p.order[i] = i;
  std::shuffle(p.order, p.order + REC, rng);
  for (size_t pos = 0; pos < REC; ++pos)
  {
    uint64_t hist[256];
    for (size_t s = 0; s < 256; ++s)
      hist[s] = pos % 2 ? rng() % 1000 : (s == 0 ? 1000000 : rng() % 3);
    hc::quantize_freqs(hist, p.freq[pos]);
  }
  return p;
}

void roundtrip_records(const std::vector<uint8_t>& data, size_t count, const hc::codec_params& p, const uint8_t seed[REC])
{
  const std::string coded = hc::compress_records(seed, data.data(), count, p);
  ASSERT_FALSE(coded.empty());
  std::vector<uint8_t> back;
  ASSERT_TRUE(hc::decompress_records(reinterpret_cast<const uint8_t*>(coded.data()), coded.size(), count, seed, p, back));
  ASSERT_EQ(data, back);
}

} // anonymous namespace

TEST(header_codec, parser_matches_cryptonote_serialization)
{
  // the raw header layout is the block hashing blob: serialized block_header,
  // then the merkle root, then varint tx count
  std::mt19937_64 rng(42);
  const uint64_t timestamps[] = {0, 1, 127, 128, 16383, 16384, 1u << 28, 1700000000, (1ull << 35) - 1, 1ull << 35, 1ull << 63, UINT64_MAX};
  const uint64_t versions[] = {0, 1, 127, 128, 255};
  const uint64_t tx_counts[] = {0, 1, 0x7f, 0x80, 0x3fff, 0x4000, 1ull << 35, UINT64_MAX};
  size_t iter = 0;
  for (uint64_t ts : timestamps)
  {
    for (uint64_t ver : versions)
    {
      cryptonote::block_header bh{};
      bh.major_version = static_cast<uint8_t>(ver);
      bh.minor_version = static_cast<uint8_t>(255 - ver);
      bh.timestamp = ts;
      for (auto& c : bh.prev_id.data) c = rng() & 0xff;
      bh.nonce = static_cast<uint32_t>(rng());

      crypto::hash merkle;
      for (auto& c : merkle.data) c = rng() & 0xff;
      // cycle deterministic varint boundary values through tx_count; timestamp and
      // version boundaries are already covered by the outer loops, tx_count is the
      // remaining varint field of the hashing blob
      const uint64_t tx_count = tx_counts[iter++ % (sizeof(tx_counts) / sizeof(tx_counts[0]))];

      std::string reference = cryptonote::t_serializable_object_to_blob(bh);
      reference.append(merkle.data, 32);
      reference.append(tools::get_varint_data(tx_count));

      // parse the reference blob and check every field
      hc::parsed_header h;
      size_t consumed = 0;
      ASSERT_TRUE(hc::parse_raw_header(reinterpret_cast<const uint8_t*>(reference.data()), reference.size(), h, consumed));
      ASSERT_EQ(consumed, reference.size());
      ASSERT_EQ(h.major_version, bh.major_version);
      ASSERT_EQ(h.minor_version, bh.minor_version);
      ASSERT_EQ(h.timestamp, bh.timestamp);
      ASSERT_EQ(h.prev_id, bh.prev_id);
      ASSERT_EQ(h.nonce, bh.nonce);
      ASSERT_EQ(h.merkle_root, merkle);
      ASSERT_EQ(h.tx_count, tx_count);

      // serialize back, byte-exact
      std::string ours;
      hc::serialize_raw_header(h, ours);
      ASSERT_EQ(reference, ours);

      // block id semantics: cn_fast_hash(varint(size) || blob), as used by
      // cryptonote::get_object_hash on a blobdata
      crypto::hash reference_id;
      cryptonote::get_object_hash(cryptonote::blobdata(reference), reference_id);
      ASSERT_EQ(reference_id, hc::hashing_blob_id(reinterpret_cast<const uint8_t*>(reference.data()), reference.size()));
    }
  }
}

TEST(header_codec, parser_rejects_malformed)
{
  std::mt19937_64 rng(43);
  std::string blob;
  hc::serialize_raw_header(random_header(rng), blob);
  hc::parsed_header h;
  size_t consumed = 0;

  // truncations of a minimal-length header fail (the blob is its own delimiter,
  // so only prefixes shorter than the parsed length can fail)
  for (size_t len = 0; len < blob.size(); ++len)
    ASSERT_FALSE(hc::parse_raw_header(reinterpret_cast<const uint8_t*>(blob.data()), len, h, consumed));

  // non-canonical varint (0x80 0x00 for major version)
  std::string bad = std::string("\x80\x00", 2) + blob.substr(1);
  ASSERT_FALSE(hc::parse_raw_header(reinterpret_cast<const uint8_t*>(bad.data()), bad.size(), h, consumed));

  // major version above 255
  bad = std::string("\x80\x02", 2) + blob.substr(1);
  ASSERT_FALSE(hc::parse_raw_header(reinterpret_cast<const uint8_t*>(bad.data()), bad.size(), h, consumed));

  // timestamp varint longer than 64 bits
  bad = blob.substr(0, 2) + std::string(10, '\xff') + blob.substr(2);
  ASSERT_FALSE(hc::parse_raw_header(reinterpret_cast<const uint8_t*>(bad.data()), bad.size(), h, consumed));
}

TEST(header_codec, record_roundtrip_arbitrary_bytes)
{
  std::mt19937_64 rng(44);
  const size_t counts[] = {1, 2, 3, 7, 64, 999};
  const hc::delta_variant variants[] = {hc::delta_variant::xor_all, hc::delta_variant::zigzag_ts, hc::delta_variant::zigzag_ts_txcount};
  for (size_t count : counts)
  {
    for (hc::delta_variant v : variants)
    {
      const hc::codec_params p = test_params(rng, v);
      std::vector<uint8_t> data(count * REC);
      uint8_t seed[REC];
      for (auto& b : seed) b = rng() & 0xff;

      // uniform random bytes
      for (auto& b : data) b = rng() & 0xff;
      roundtrip_records(data, count, p, seed);

      // all zero (max zero run)
      std::fill(data.begin(), data.end(), 0);
      roundtrip_records(data, count, p, seed);

      // all 0xff
      std::fill(data.begin(), data.end(), 0xff);
      roundtrip_records(data, count, p, seed);

      // identical records (deltas vanish after the first)
      for (size_t i = 0; i < count; ++i)
        memcpy(data.data() + i * REC, seed, REC);
      roundtrip_records(data, count, p, seed);
    }
  }
}

TEST(header_codec, record_roundtrip_v1_params)
{
  // same contract through the baked tables, whatever they are
  ASSERT_TRUE(hc::validate_params(hc::v1_params()));
  std::mt19937_64 rng(45);
  for (size_t count : {1, 5, 999})
  {
    std::vector<uint8_t> data(count * REC);
    uint8_t seed[REC];
    for (auto& b : seed) b = rng() & 0xff;
    for (auto& b : data) b = rng() & 0xff;
    roundtrip_records(data, count, hc::v1_params(), seed);
  }
}

TEST(header_codec, zigzag_delta_extremes)
{
  // timestamp / tx count transitions across the full u64 range survive the
  // subtract+zigzag path (mod 2^64 arithmetic is bijective)
  std::mt19937_64 rng(46);
  const uint64_t values[] = {0, 1, 0x7f, 0x80, UINT32_MAX, 1ull << 63, (1ull << 63) - 1, UINT64_MAX};
  const hc::codec_params p = test_params(rng, hc::delta_variant::zigzag_ts_txcount);
  std::vector<uint8_t> data(8 * 8 * REC);
  uint8_t seed[REC] = {};
  size_t i = 0;
  for (uint64_t a : values)
  {
    for (uint64_t b : values)
    {
      uint8_t* rec = data.data() + i++ * REC;
      memset(rec, 0, REC);
      hc::parsed_header h{};
      h.timestamp = a;
      h.tx_count = b;
      hc::to_record(h, rec);
    }
  }
  roundtrip_records(data, 64, p, seed);
}

TEST(header_codec, quantize_freqs_invariants)
{
  uint64_t hist[256];
  uint16_t freq[256];
  std::mt19937_64 rng(47);
  for (int round = 0; round < 50; ++round)
  {
    for (size_t s = 0; s < 256; ++s)
    {
      switch (round % 4)
      {
        case 0: hist[s] = 0; break;                                 // empty
        case 1: hist[s] = s == 7 ? 1000000000 : 0; break;           // single symbol
        case 2: hist[s] = rng() % 5; break;                         // sparse
        default: hist[s] = rng() % 1000000; break;                  // dense
      }
    }
    hc::quantize_freqs(hist, freq);
    uint32_t sum = 0;
    for (size_t s = 0; s < 256; ++s)
    {
      ASSERT_GE(freq[s], 1);
      sum += freq[s];
    }
    ASSERT_EQ(sum, hc::FREQ_SCALE);
  }
}

TEST(header_codec, invalid_params_rejected)
{
  std::mt19937_64 rng(48);
  const hc::codec_params good = test_params(rng, hc::delta_variant::xor_all);
  std::vector<uint8_t> data(REC, 0);
  uint8_t seed[REC] = {};

  // positive control: the unmutated fixture must be accepted, otherwise every rejection
  // assertion below could pass for the wrong reason (e.g. if validate_params rejected all)
  ASSERT_TRUE(hc::validate_params(good));
  ASSERT_FALSE(hc::compress_records(seed, data.data(), 1, good).empty());

  hc::codec_params bad = good;
  bad.order[3] = bad.order[5]; // not a permutation (duplicate)
  ASSERT_TRUE(hc::compress_records(seed, data.data(), 1, bad).empty());

  bad = good;
  bad.order[3] = REC; // plane index out of range (distinct from the duplicate case)
  ASSERT_TRUE(hc::compress_records(seed, data.data(), 1, bad).empty());

  bad = good;
  bad.variant = static_cast<hc::delta_variant>(99); // not a defined variant
  ASSERT_TRUE(hc::compress_records(seed, data.data(), 1, bad).empty());

  bad = good;
  bad.split_ratio = 1.5; // ratio outside [0, 1]
  ASSERT_TRUE(hc::compress_records(seed, data.data(), 1, bad).empty());

  bad = good;
  bad.split_ratio = std::numeric_limits<double>::infinity(); // non-finite ratio
  ASSERT_TRUE(hc::compress_records(seed, data.data(), 1, bad).empty());

  bad = good;
  bad.freq[10][20] += 1; // row sum one above FREQ_SCALE
  ASSERT_TRUE(hc::compress_records(seed, data.data(), 1, bad).empty());

  bad = good;
  bad.freq[10][0] -= 1; // row sum one below FREQ_SCALE (the entry stays > 0)
  ASSERT_TRUE(hc::compress_records(seed, data.data(), 1, bad).empty());

  bad = good;
  bad.freq[10][20] += bad.freq[10][21];
  bad.freq[10][21] = 0; // zero frequency
  ASSERT_TRUE(hc::compress_records(seed, data.data(), 1, bad).empty());

  bad = good;
  bad.nonce_bit_order[4] = bad.nonce_bit_order[9]; // not a permutation
  ASSERT_TRUE(hc::compress_records(seed, data.data(), 1, bad).empty());

  bad = good;
  bad.nonce_bit_order[4] = 32; // out of range
  ASSERT_TRUE(hc::compress_records(seed, data.data(), 1, bad).empty());

  bad = good;
  bad.split_offsets[2] = 1.5; // out of range
  ASSERT_TRUE(hc::compress_records(seed, data.data(), 1, bad).empty());

  bad = good;
  bad.split_offsets[2] = std::numeric_limits<double>::quiet_NaN();
  ASSERT_TRUE(hc::compress_records(seed, data.data(), 1, bad).empty());

  std::vector<uint8_t> out;
  ASSERT_FALSE(hc::decompress_records(data.data(), data.size(), 1, seed, bad, out));
  ASSERT_TRUE(hc::compress_records(seed, data.data(), 0, good).empty()); // count == 0
}

TEST(header_codec, chunk_roundtrip)
{
  std::mt19937_64 rng(49);
  for (size_t n : {2, 3, 50, 1000})
  {
    const std::vector<std::string> blobs = synthetic_chain(rng, n);
    hc::chunk_info info;
    info.height = 1978433 + rng() % 1000000;
    info.cumulative_difficulty_low = rng();
    info.cumulative_difficulty_high = rng() % 3;

    std::string chunk;
    ASSERT_TRUE(hc::compress_chunk(blobs, info, chunk));

    hc::chunk_info info2;
    std::vector<std::string> back;
    std::vector<crypto::hash> ids;
    ASSERT_TRUE(hc::decompress_chunk(chunk, info2, back, &ids));
    ASSERT_EQ(blobs, back);
    ASSERT_EQ(info.height, info2.height);
    ASSERT_EQ(info.cumulative_difficulty_low, info2.cumulative_difficulty_low);
    ASSERT_EQ(info.cumulative_difficulty_high, info2.cumulative_difficulty_high);
    ASSERT_EQ(ids.size(), blobs.size());
    for (size_t i = 0; i < blobs.size(); ++i)
      ASSERT_EQ(ids[i], hc::hashing_blob_id(reinterpret_cast<const uint8_t*>(blobs[i].data()), blobs[i].size()));
  }
}

TEST(header_codec, chunk_rejects_bad_input)
{
  std::mt19937_64 rng(50);
  std::vector<std::string> blobs = synthetic_chain(rng, 10);
  hc::chunk_info info{};
  info.height = 2000000;
  std::string chunk;

  // fewer than 2 headers
  ASSERT_FALSE(hc::compress_chunk(std::vector<std::string>(blobs.begin(), blobs.begin() + 1), info, chunk));

  // broken prev_id chain: change a non-last header's merkle root
  {
    std::vector<std::string> broken = blobs;
    hc::parsed_header h;
    size_t consumed = 0;
    ASSERT_TRUE(hc::parse_raw_header(reinterpret_cast<const uint8_t*>(broken[4].data()), broken[4].size(), h, consumed));
    h.merkle_root.data[0] ^= 1;
    broken[4].clear();
    hc::serialize_raw_header(h, broken[4]);
    ASSERT_FALSE(hc::compress_chunk(broken, info, chunk));
  }

  // trailing bytes after a header blob
  {
    std::vector<std::string> trailing = blobs;
    trailing[9] += '\x00';
    ASSERT_FALSE(hc::compress_chunk(trailing, info, chunk));
  }
}

TEST(header_codec, chunk_decoder_rejects_malformed)
{
  std::mt19937_64 rng(51);
  const std::vector<std::string> blobs = synthetic_chain(rng, 40);
  hc::chunk_info info;
  info.height = 2222222;
  info.cumulative_difficulty_low = 123456789;
  info.cumulative_difficulty_high = 0;
  std::string chunk;
  ASSERT_TRUE(hc::compress_chunk(blobs, info, chunk));

  hc::chunk_info info2;
  std::vector<std::string> back;

  // wrong version byte
  std::string bad = chunk;
  bad[0] = 2;
  ASSERT_FALSE(hc::decompress_chunk(bad, info2, back));

  // every truncation either fails or yields something else
  for (size_t len = 0; len < chunk.size(); ++len)
  {
    if (hc::decompress_chunk(chunk.substr(0, len), info2, back))
    {
      ASSERT_NE(back, blobs);
    }
  }

  // header count cap
  ASSERT_FALSE(hc::decompress_chunk(chunk, info2, back, NULL, 39));
  ASSERT_TRUE(hc::decompress_chunk(chunk, info2, back, NULL, 40));

  // bit flips never crash; if they decode, they decode to something
  for (int i = 0; i < 500; ++i)
  {
    std::string mutated = chunk;
    mutated[rng() % mutated.size()] ^= 1 << (rng() % 8);
    hc::decompress_chunk(mutated, info2, back);
  }

  // random garbage
  for (int i = 0; i < 200; ++i)
  {
    std::string garbage(rng() % 4096, '\0');
    for (auto& c : garbage) c = rng() & 0xff;
    hc::decompress_chunk(garbage, info2, back);
  }
}

TEST(header_codec, decoder_rejects_bad_framing)
{
  // hand-crafted codec sections for count = 4 (stream_len = 216) and an all-zero
  // payload, baked tables: the only valid encoding is [zero_run=216][csize=0],
  // i.e. exactly the bytes d8 01 00
  const uint8_t seed[REC] = {};
  std::vector<uint8_t> zeros(4 * REC, 0), out;
  const std::string ok = hc::compress_records(seed, zeros.data(), 4, hc::v1_params());
  ASSERT_EQ(ok, std::string("\xd8\x01\x00", 3)); // uvarint(216), uvarint(0)
  auto dec = [&](const std::string& s) {
    return hc::decompress_records(reinterpret_cast<const uint8_t*>(s.data()), s.size(), 4, seed, hc::v1_params(), out);
  };
  ASSERT_TRUE(dec(ok));
  ASSERT_EQ(out, zeros);

  ASSERT_FALSE(dec(std::string()));                              // empty input
  ASSERT_FALSE(dec(std::string("\xd8\x01", 2)));                 // missing csize varint
  ASSERT_FALSE(dec(std::string("\xd9\x01\x00", 3)));             // zero_run 217 > stream_len
  ASSERT_FALSE(dec(std::string("\xd4\x01\x01\x00", 4)));         // csize 1: a rANS blob is >= 4 bytes
  ASSERT_FALSE(dec(std::string("\xd0\x01\x03\x00\x00\x00", 6))); // csize 3: still too short for the state
  ASSERT_FALSE(dec(std::string("\xd0\x01\x00\x55\x55", 5)));     // coded region [208, 214) implied but csize 0
  ASSERT_FALSE(dec(std::string("\xd0\x01\x20\x00\x00", 5)));     // csize 32 overruns the input
  ASSERT_FALSE(dec(ok + '\x00'));                                // trailing byte
  ASSERT_FALSE(dec(std::string("\x80\x00\x00", 3)));             // non-canonical zero_run varint
  std::string huge(9, '\xff');
  huge += '\x01';
  ASSERT_FALSE(dec(huge));                                       // zero_run = 2^64 - 1
  ASSERT_FALSE(dec(std::string(10, '\xff')));                    // varint wider than 64 bits
}

TEST(header_codec, chunk_decoder_rejects_crafted)
{
  // build a small valid chunk whose container fields are all single-byte varints, so
  // their byte offsets are known, then surgically corrupt individual fields. This pins
  // the container-level rejection branches deterministically (the fuzz loops in
  // chunk_decoder_rejects_malformed exercise them but assert nothing specific).
  std::mt19937_64 rng(53);
  const std::vector<std::string> blobs = synthetic_chain(rng, 3);
  hc::chunk_info info;
  info.height = 5;                     // 1-byte varint
  info.cumulative_difficulty_low = 5;  // 1-byte varint
  info.cumulative_difficulty_high = 0; // 1-byte varint
  std::string chunk;
  ASSERT_TRUE(hc::compress_chunk(blobs, info, chunk));

  hc::chunk_info info2;
  std::vector<std::string> back;
  // positive control + container layout pin: [version][height][cdlo][cdhi][N]...
  // N at offset 4 implies the three preceding fields are each one byte, as intended
  ASSERT_TRUE(hc::decompress_chunk(chunk, info2, back));
  ASSERT_EQ(back, blobs);
  ASSERT_EQ(static_cast<uint8_t>(chunk[0]), hc::FORMAT_VERSION);
  ASSERT_EQ(static_cast<uint8_t>(chunk[4]), 3u); // N == header count

  // N < 2 rejected at the container level (record count would be 0)
  std::string bad = chunk;
  bad[4] = 1;
  ASSERT_FALSE(hc::decompress_chunk(bad, info2, back));
  bad[4] = 0;
  ASSERT_FALSE(hc::decompress_chunk(bad, info2, back));

  // N above the allocation cap rejected
  ASSERT_FALSE(hc::decompress_chunk(chunk, info2, back, NULL, 2));

  // non-canonical height varint (0x85 0x00 also encodes 5) rejected by the strict reader
  bad = chunk.substr(0, 1) + std::string("\x85\x00", 2) + chunk.substr(2);
  ASSERT_FALSE(hc::decompress_chunk(bad, info2, back));

  // a byte appended after a valid chunk: the codec section must span the container
  // exactly (the trailing byte inflates the raw region past its bound, or breaks the
  // rANS exact-consumption check)
  bad = chunk;
  bad.push_back('\x00');
  ASSERT_FALSE(hc::decompress_chunk(bad, info2, back));
}

TEST(header_codec, documented_test_vectors)
{
  // the two test vectors from docs/HEADER_CODEC.md; they pin the byte-exact output of
  // this encoder with the checked-in v1 tables -- regenerating the tables changes
  // these bytes, and the documented vectors must be regenerated with them
  hc::parsed_header h[3] = {};
  h[0].major_version = h[0].minor_version = 16;
  h[0].timestamp = 1700000000;
  memset(h[0].prev_id.data, 0x00, 32);
  h[0].nonce = 0x00000001;
  memset(h[0].merkle_root.data, 0x11, 32);
  h[0].tx_count = 1;
  h[1].major_version = h[1].minor_version = 16;
  h[1].timestamp = 1700000120;
  h[1].nonce = 0x12345678;
  memset(h[1].merkle_root.data, 0x22, 32);
  h[1].tx_count = 200;
  h[2].major_version = h[2].minor_version = 16;
  h[2].timestamp = 1700000003; // goes backwards
  h[2].nonce = 0x00abcdef;
  memset(h[2].merkle_root.data, 0x33, 32);
  h[2].tx_count = 2;

  std::vector<std::string> blobs;
  for (int i = 0; i < 3; ++i)
  {
    if (i)
      h[i].prev_id = hc::hashing_blob_id(reinterpret_cast<const uint8_t*>(blobs[i - 1].data()), blobs[i - 1].size());
    std::string blob;
    hc::serialize_raw_header(h[i], blob);
    blobs.push_back(std::move(blob));
  }

  hc::chunk_info info;
  info.height = 3000000;
  info.cumulative_difficulty_low = 1000000;
  info.cumulative_difficulty_high = 0;
  std::string chunk;
  ASSERT_TRUE(hc::compress_chunk(blobs, info, chunk));
  std::string expected;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(
    "01c08db701c0843d0003101080e2cfaa060000000000000000000000000000000000000000000000000000000000000000010000001111"
    "111111111111111111111111111111111111111111111111111111111111012000398bf0e94141c9ca84fb6fbc33113311331133113311"
    "331133113311331133113311331133113311331133113311331133113311331133113311331133113311331133113311331133113311", expected));
  ASSERT_EQ(expected, chunk);
  hc::chunk_info info2;
  std::vector<std::string> back;
  ASSERT_TRUE(hc::decompress_chunk(expected, info2, back));
  ASSERT_EQ(blobs, back);

  // vector B (nonempty rANS region)
  static const uint64_t ts_b[8] = {1700000000, 1700000097, 1700000239, 1700000299, 1700000502, 1700000471, 1700000589, 1700000765};
  static const uint32_t nonce_b[8] = {0x000a3b1c, 0x0007d1e8, 0x0001493f, 0x00000b52, 0x00112d07, 0x0003428b, 0x0299c477, 0x00049d10};
  static const uint64_t txc_b[8] = {47, 102, 33, 88, 156, 61, 29, 74};
  std::vector<std::string> blobs2;
  crypto::hash prev;
  memset(prev.data, 0xaa, 32);
  for (int i = 0; i < 8; ++i)
  {
    hc::parsed_header hb{};
    hb.major_version = hb.minor_version = 16;
    hb.timestamp = ts_b[i];
    hb.prev_id = prev;
    hb.nonce = nonce_b[i];
    for (int j = 0; j < 32; ++j)
      hb.merkle_root.data[j] = static_cast<char>((i * 37 + j * 11 + 5) & 0xff);
    hb.tx_count = txc_b[i];
    std::string blob;
    hc::serialize_raw_header(hb, blob);
    prev = hc::hashing_blob_id(reinterpret_cast<const uint8_t*>(blob.data()), blob.size());
    blobs2.push_back(std::move(blob));
  }
  info.height = 3500000;
  info.cumulative_difficulty_low = 0x123456789abcdefull;
  info.cumulative_difficulty_high = 0;
  std::string chunk2;
  ASSERT_TRUE(hc::compress_chunk(blobs2, info, chunk2));
  std::string expected2;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(
    "01e0cfd501ef9bafcdf8acd191010008101080e2cfaa06aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1c3b0a0005101b26313c47525d68737e89949faab5c0cbd6e1ecf7020d18232e39444f5a2f6a1609f6e9d9d1f891064f8cf6591d22b23d"
    "3f65df1eb400494779c4a1205731d924204755aabb9d377df07b97277d2be55f25eb25db6d27fd2b656f25db6d27fd2bfd276ddb256f25"
    "2d67dd2b653fe52de73d6b25df65e53f652bdd672d7d2be55f25eb3d2bfd276ddb256f672ddb652fe53be72d7b25ef255beb255fe52b7d"
    "272f653bed275deb5b2de73d6b25df25eb5d27ed3b653f652bdd672dfb256f25db6d27fd255fe52b7d27ed3bed275deb257f2ddb652fe5"
    "3b6d653bed275deb256d3be52f65db2d5b25ef257b2de725ef257b2de75d256b3de72d5be5df256b3de72d5b3be52f65db2d6767dd2b65"
    "3fe52b5de72d7b25ef25dd6b25ff256bddeb5d27ed3b652f6b25ff256bdd27", expected2));
  ASSERT_EQ(expected2, chunk2);
  std::vector<crypto::hash> ids2;
  ASSERT_TRUE(hc::decompress_chunk(expected2, info2, back, &ids2));
  ASSERT_EQ(blobs2, back);
  crypto::hash id7;
  ASSERT_TRUE(epee::string_tools::hex_to_pod("5d82cfacebeea25421af3a7b3d1ec724c5fcb5dd309ffeb69dfd3786723235e3", id7));
  ASSERT_EQ(id7, ids2[7]);
}

TEST(header_codec, compressed_chunk_is_small_on_zero_deltas)
{
  // identical records compress to (nearly) nothing: the whole transposed stream is a
  // zero run; this pins the zero-run path irrespective of the baked tables
  std::mt19937_64 rng(52);
  uint8_t seed[REC];
  for (auto& b : seed) b = rng() & 0xff;
  std::vector<uint8_t> data(999 * REC);
  for (size_t i = 0; i < 999; ++i)
    memcpy(data.data() + i * REC, seed, REC);
  const std::string coded = hc::compress_records(seed, data.data(), 999, hc::v1_params());
  ASSERT_FALSE(coded.empty());
  ASSERT_LE(coded.size(), 16u);
  std::vector<uint8_t> back;
  ASSERT_TRUE(hc::decompress_records(reinterpret_cast<const uint8_t*>(coded.data()), coded.size(), 999, seed, hc::v1_params(), back));
  ASSERT_EQ(data, back);
}

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

#include "header_codec.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <iterator>

#include "common/varint.h"
#include "crypto/hash.h"

// generated calibration tables (data only, included by this translation unit alone)
#include "header_codec_tables.h"

namespace tools { namespace header_codec {

namespace
{

// rANS state lower bound; with byte renormalization the state stays in [RANS_L, 256 * RANS_L)
constexpr uint32_t RANS_L = 1u << 23;

// Strict varint reader: rejects truncated, non-canonical and overflowing encodings
// (common/varint.h read_varint reports a truncated varint as success, which is not
// acceptable when parsing adversarial containers)
bool read_uvarint(const uint8_t*& p, const uint8_t* end, uint64_t& v)
{
  v = 0;
  unsigned shift = 0;
  while (true)
  {
    if (p == end)
      return false;
    const uint8_t b = *p++;
    if (shift && b == 0)
      return false;
    if (shift == 63 && b > 1)
      return false;
    v |= static_cast<uint64_t>(b & 0x7f) << shift;
    if ((b & 0x80) == 0)
      return true;
    shift += 7;
    if (shift > 63)
      return false;
  }
}

void append_uvarint(std::string& out, uint64_t v)
{
  tools::write_varint(std::back_inserter(out), v);
}

size_t uvarint_size(uint64_t v)
{
  size_t n = 1;
  while (v >= 0x80)
  {
    v >>= 7;
    ++n;
  }
  return n;
}

uint64_t get_le(const uint8_t* p, size_t n)
{
  uint64_t v = 0;
  for (size_t i = 0; i < n; ++i)
    v |= static_cast<uint64_t>(p[i]) << (8 * i);
  return v;
}

void put_le(uint8_t* p, uint64_t v, size_t n)
{
  for (size_t i = 0; i < n; ++i)
    p[i] = static_cast<uint8_t>(v >> (8 * i));
}

// NaN/Inf-proof range check: release builds use -Ofast (-ffinite-math-only), so
// floating comparisons cannot be trusted to reject NaN; classify via the bit pattern
bool finite_in_range(double v, double lo, double hi)
{
  uint64_t bits;
  memcpy(&bits, &v, sizeof(bits));
  if (((bits >> 52) & 0x7ff) == 0x7ff) // NaN or infinity
    return false;
  return v >= lo && v <= hi;
}

uint64_t zigzag(uint64_t d)
{
  return (d << 1) ^ (0 - (d >> 63));
}

uint64_t unzigzag(uint64_t z)
{
  return (z >> 1) ^ (0 - (z & 1));
}

// Byte offsets stored as zigzag deltas instead of XOR for a given variant: each entry
// is an (offset, size) pair of a little endian unsigned integer field
struct int_field { size_t offset, size; };

size_t variant_int_fields(delta_variant v, int_field fields[2])
{
  size_t n = 0;
  if (v == delta_variant::zigzag_ts || v == delta_variant::zigzag_ts_txcount)
    fields[n++] = {REC_OFF_TIMESTAMP, 8};
  if (v == delta_variant::zigzag_ts_txcount)
    fields[n++] = {REC_OFF_TX_COUNT, 8};
  return n;
}

struct cum_table
{
  uint16_t cum[257];
};

void build_cum_tables(const codec_params& p, std::vector<cum_table>& tabs)
{
  tabs.resize(RECORD_BYTES);
  for (size_t pos = 0; pos < RECORD_BYTES; ++pos)
  {
    uint32_t c = 0;
    for (size_t s = 0; s < 256; ++s)
    {
      tabs[pos].cum[s] = static_cast<uint16_t>(c);
      c += p.freq[pos][s];
    }
    tabs[pos].cum[256] = static_cast<uint16_t>(c); // == FREQ_SCALE, fits: FREQ_SCALE < 1<<16
  }
}

// Entropy-code stream[begin, end) (positions are global stream offsets, plane width =
// count); symbols are processed in reverse so the decoder can run forward
std::string rans_encode(const uint8_t* stream, size_t begin, size_t end, size_t count, const codec_params& p, const std::vector<cum_table>& tabs)
{
  std::string buf;
  buf.reserve((end - begin) * 2 + 4);
  uint32_t x = RANS_L;
  for (size_t pos = end; pos-- > begin;)
  {
    const uint8_t s = stream[pos];
    const uint8_t orig = p.order[pos / count];
    const uint32_t f = p.freq[orig][s];
    const uint32_t c = tabs[orig].cum[s];
    const uint32_t x_max = ((RANS_L >> SCALE_BITS) << 8) * f;
    while (x >= x_max)
    {
      buf.push_back(static_cast<char>(x & 0xff));
      x >>= 8;
    }
    x = ((x / f) << SCALE_BITS) + (x % f) + c;
  }
  // final state, ends up big-endian at the start of the output after the reverse
  buf.push_back(static_cast<char>(x & 0xff));
  buf.push_back(static_cast<char>((x >> 8) & 0xff));
  buf.push_back(static_cast<char>((x >> 16) & 0xff));
  buf.push_back(static_cast<char>((x >> 24) & 0xff));
  std::reverse(buf.begin(), buf.end());
  return buf;
}

bool rans_decode(const uint8_t* in, size_t in_len, uint8_t* stream, size_t begin, size_t end, size_t count, const codec_params& p, const std::vector<cum_table>& tabs)
{
  if (in_len < 4)
    return false;
  uint32_t x = (static_cast<uint32_t>(in[0]) << 24) | (static_cast<uint32_t>(in[1]) << 16) | (static_cast<uint32_t>(in[2]) << 8) | in[3];
  size_t ip = 4;
  for (size_t pos = begin; pos < end; ++pos)
  {
    const uint8_t orig = p.order[pos / count];
    const cum_table& t = tabs[orig];
    const uint32_t slot = x & (FREQ_SCALE - 1);
    // largest s with cum[s] <= slot (cum is nondecreasing, cum[0] = 0, cum[256] = FREQ_SCALE)
    unsigned lo = 0, hi = 256;
    while (hi - lo > 1)
    {
      const unsigned mid = (lo + hi) >> 1;
      if (t.cum[mid] <= slot)
        lo = mid;
      else
        hi = mid;
    }
    const uint32_t f = p.freq[orig][lo];
    x = f * (x >> SCALE_BITS) + slot - t.cum[lo];
    while (x < RANS_L)
    {
      if (ip >= in_len)
        return false;
      x = (x << 8) | in[ip++];
    }
    stream[pos] = static_cast<uint8_t>(lo);
  }
  // a stream produced by rans_encode consumes its input exactly and ends at the
  // encoder's initial state
  return ip == in_len && x == RANS_L;
}

} // anonymous namespace

std::string entropy_code_region(const uint8_t* stream, size_t begin, size_t end, size_t count, const codec_params& params)
{
  if (count == 0 || count > SIZE_MAX / RECORD_BYTES / 2 || begin > end || end > count * RECORD_BYTES || !validate_params(params))
    return std::string();
  std::vector<cum_table> tabs;
  build_cum_tables(params, tabs);
  return rans_encode(stream, begin, end, count, params, tabs);
}

bool validate_params(const codec_params& p)
{
  if (p.variant != delta_variant::xor_all && p.variant != delta_variant::zigzag_ts && p.variant != delta_variant::zigzag_ts_txcount)
    return false;
  if (!finite_in_range(p.split_ratio, 0.0, 1.0))
    return false;
  for (size_t i = 0; i < SPLIT_CANDIDATES; ++i)
  {
    if (!finite_in_range(p.split_offsets[i], -1.0, 1.0))
      return false;
  }
  bool seen_bit[32] = {};
  for (size_t i = 0; i < 32; ++i)
  {
    if (p.nonce_bit_order[i] >= 32 || seen_bit[p.nonce_bit_order[i]])
      return false;
    seen_bit[p.nonce_bit_order[i]] = true;
  }
  bool seen[RECORD_BYTES] = {};
  for (size_t i = 0; i < RECORD_BYTES; ++i)
  {
    if (p.order[i] >= RECORD_BYTES || seen[p.order[i]])
      return false;
    seen[p.order[i]] = true;
  }
  for (size_t pos = 0; pos < RECORD_BYTES; ++pos)
  {
    uint32_t sum = 0;
    for (size_t s = 0; s < 256; ++s)
    {
      if (p.freq[pos][s] == 0)
        return false;
      sum += p.freq[pos][s];
    }
    if (sum != FREQ_SCALE)
      return false;
  }
  return true;
}

bool parse_raw_header(const uint8_t* data, size_t size, parsed_header& header, size_t& consumed)
{
  const uint8_t* p = data;
  const uint8_t* end = data + size;
  if (!read_uvarint(p, end, header.major_version) || header.major_version > 0xff)
    return false;
  if (!read_uvarint(p, end, header.minor_version) || header.minor_version > 0xff)
    return false;
  if (!read_uvarint(p, end, header.timestamp))
    return false;
  if (static_cast<size_t>(end - p) < 32 + 4 + 32)
    return false;
  memcpy(header.prev_id.data, p, 32);
  p += 32;
  header.nonce = static_cast<uint32_t>(get_le(p, 4));
  p += 4;
  memcpy(header.merkle_root.data, p, 32);
  p += 32;
  if (!read_uvarint(p, end, header.tx_count))
    return false;
  consumed = p - data;
  return true;
}

void serialize_raw_header(const parsed_header& header, std::string& out)
{
  append_uvarint(out, header.major_version);
  append_uvarint(out, header.minor_version);
  append_uvarint(out, header.timestamp);
  out.append(header.prev_id.data, 32);
  char nonce[4];
  put_le(reinterpret_cast<uint8_t*>(nonce), header.nonce, 4);
  out.append(nonce, 4);
  out.append(header.merkle_root.data, 32);
  append_uvarint(out, header.tx_count);
}

void to_record(const parsed_header& header, uint8_t record[RECORD_BYTES])
{
  record[0] = static_cast<uint8_t>(header.major_version);
  record[1] = static_cast<uint8_t>(header.minor_version);
  put_le(record + REC_OFF_TIMESTAMP, header.timestamp, 8);
  put_le(record + REC_OFF_NONCE, header.nonce, 4);
  memcpy(record + REC_OFF_MERKLE, header.merkle_root.data, 32);
  put_le(record + REC_OFF_TX_COUNT, header.tx_count, 8);
}

void from_record(const uint8_t record[RECORD_BYTES], const crypto::hash& prev_id, parsed_header& header)
{
  header.major_version = record[0];
  header.minor_version = record[1];
  header.timestamp = get_le(record + REC_OFF_TIMESTAMP, 8);
  header.prev_id = prev_id;
  header.nonce = static_cast<uint32_t>(get_le(record + REC_OFF_NONCE, 4));
  memcpy(header.merkle_root.data, record + REC_OFF_MERKLE, 32);
  header.tx_count = get_le(record + REC_OFF_TX_COUNT, 8);
}

crypto::hash hashing_blob_id(const uint8_t* blob, size_t size)
{
  std::string buf;
  buf.reserve(size + 4);
  append_uvarint(buf, size);
  buf.append(reinterpret_cast<const char*>(blob), size);
  crypto::hash id;
  crypto::cn_fast_hash(buf.data(), buf.size(), id);
  return id;
}

void delta_encode(const uint8_t seed[RECORD_BYTES], const uint8_t* records, size_t count, uint8_t* out, delta_variant variant)
{
  int_field fields[2];
  const size_t nfields = variant_int_fields(variant, fields);
  const uint8_t* prev = seed;
  for (size_t i = 0; i < count; ++i)
  {
    const uint8_t* cur = records + i * RECORD_BYTES;
    uint8_t* o = out + i * RECORD_BYTES;
    for (size_t j = 0; j < RECORD_BYTES; ++j)
      o[j] = cur[j] ^ prev[j];
    for (size_t f = 0; f < nfields; ++f)
    {
      const uint64_t d = get_le(cur + fields[f].offset, fields[f].size) - get_le(prev + fields[f].offset, fields[f].size);
      put_le(o + fields[f].offset, zigzag(d), fields[f].size);
    }
    prev = cur;
  }
}

void delta_decode(const uint8_t seed[RECORD_BYTES], const uint8_t* deltas, size_t count, uint8_t* out, delta_variant variant)
{
  int_field fields[2];
  const size_t nfields = variant_int_fields(variant, fields);
  const uint8_t* prev = seed;
  for (size_t i = 0; i < count; ++i)
  {
    const uint8_t* d = deltas + i * RECORD_BYTES;
    uint8_t* o = out + i * RECORD_BYTES;
    for (size_t j = 0; j < RECORD_BYTES; ++j)
      o[j] = d[j] ^ prev[j];
    for (size_t f = 0; f < nfields; ++f)
    {
      const uint64_t v = get_le(prev + fields[f].offset, fields[f].size) + unzigzag(get_le(d + fields[f].offset, fields[f].size));
      put_le(o + fields[f].offset, v, fields[f].size);
    }
    prev = o;
  }
}

void permute_nonce_bits(uint8_t* records, size_t count, const uint8_t order[32])
{
  for (size_t i = 0; i < count; ++i)
  {
    uint8_t* p = records + i * RECORD_BYTES + REC_OFF_NONCE;
    const uint32_t src = static_cast<uint32_t>(get_le(p, 4));
    uint32_t dst = 0;
    for (unsigned k = 0; k < 32; ++k)
      dst |= ((src >> order[k]) & 1u) << k;
    put_le(p, dst, 4);
  }
}

void unpermute_nonce_bits(uint8_t* records, size_t count, const uint8_t order[32])
{
  for (size_t i = 0; i < count; ++i)
  {
    uint8_t* p = records + i * RECORD_BYTES + REC_OFF_NONCE;
    const uint32_t src = static_cast<uint32_t>(get_le(p, 4));
    uint32_t dst = 0;
    for (unsigned k = 0; k < 32; ++k)
      dst |= ((src >> k) & 1u) << order[k];
    put_le(p, dst, 4);
  }
}

void transpose(const uint8_t* records, size_t count, const uint8_t order[RECORD_BYTES], uint8_t* out)
{
  for (size_t r = 0; r < RECORD_BYTES; ++r)
  {
    const size_t pos = order[r];
    for (size_t j = 0; j < count; ++j)
      out[r * count + j] = records[j * RECORD_BYTES + pos];
  }
}

void untranspose(const uint8_t* stream, size_t count, const uint8_t order[RECORD_BYTES], uint8_t* out)
{
  for (size_t r = 0; r < RECORD_BYTES; ++r)
  {
    const size_t pos = order[r];
    for (size_t j = 0; j < count; ++j)
      out[j * RECORD_BYTES + pos] = stream[r * count + j];
  }
}

std::string compress_records(const uint8_t seed[RECORD_BYTES], const uint8_t* records, size_t count, const codec_params& params)
{
  if (count == 0 || count > SIZE_MAX / RECORD_BYTES / 2 || !validate_params(params))
    return std::string();

  const size_t stream_len = count * RECORD_BYTES;
  std::vector<uint8_t> deltas(stream_len), stream(stream_len);
  delta_encode(seed, records, count, deltas.data(), params.variant);
  permute_nonce_bits(deltas.data(), count, params.nonce_bit_order);
  transpose(deltas.data(), count, params.order, stream.data());

  size_t zero_run = 0;
  while (zero_run < stream_len && stream[zero_run] == 0)
    ++zero_run;

  std::vector<cum_table> tabs;
  build_cum_tables(params, tabs);

  // candidate split points: hardcoded ratio plus each calibrated offset, plus the
  // all-raw fallback (a strict win on incompressible payloads)
  std::vector<size_t> candidates;
  candidates.push_back(zero_run);
  for (size_t k = 0; k < SPLIT_CANDIDATES; ++k)
  {
    const double r = params.split_ratio + params.split_offsets[k];
    long long c = std::llround(r * static_cast<double>(stream_len));
    if (c < static_cast<long long>(zero_run))
      c = zero_run;
    if (c > static_cast<long long>(stream_len))
      c = stream_len;
    candidates.push_back(static_cast<size_t>(c));
  }
  std::sort(candidates.begin(), candidates.end());
  candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());

  std::string best_enc;
  size_t best_cand = 0;
  size_t best_cost = SIZE_MAX;
  for (size_t i = 0; i < candidates.size(); ++i)
  {
    const size_t cand = candidates[i];
    std::string enc;
    if (cand > zero_run)
      enc = rans_encode(stream.data(), zero_run, cand, count, params, tabs);
    const size_t cost = uvarint_size(zero_run) + uvarint_size(enc.size()) + enc.size() + (stream_len - cand);
    if (cost < best_cost)
    {
      best_cost = cost;
      best_cand = cand;
      best_enc.swap(enc);
    }
  }

  std::string out;
  out.reserve(best_cost);
  append_uvarint(out, zero_run);
  append_uvarint(out, best_enc.size());
  out += best_enc;
  out.append(reinterpret_cast<const char*>(stream.data()) + best_cand, stream_len - best_cand);
  return out;
}

bool decompress_records(const uint8_t* in, size_t size, size_t count, const uint8_t seed[RECORD_BYTES], const codec_params& params, std::vector<uint8_t>& records_out)
{
  if (count == 0 || count > SIZE_MAX / RECORD_BYTES / 2 || !validate_params(params))
    return false;

  const size_t stream_len = count * RECORD_BYTES;
  const uint8_t* p = in;
  const uint8_t* end = in + size;
  uint64_t zero_run = 0, csize = 0;
  if (!read_uvarint(p, end, zero_run) || zero_run > stream_len)
    return false;
  if (!read_uvarint(p, end, csize) || csize > static_cast<uint64_t>(end - p))
    return false;
  const uint8_t* cblob = p;
  p += csize;
  const size_t raw_len = end - p;
  if (raw_len > stream_len - zero_run)
    return false;
  const size_t split = stream_len - raw_len;
  if (split == zero_run && csize != 0)
    return false;

  std::vector<uint8_t> stream(stream_len, 0);
  if (split > zero_run)
  {
    std::vector<cum_table> tabs;
    build_cum_tables(params, tabs);
    if (!rans_decode(cblob, csize, stream.data(), zero_run, split, count, params, tabs))
      return false;
  }
  memcpy(stream.data() + split, p, raw_len);

  std::vector<uint8_t> deltas(stream_len);
  untranspose(stream.data(), count, params.order, deltas.data());
  unpermute_nonce_bits(deltas.data(), count, params.nonce_bit_order);
  records_out.resize(stream_len);
  delta_decode(seed, deltas.data(), count, records_out.data(), params.variant);
  return true;
}

void quantize_freqs(const uint64_t hist[256], uint16_t freq_out[256])
{
  uint64_t total = 0;
  for (size_t s = 0; s < 256; ++s)
    total += hist[s];
  if (total == 0)
  {
    for (size_t s = 0; s < 256; ++s)
      freq_out[s] = FREQ_SCALE / 256;
    return;
  }

  uint32_t sum = 0;
  for (size_t s = 0; s < 256; ++s)
  {
    // hist[s] <= total <= the number of calibrated headers, so the multiply by
    // FREQ_SCALE (2^14) stays far below 2^64 for any realistic histogram (it would
    // overflow only for counts >= 2^50); kept as 64-bit math to avoid __int128, which
    // this codebase deliberately does not rely on (see cryptonote_basic/difficulty.cpp)
    uint64_t f = (hist[s] * static_cast<uint64_t>(FREQ_SCALE)) / total;
    if (f == 0)
      f = 1;
    if (f > FREQ_SCALE - 255)
      f = FREQ_SCALE - 255; // leave room for the 255 other minimum entries
    freq_out[s] = static_cast<uint16_t>(f);
    sum += static_cast<uint32_t>(f);
  }
  // settle the rounding remainder on the most/least distorted entries
  while (sum > FREQ_SCALE)
  {
    size_t best = 0;
    for (size_t s = 1; s < 256; ++s)
      if (freq_out[s] > freq_out[best])
        best = s;
    --freq_out[best];
    --sum;
  }
  while (sum < FREQ_SCALE)
  {
    size_t best = 0;
    uint64_t best_key = 0;
    for (size_t s = 0; s < 256; ++s)
    {
      if (hist[s] > best_key)
      {
        best_key = hist[s];
        best = s;
      }
    }
    ++freq_out[best];
    ++sum;
  }
}

bool compress_chunk(const std::vector<std::string>& hashing_blobs, const chunk_info& info, std::string& out)
{
  const size_t n = hashing_blobs.size();
  if (n < 2)
    return false;

  std::vector<uint8_t> records((n - 1) * RECORD_BYTES);
  uint8_t seed[RECORD_BYTES];
  crypto::hash prev_id = crypto::null_hash;
  for (size_t i = 0; i < n; ++i)
  {
    const std::string& blob = hashing_blobs[i];
    parsed_header h;
    size_t consumed = 0;
    if (!parse_raw_header(reinterpret_cast<const uint8_t*>(blob.data()), blob.size(), h, consumed) || consumed != blob.size())
      return false;
    // byte-exact reconstruction requires canonical serialization and a valid chain
    std::string check;
    serialize_raw_header(h, check);
    if (check != blob)
      return false;
    if (i > 0 && h.prev_id != prev_id)
      return false;
    if (i == 0)
      to_record(h, seed);
    else
      to_record(h, records.data() + (i - 1) * RECORD_BYTES);
    prev_id = hashing_blob_id(reinterpret_cast<const uint8_t*>(blob.data()), blob.size());
  }

  const std::string coded = compress_records(seed, records.data(), n - 1, v1_params());
  if (coded.empty())
    return false;

  out.clear();
  out.reserve(coded.size() + hashing_blobs[0].size() + 40);
  out.push_back(static_cast<char>(FORMAT_VERSION));
  append_uvarint(out, info.height);
  append_uvarint(out, info.cumulative_difficulty_low);
  append_uvarint(out, info.cumulative_difficulty_high);
  append_uvarint(out, n);
  out += hashing_blobs[0];
  out += coded;
  return true;
}

bool decompress_chunk(const std::string& in, chunk_info& info, std::vector<std::string>& hashing_blobs, std::vector<crypto::hash>* block_ids, size_t max_headers)
{
  const uint8_t* p = reinterpret_cast<const uint8_t*>(in.data());
  const uint8_t* end = p + in.size();
  if (p == end || *p++ != FORMAT_VERSION)
    return false;
  uint64_t n = 0;
  if (!read_uvarint(p, end, info.height))
    return false;
  if (!read_uvarint(p, end, info.cumulative_difficulty_low))
    return false;
  if (!read_uvarint(p, end, info.cumulative_difficulty_high))
    return false;
  if (!read_uvarint(p, end, n) || n < 2 || n > max_headers)
    return false;

  parsed_header h0;
  size_t consumed = 0;
  if (!parse_raw_header(p, end - p, h0, consumed))
    return false;
  const uint8_t* header0 = p;
  p += consumed;

  uint8_t seed[RECORD_BYTES];
  to_record(h0, seed);
  std::vector<uint8_t> records;
  if (!decompress_records(p, end - p, n - 1, seed, v1_params(), records))
    return false;

  hashing_blobs.clear();
  hashing_blobs.reserve(n);
  if (block_ids)
  {
    block_ids->clear();
    block_ids->reserve(n);
  }
  hashing_blobs.emplace_back(reinterpret_cast<const char*>(header0), consumed);
  crypto::hash id = hashing_blob_id(header0, consumed);
  if (block_ids)
    block_ids->push_back(id);
  for (size_t i = 1; i < n; ++i)
  {
    parsed_header h;
    from_record(records.data() + (i - 1) * RECORD_BYTES, id, h);
    std::string blob;
    serialize_raw_header(h, blob);
    id = hashing_blob_id(reinterpret_cast<const uint8_t*>(blob.data()), blob.size());
    if (block_ids)
      block_ids->push_back(id);
    hashing_blobs.push_back(std::move(blob));
  }
  return true;
}

const codec_params& v1_params()
{
  static const codec_params params = []() {
    codec_params p;
    p.variant = static_cast<delta_variant>(detail::V1_VARIANT);
    p.split_ratio = detail::V1_SPLIT_RATIO;
    memcpy(p.split_offsets, detail::V1_SPLIT_OFFSETS, sizeof(p.split_offsets));
    memcpy(p.nonce_bit_order, detail::V1_NONCE_BIT_ORDER, sizeof(p.nonce_bit_order));
    memcpy(p.order, detail::V1_ORDER, sizeof(p.order));
    memcpy(p.freq, detail::V1_FREQ, sizeof(p.freq));
    return p;
  }();
  return params;
}

}}

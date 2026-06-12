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

// Calibration and benchmark tool for the header-only sync wire format
// (src/common/header_codec.h): reads a range of real blocks from the blockchain
// database, measures per-byte statistics of delta-coded headers, calibrates the
// entropy order / frequency tables / split ratio, compares delta variants, plane
// orderings and entropy coding backends (static rANS vs raw deflate -9), and emits
// the hardcoded tables used by format version 1.

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <string>
#include <vector>

#include <boost/filesystem.hpp>
#include <zlib.h>

#include "common/command_line.h"
#include "common/header_codec.h"
#include "common/util.h"
#include "common/varint.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/blockchain.h"
#include "blockchain_db/blockchain_db.h"
#include "version.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bcutil"

namespace po = boost::program_options;
using namespace cryptonote;
namespace hc = tools::header_codec;

namespace
{

constexpr size_t REC = hc::RECORD_BYTES;

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

const char* position_name(size_t pos)
{
  static char buf[16];
  if (pos == 0) return "major";
  if (pos == 1) return "minor";
  if (pos < hc::REC_OFF_NONCE) { snprintf(buf, sizeof(buf), "ts[%zu]", pos - hc::REC_OFF_TIMESTAMP); return buf; }
  if (pos < hc::REC_OFF_MERKLE) { snprintf(buf, sizeof(buf), "nonce[%zu]", pos - hc::REC_OFF_NONCE); return buf; }
  if (pos < hc::REC_OFF_TX_COUNT) { snprintf(buf, sizeof(buf), "merkle[%zu]", pos - hc::REC_OFF_MERKLE); return buf; }
  snprintf(buf, sizeof(buf), "txcnt[%zu]", pos - hc::REC_OFF_TX_COUNT);
  return buf;
}

struct pos_stats
{
  std::vector<std::array<uint64_t, 256>> hist; // [REC][256]
  pos_stats() : hist(REC) { for (auto &h : hist) h.fill(0); }

  double entropy(size_t pos) const
  {
    uint64_t total = 0;
    for (size_t s = 0; s < 256; ++s) total += hist[pos][s];
    if (!total) return 0.0;
    double e = 0.0;
    for (size_t s = 0; s < 256; ++s)
    {
      if (!hist[pos][s]) continue;
      const double p = double(hist[pos][s]) / double(total);
      e -= p * std::log2(p);
    }
    return e;
  }

  double p_nonzero(size_t pos) const
  {
    uint64_t total = 0;
    for (size_t s = 0; s < 256; ++s) total += hist[pos][s];
    return total ? 1.0 - double(hist[pos][0]) / double(total) : 0.0;
  }
};

// accumulate per-position delta histograms over records [begin, end) of the sample,
// each record delta-coded against its predecessor (record begin-1 acts as seed);
// nonce_bit_order, if non-null, is applied between the delta and the histograms,
// exactly as the codec pipeline does
void accumulate_hists(const std::vector<uint8_t>& records, size_t begin, size_t end, hc::delta_variant v, const uint8_t* nonce_bit_order, pos_stats& st)
{
  std::vector<uint8_t> delta(REC);
  for (size_t i = begin; i < end; ++i)
  {
    hc::delta_encode(records.data() + (i - 1) * REC, records.data() + i * REC, 1, delta.data(), v);
    if (nonce_bit_order)
      hc::permute_nonce_bits(delta.data(), 1, nonce_bit_order);
    for (size_t pos = 0; pos < REC; ++pos)
      ++st.hist[pos][delta[pos]];
  }
}

uint32_t record_nonce(const std::vector<uint8_t>& records, size_t i)
{
  const uint8_t* p = records.data() + i * REC + hc::REC_OFF_NONCE;
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// per-bit flip probability of the nonce XOR delta over records [begin, end)
std::array<double, 32> nonce_bit_flip_probs(const std::vector<uint8_t>& records, size_t begin, size_t end)
{
  uint64_t flips[32] = {};
  for (size_t i = begin; i < end; ++i)
  {
    const uint32_t d = record_nonce(records, i) ^ record_nonce(records, i - 1);
    for (unsigned b = 0; b < 32; ++b)
      flips[b] += (d >> b) & 1;
  }
  std::array<double, 32> p;
  for (unsigned b = 0; b < 32; ++b)
    p[b] = double(flips[b]) / double(end - begin);
  return p;
}

double binary_entropy(double p)
{
  if (p <= 0.0 || p >= 1.0)
    return 0.0;
  return -p * std::log2(p) - (1.0 - p) * std::log2(1.0 - p);
}

const std::array<uint8_t, 32> identity_bit_order()
{
  std::array<uint8_t, 32> order;
  for (unsigned b = 0; b < 32; ++b)
    order[b] = b;
  return order;
}

std::array<uint8_t, REC> make_order(const pos_stats& st, bool by_entropy)
{
  std::array<uint8_t, REC> order;
  for (size_t i = 0; i < REC; ++i) order[i] = i;
  std::stable_sort(order.begin(), order.end(), [&](uint8_t a, uint8_t b) {
    const double ka = by_entropy ? st.entropy(a) : st.p_nonzero(a);
    const double kb = by_entropy ? st.entropy(b) : st.p_nonzero(b);
    if (ka != kb) return ka < kb;
    return a < b;
  });
  return order;
}

hc::codec_params make_params(hc::delta_variant v, const std::array<uint8_t, REC>& order, const pos_stats& st, double ratio, const std::array<uint8_t, 32>& nonce_bit_order)
{
  hc::codec_params p;
  p.variant = v;
  p.split_ratio = ratio;
  for (size_t k = 0; k < hc::SPLIT_CANDIDATES; ++k)
    p.split_offsets[k] = 0.01 * (double(k) - double(hc::SPLIT_CANDIDATES / 2)); // classic -3..+3 points
  memcpy(p.nonce_bit_order, nonce_bit_order.data(), 32);
  memcpy(p.order, order.data(), REC);
  for (size_t pos = 0; pos < REC; ++pos)
    hc::quantize_freqs(st.hist[pos].data(), p.freq[pos]);
  return p;
}

struct sample_data
{
  uint64_t start_height = 0;
  size_t count = 0;
  std::vector<uint8_t> records;            // count * REC
  std::vector<crypto::hash> ids;           // block id per sample header
  crypto::hash first_prev_id = crypto::null_hash; // prev_id of the first sample header
  std::vector<uint64_t> cumdiff_low, cumdiff_high; // per sample header
};

// raw hashing blob of sample header i (byte-exact, verified at load time)
std::string sample_blob(const sample_data& d, size_t i)
{
  hc::parsed_header h;
  hc::from_record(d.records.data() + i * REC, i ? d.ids[i - 1] : d.first_prev_id, h);
  std::string blob;
  hc::serialize_raw_header(h, blob);
  return blob;
}

size_t container_overhead(const sample_data& d, size_t base, size_t chunk_size)
{
  return 1 + uvarint_size(d.start_height + base) + uvarint_size(d.cumdiff_low[base]) +
         uvarint_size(d.cumdiff_high[base]) + uvarint_size(chunk_size) + sample_blob(d, base).size();
}

// ---- split candidate sweep ----------------------------------------------------------
// evaluates every split (split_ratio + k/100) * stream_len for k in {-5.0..5.0} step
// 0.1 on each chunk, with true rANS encodes, and counts per-chunk winners

constexpr int SWEEP_POINTS = 101;
inline double sweep_k(int i) { return -5.0 + 0.1 * i; } // in percentage points

struct sweep_result
{
  std::array<uint64_t, SWEEP_POINTS> wins{};
  uint64_t fallback_wins = 0; // chunks where all-raw beats the whole grid (expect 0)
  uint64_t ties = 0;          // chunks with more than one winning k
  double mean_best = 0.0;     // mean codec-section cost at the per-chunk grid/fallback best
  std::vector<std::array<uint32_t, SWEEP_POINTS>> costs; // per chunk, per grid point
  std::vector<uint32_t> fallback_costs;                  // per chunk
};

size_t chunk_cost_at_splits(const std::vector<uint8_t>& stream, size_t zero_run, size_t M, const hc::codec_params& params, const std::vector<size_t>& splits, std::vector<size_t>& costs)
{
  costs.assign(splits.size(), SIZE_MAX);
  size_t best = SIZE_MAX;
  for (size_t i = 0; i < splits.size(); ++i)
  {
    const size_t split = splits[i];
    std::string enc;
    if (split > zero_run)
    {
      enc = hc::entropy_code_region(stream.data(), zero_run, split, M, params);
      if (enc.empty())
        continue;
    }
    costs[i] = uvarint_size(zero_run) + uvarint_size(enc.size()) + enc.size() + (stream.size() - split);
    best = std::min(best, costs[i]);
  }
  return best;
}

size_t ratio_to_split(double ratio, size_t stream_len, size_t zero_run)
{
  long long c = std::llround(ratio * double(stream_len));
  c = std::max<long long>(c, zero_run);
  c = std::min<long long>(c, stream_len);
  return size_t(c);
}

sweep_result split_sweep(const sample_data& d, size_t chunk_size, const hc::codec_params& params, const std::vector<size_t>& bases)
{
  sweep_result res;
  const size_t M = chunk_size - 1;
  std::vector<uint8_t> deltas(M * REC), stream(M * REC);
  std::vector<size_t> splits(SWEEP_POINTS), costs;
  double total = 0.0;
  for (size_t b : bases)
  {
    hc::delta_encode(d.records.data() + b * REC, d.records.data() + (b + 1) * REC, M, deltas.data(), params.variant);
    hc::permute_nonce_bits(deltas.data(), M, params.nonce_bit_order);
    hc::transpose(deltas.data(), M, params.order, stream.data());
    size_t zero_run = 0;
    while (zero_run < stream.size() && stream[zero_run] == 0) ++zero_run;
    for (int i = 0; i < SWEEP_POINTS; ++i)
      splits[i] = ratio_to_split(params.split_ratio + sweep_k(i) / 100.0, stream.size(), zero_run);
    const size_t best = chunk_cost_at_splits(stream, zero_run, M, params, splits, costs);
    const size_t fallback = uvarint_size(zero_run) + uvarint_size(0) + (stream.size() - zero_run);
    if (fallback < best)
      ++res.fallback_wins;
    total += double(std::min(best, fallback));
    unsigned winners = 0;
    res.costs.emplace_back();
    for (int i = 0; i < SWEEP_POINTS; ++i)
    {
      res.costs.back()[i] = static_cast<uint32_t>(std::min<size_t>(costs[i], UINT32_MAX));
      if (costs[i] == best)
      {
        ++res.wins[i];
        ++winners;
      }
    }
    res.fallback_costs.push_back(static_cast<uint32_t>(fallback));
    if (winners > 1)
      ++res.ties;
  }
  res.mean_best = bases.empty() ? 0.0 : total / double(bases.size());
  return res;
}

// top SPLIT_CANDIDATES offsets by win count; ties broken toward smaller |k|, then
// smaller k; returned sorted ascending
std::array<double, hc::SPLIT_CANDIDATES> pick_split_offsets(const sweep_result& res)
{
  std::array<int, SWEEP_POINTS> idx;
  for (int i = 0; i < SWEEP_POINTS; ++i)
    idx[i] = i;
  std::stable_sort(idx.begin(), idx.end(), [&](int a, int b) {
    if (res.wins[a] != res.wins[b]) return res.wins[a] > res.wins[b];
    const double ka = std::fabs(sweep_k(a)), kb = std::fabs(sweep_k(b));
    if (ka != kb) return ka < kb;
    return sweep_k(a) < sweep_k(b);
  });
  std::array<double, hc::SPLIT_CANDIDATES> offsets;
  for (size_t i = 0; i < hc::SPLIT_CANDIDATES; ++i)
    offsets[i] = sweep_k(idx[i]) / 100.0;
  std::sort(offsets.begin(), offsets.end());
  return offsets;
}

// greedy coverage selection: pick SPLIT_CANDIDATES grid points minimizing the mean
// over chunks of min(cost over chosen points, fallback). Win counts mislead here:
// the cost surface is a flat plateau (most chunks have many tied winners), so the
// most-winning points cluster together; what a candidate *set* needs is to cover the
// spread of per-chunk optima. Ties broken toward smaller |k|, then smaller k.
std::array<double, hc::SPLIT_CANDIDATES> greedy_split_offsets(const sweep_result& res, double* achieved_mean)
{
  const size_t n = res.costs.size();
  std::vector<uint32_t> cur_min(res.fallback_costs); // fallback is always available
  std::array<bool, SWEEP_POINTS> used{};
  std::array<double, hc::SPLIT_CANDIDATES> offsets{};
  double mean = 0.0;
  for (size_t round = 0; round < hc::SPLIT_CANDIDATES; ++round)
  {
    int best_i = -1;
    double best_total = 1e300;
    for (int i = 0; i < SWEEP_POINTS; ++i)
    {
      if (used[i])
        continue;
      double total = 0.0;
      for (size_t c = 0; c < n; ++c)
        total += double(std::min(cur_min[c], res.costs[c][i]));
      const bool better = total < best_total - 1e-9;
      const bool tie = !better && total < best_total + 1e-9 && best_i >= 0 &&
                       (std::fabs(sweep_k(i)) < std::fabs(sweep_k(best_i)) ||
                        (std::fabs(sweep_k(i)) == std::fabs(sweep_k(best_i)) && sweep_k(i) < sweep_k(best_i)));
      if (better || tie)
      {
        best_total = std::min(best_total, total);
        best_i = i;
      }
    }
    used[best_i] = true;
    offsets[round] = sweep_k(best_i) / 100.0;
    for (size_t c = 0; c < n; ++c)
      cur_min[c] = std::min(cur_min[c], res.costs[c][best_i]);
    mean = best_total / double(n ? n : 1);
  }
  std::sort(offsets.begin(), offsets.end());
  if (achieved_mean)
    *achieved_mean = mean;
  return offsets;
}

// mean codec-section cost over chunks using a specific candidate offset set (plus the
// all-raw fallback), i.e. the production encoder policy
double mean_cost_with_offsets(const sample_data& d, size_t chunk_size, const hc::codec_params& params, const std::vector<size_t>& bases, const double* offsets, size_t n_offsets)
{
  const size_t M = chunk_size - 1;
  std::vector<uint8_t> deltas(M * REC), stream(M * REC);
  std::vector<size_t> splits(n_offsets), costs;
  double total = 0.0;
  for (size_t b : bases)
  {
    hc::delta_encode(d.records.data() + b * REC, d.records.data() + (b + 1) * REC, M, deltas.data(), params.variant);
    hc::permute_nonce_bits(deltas.data(), M, params.nonce_bit_order);
    hc::transpose(deltas.data(), M, params.order, stream.data());
    size_t zero_run = 0;
    while (zero_run < stream.size() && stream[zero_run] == 0) ++zero_run;
    for (size_t i = 0; i < n_offsets; ++i)
      splits[i] = ratio_to_split(params.split_ratio + offsets[i], stream.size(), zero_run);
    const size_t best = chunk_cost_at_splits(stream, zero_run, M, params, splits, costs);
    const size_t fallback = uvarint_size(zero_run) + uvarint_size(0) + (stream.size() - zero_run);
    total += double(std::min(best, fallback));
  }
  return bases.empty() ? 0.0 : total / double(bases.size());
}

// exact byte-granular optimal split under the rANS cost model (bits = -log2(f/SCALE)),
// returns the best split offset for the given transposed stream
size_t optimal_split_estimate(const std::vector<uint8_t>& stream, size_t zero_run, size_t count, const hc::codec_params& p)
{
  const size_t len = stream.size();
  double best_cost = 1e300;
  size_t best = zero_run;
  double bits = 0.0;
  // cost(split) = bits(zero_run..split)/8 + (len - split), constants dropped
  for (size_t split = zero_run; split <= len; ++split)
  {
    const double cost = bits / 8.0 + double(len - split);
    if (cost < best_cost)
    {
      best_cost = cost;
      best = split;
    }
    if (split == len)
      break;
    const uint8_t orig = p.order[split / count];
    bits -= std::log2(double(p.freq[orig][stream[split]]) / double(hc::FREQ_SCALE));
  }
  return best;
}

bool deflate_raw9(const uint8_t* data, size_t size, std::string& out)
{
  z_stream zs;
  memset(&zs, 0, sizeof(zs));
  if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY) != Z_OK)
    return false;
  out.resize(deflateBound(&zs, size));
  zs.next_in = const_cast<Bytef*>(data);
  zs.avail_in = size;
  zs.next_out = reinterpret_cast<Bytef*>(&out[0]);
  zs.avail_out = out.size();
  const int rc = deflate(&zs, Z_FINISH);
  const size_t produced = out.size() - zs.avail_out;
  deflateEnd(&zs);
  if (rc != Z_STREAM_END)
    return false;
  out.resize(produced);
  return true;
}

struct bench_result
{
  std::string name;
  double mean = 0.0, median = 0.0, p95 = 0.0;
  size_t chunks = 0;
};

void summarize(const std::string& name, std::vector<size_t>& sizes, size_t chunk_size, std::vector<bench_result>& results)
{
  if (sizes.empty())
    return;
  std::sort(sizes.begin(), sizes.end());
  bench_result r;
  r.name = name;
  r.chunks = sizes.size();
  double sum = 0.0;
  for (size_t s : sizes) sum += s;
  r.mean = sum / sizes.size();
  r.median = sizes[sizes.size() / 2];
  r.p95 = sizes[(sizes.size() * 95) / 100 < sizes.size() ? (sizes.size() * 95) / 100 : sizes.size() - 1];
  results.push_back(r);
  std::cout << "  " << std::left << std::setw(38) << name << std::right
            << "  mean " << std::fixed << std::setprecision(1) << std::setw(8) << r.mean
            << "  median " << std::setw(6) << (uint64_t)r.median
            << "  p95 " << std::setw(6) << (uint64_t)r.p95
            << "  bytes/header " << std::setprecision(3) << r.mean / chunk_size
            << "  (" << r.chunks << " chunks)" << std::endl;
}

// ---------------------------------------------------------------------------------
// self test (no database): round-trip the codec on synthetic and adversarial inputs
// ---------------------------------------------------------------------------------

hc::codec_params random_params(std::mt19937_64& rng, int style)
{
  std::array<uint8_t, REC> order;
  for (size_t i = 0; i < REC; ++i) order[i] = i;
  std::shuffle(order.begin(), order.end(), rng);
  hc::codec_params p;
  p.variant = static_cast<hc::delta_variant>(rng() % 3);
  p.split_ratio = double(rng() % 1001) / 1000.0;
  for (size_t k = 0; k < hc::SPLIT_CANDIDATES; ++k)
    p.split_offsets[k] = double(int(rng() % 2001) - 1000) / 10000.0; // [-0.1, 0.1]
  for (unsigned k = 0; k < 32; ++k)
    p.nonce_bit_order[k] = k;
  if (style % 2)
    std::shuffle(p.nonce_bit_order, p.nonce_bit_order + 32, rng);
  memcpy(p.order, order.data(), REC);
  for (size_t pos = 0; pos < REC; ++pos)
  {
    uint64_t hist[256];
    for (size_t s = 0; s < 256; ++s)
    {
      switch (style % 3)
      {
        case 0: hist[s] = rng() % 1000; break;             // arbitrary
        case 1: hist[s] = s == 0 ? 1000000 : rng() % 3; break; // highly skewed
        default: hist[s] = 1; break;                        // uniform
      }
    }
    hc::quantize_freqs(hist, p.freq[pos]);
  }
  return p;
}

void fill_payload(std::mt19937_64& rng, int style, std::vector<uint8_t>& data)
{
  switch (style % 5)
  {
    case 0: for (auto& b : data) b = rng() & 0xff; break;
    case 1: std::fill(data.begin(), data.end(), 0); break;
    case 2: std::fill(data.begin(), data.end(), 0xff); break;
    case 3:
    {
      std::vector<uint8_t> rec(REC);
      for (auto& b : rec) b = rng() & 0xff;
      for (size_t i = 0; i < data.size(); ++i) data[i] = rec[i % REC];
      break;
    }
    default: // header-like
    {
      uint64_t ts = 1700000000 + rng() % 1000000;
      for (size_t i = 0; i * REC < data.size(); ++i)
      {
        hc::parsed_header h;
        h.major_version = 16;
        h.minor_version = 16;
        ts += 30 + rng() % 240 - (rng() % 5 == 0 ? 200 : 0);
        h.timestamp = ts;
        h.prev_id = crypto::null_hash;
        h.nonce = (rng() % 4 == 0 ? rng() : rng() % 100000);
        for (auto& c : h.merkle_root.data) c = rng() & 0xff;
        h.tx_count = 1 + rng() % 150;
        hc::to_record(h, data.data() + i * REC);
      }
      break;
    }
  }
}

bool make_synthetic_chain(std::mt19937_64& rng, size_t n, std::vector<std::string>& blobs)
{
  blobs.clear();
  crypto::hash prev;
  for (auto& c : prev.data) c = rng() & 0xff;
  uint64_t ts = 1700000000;
  for (size_t i = 0; i < n; ++i)
  {
    hc::parsed_header h;
    h.major_version = 16;
    h.minor_version = 16;
    ts += 30 + rng() % 240;
    h.timestamp = ts;
    h.prev_id = prev;
    h.nonce = static_cast<uint32_t>(rng());
    for (auto& c : h.merkle_root.data) c = rng() & 0xff;
    h.tx_count = 1 + rng() % 300;
    std::string blob;
    hc::serialize_raw_header(h, blob);
    prev = hc::hashing_blob_id(reinterpret_cast<const uint8_t*>(blob.data()), blob.size());
    blobs.push_back(std::move(blob));
  }
  return true;
}

int self_test()
{
  std::mt19937_64 rng(0x5eed5eed);
  size_t failures = 0, cases = 0;

  // low-level codec round trips
  const size_t counts[] = {1, 2, 3, 7, 64, 999};
  for (int round = 0; round < 60; ++round)
  {
    const size_t count = counts[round % (sizeof(counts) / sizeof(counts[0]))];
    hc::codec_params p = random_params(rng, round);
    std::vector<uint8_t> data(count * REC), seed(REC);
    fill_payload(rng, round, data);
    for (auto& b : seed) b = rng() & 0xff;

    const std::string coded = hc::compress_records(seed.data(), data.data(), count, p);
    std::vector<uint8_t> back;
    ++cases;
    if (coded.empty() ||
        !hc::decompress_records(reinterpret_cast<const uint8_t*>(coded.data()), coded.size(), count, seed.data(), p, back) ||
        back != data)
    {
      std::cout << "FAIL: record codec round trip, round " << round << ", count " << count << std::endl;
      ++failures;
    }
  }

  // chunk round trips with the baked parameters
  for (int round = 0; round < 10; ++round)
  {
    std::vector<std::string> blobs;
    make_synthetic_chain(rng, 2 + rng() % 120, blobs);
    hc::chunk_info info;
    info.height = 1978433 + (rng() % 1000000);
    info.cumulative_difficulty_low = rng();
    info.cumulative_difficulty_high = rng() % 3;
    std::string chunk;
    std::vector<std::string> back;
    std::vector<crypto::hash> ids;
    hc::chunk_info info2;
    ++cases;
    if (!hc::compress_chunk(blobs, info, chunk) ||
        !hc::decompress_chunk(chunk, info2, back, &ids) ||
        back != blobs || ids.size() != blobs.size() ||
        info2.height != info.height ||
        info2.cumulative_difficulty_low != info.cumulative_difficulty_low ||
        info2.cumulative_difficulty_high != info.cumulative_difficulty_high)
    {
      std::cout << "FAIL: chunk round trip, round " << round << std::endl;
      ++failures;
      continue;
    }
    for (size_t i = 0; i < blobs.size(); ++i)
    {
      const crypto::hash id = hc::hashing_blob_id(reinterpret_cast<const uint8_t*>(blobs[i].data()), blobs[i].size());
      if (id != ids[i])
      {
        std::cout << "FAIL: chunk ids, round " << round << std::endl;
        ++failures;
        break;
      }
    }

    // a chunk with a broken prev_id chain must be rejected by the compressor:
    // changing a non-last header's merkle root changes its id, so the successor's
    // prev_id no longer links (the mutated blob itself stays perfectly parseable)
    std::vector<std::string> broken = blobs;
    const size_t victim = broken.size() >= 3 ? broken.size() / 2 : 0;
    hc::parsed_header vh;
    size_t vconsumed = 0;
    hc::parse_raw_header(reinterpret_cast<const uint8_t*>(broken[victim].data()), broken[victim].size(), vh, vconsumed);
    vh.merkle_root.data[7] ^= 1;
    broken[victim].clear();
    hc::serialize_raw_header(vh, broken[victim]);
    std::string out;
    ++cases;
    if (hc::compress_chunk(broken, info, out))
    {
      std::cout << "FAIL: broken chain accepted, round " << round << std::endl;
      ++failures;
    }

    // every truncation must fail to reproduce the original chunk
    ++cases;
    for (size_t len = 0; len < chunk.size(); ++len)
    {
      std::vector<std::string> tback;
      hc::chunk_info tinfo;
      if (hc::decompress_chunk(chunk.substr(0, len), tinfo, tback) && tback == blobs)
      {
        std::cout << "FAIL: truncation to " << len << " reproduced the chunk, round " << round << std::endl;
        ++failures;
        break;
      }
    }

    // bit flips must never crash and must round-trip-or-fail cleanly
    ++cases;
    for (int flips = 0; flips < 200; ++flips)
    {
      std::string mutated = chunk;
      mutated[rng() % mutated.size()] ^= 1 << (rng() % 8);
      std::vector<std::string> mback;
      hc::chunk_info minfo;
      hc::decompress_chunk(mutated, minfo, mback); // any verdict is fine, just no crash/UB
    }
  }

  std::cout << "self test: " << (cases - failures) << "/" << cases << " passed" << std::endl;
  return failures ? 1 : 0;
}

} // anonymous namespace

int main(int argc, char* argv[])
{
  TRY_ENTRY();

  epee::string_tools::set_module_name_and_folder(argv[0]);

  tools::on_startup();

  po::options_description desc_cmd_only("Command line options");
  po::options_description desc_cmd_sett("Command line options and settings options");
  const command_line::arg_descriptor<std::string> arg_log_level = {"log-level", "0-4 or categories", ""};
  const command_line::arg_descriptor<uint64_t> arg_sample_size = {"sample-size", "number of most recent headers to sample", 1000000};
  const command_line::arg_descriptor<uint64_t> arg_chunk_size = {"chunk-size", "headers per chunk in benchmarks", 1000};
  const command_line::arg_descriptor<uint64_t> arg_deflate_chunks = {"deflate-chunks", "training chunks for deflate split calibration", 200};
  const command_line::arg_descriptor<std::string> arg_emit_tables = {"emit-tables", "write the winning calibration tables to this header file", ""};
  const command_line::arg_descriptor<bool> arg_eval_baked = {"eval-baked", "benchmark the baked v1 parameters via the chunk container API", false};
  const command_line::arg_descriptor<bool> arg_self_test = {"self-test", "run codec round-trip self tests and exit (no database)", false};
  const command_line::arg_descriptor<std::string> arg_dump_nonces = {"dump-nonces", "write all sampled nonce values (u32 LE, height order) to this binary file and exit", ""};
  const command_line::arg_descriptor<std::string> arg_dump_stages = {"dump-stages", "write per-stage encoding pipeline dumps of the sampled headers (all but the first, which only seeds the deltas) to this directory and exit", ""};
  const command_line::arg_descriptor<bool> arg_split_sweep = {"split-sweep", "sweep split candidates (ratio - 5%..+5%, 0.1 point steps) over all chunks with the baked v1 parameters, report win counts, then exit unless --emit-tables is also given", false};
  const command_line::arg_descriptor<std::string> arg_bit_order = {"bit-order", "comma-separated 32-entry nonce bit permutation for the bit-sorted benchmarks (overrides the entropy-derived order)", ""};

  command_line::add_arg(desc_cmd_sett, cryptonote::arg_data_dir);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_testnet_on);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_stagenet_on);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_regtest_on); // arg_data_dir depends on it
  command_line::add_arg(desc_cmd_sett, arg_log_level);
  command_line::add_arg(desc_cmd_sett, arg_sample_size);
  command_line::add_arg(desc_cmd_sett, arg_chunk_size);
  command_line::add_arg(desc_cmd_sett, arg_deflate_chunks);
  command_line::add_arg(desc_cmd_sett, arg_emit_tables);
  command_line::add_arg(desc_cmd_sett, arg_eval_baked);
  command_line::add_arg(desc_cmd_sett, arg_self_test);
  command_line::add_arg(desc_cmd_sett, arg_dump_nonces);
  command_line::add_arg(desc_cmd_sett, arg_dump_stages);
  command_line::add_arg(desc_cmd_sett, arg_bit_order);
  command_line::add_arg(desc_cmd_sett, arg_split_sweep);
  command_line::add_arg(desc_cmd_only, command_line::arg_help);

  po::options_description desc_options("Allowed options");
  desc_options.add(desc_cmd_only).add(desc_cmd_sett);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]() {
    auto parser = po::command_line_parser(argc, argv).options(desc_options);
    po::store(parser.run(), vm);
    po::notify(vm);
    return true;
  });
  if (!r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << "Monero '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL << ENDL;
    std::cout << desc_options << std::endl;
    return 1;
  }

  mlog_configure(mlog_get_default_log_path("monero-blockchain-header-stats.log"), true);
  if (!command_line::is_arg_defaulted(vm, arg_log_level))
    mlog_set_log(command_line::get_arg(vm, arg_log_level).c_str());
  else
    mlog_set_log("0,bcutil:INFO");

  if (command_line::get_arg(vm, arg_self_test))
    return self_test();

  const std::string opt_data_dir = command_line::get_arg(vm, cryptonote::arg_data_dir);
  const network_type net_type = command_line::get_arg(vm, cryptonote::arg_testnet_on) ? TESTNET :
                                command_line::get_arg(vm, cryptonote::arg_stagenet_on) ? STAGENET : MAINNET;
  const uint64_t sample_size = command_line::get_arg(vm, arg_sample_size);
  const uint64_t chunk_size = command_line::get_arg(vm, arg_chunk_size);
  const uint64_t deflate_chunks = command_line::get_arg(vm, arg_deflate_chunks);
  const std::string emit_tables = command_line::get_arg(vm, arg_emit_tables);
  const bool eval_baked = command_line::get_arg(vm, arg_eval_baked);

  LOG_PRINT_L0("Initializing source blockchain (BlockchainDB)");
  std::unique_ptr<Blockchain> core_storage;
  tx_memory_pool m_mempool(*core_storage);
  core_storage.reset(new Blockchain(m_mempool));
  BlockchainDB* db = new_db();
  if (db == NULL)
  {
    LOG_ERROR("Failed to initialize a database");
    throw std::runtime_error("Failed to initialize a database");
  }

  const std::string filename = (boost::filesystem::path(opt_data_dir) / db->get_db_name()).string();
  LOG_PRINT_L0("Loading blockchain from folder " << filename << " ...");
  try
  {
    db->open(filename, DBF_RDONLY);
  }
  catch (const std::exception& e)
  {
    LOG_PRINT_L0("Error opening database: " << e.what());
    return 1;
  }
  r = core_storage->init(db, net_type);
  CHECK_AND_ASSERT_MES(r, 1, "Failed to initialize source blockchain storage");

  const uint64_t db_height = db->height();
  if (db_height < 2 || chunk_size < 2)
  {
    std::cout << "not enough blocks / bad chunk size" << std::endl;
    return 1;
  }
  sample_data d;
  d.count = std::min<uint64_t>(sample_size, db_height - 1);
  d.start_height = db_height - d.count;

  std::cout << "database height: " << db_height << std::endl;
  std::cout << "sample: " << d.count << " headers, heights [" << d.start_height << ", " << (db_height - 1) << "]" << std::endl;
  std::cout << "tip id: " << epee::string_tools::pod_to_hex(db->get_block_hash_from_height(db_height - 1)) << std::endl;

  // ---- load and verify -------------------------------------------------------------
  d.records.resize(d.count * REC);
  d.ids.resize(d.count);
  d.cumdiff_low.resize(d.count);
  d.cumdiff_high.resize(d.count);
  d.first_prev_id = d.start_height ? db->get_block_hash_from_height(d.start_height - 1) : crypto::null_hash;

  size_t verify_failures = 0;
  for (size_t i = 0; i < d.count; ++i)
  {
    const uint64_t h = d.start_height + i;
    const blobdata bd = db->get_block_blob_from_height(h);
    block blk;
    if (!parse_and_validate_block_from_blob(bd, blk))
    {
      std::cout << "failed to parse block at height " << h << std::endl;
      return 1;
    }
    const blobdata hashing_blob = get_block_hashing_blob(blk);

    // cross-check our id computation and raw header parser against the real chain
    const crypto::hash db_id = db->get_block_hash_from_height(h);
    const crypto::hash our_id = hc::hashing_blob_id(reinterpret_cast<const uint8_t*>(hashing_blob.data()), hashing_blob.size());
    hc::parsed_header ph;
    size_t consumed = 0;
    std::string reserialized;
    if (our_id != db_id ||
        !hc::parse_raw_header(reinterpret_cast<const uint8_t*>(hashing_blob.data()), hashing_blob.size(), ph, consumed) ||
        consumed != hashing_blob.size() ||
        (hc::serialize_raw_header(ph, reserialized), reserialized != hashing_blob) ||
        ph.prev_id != (i ? d.ids[i - 1] : d.first_prev_id))
    {
      ++verify_failures;
      if (verify_failures < 10)
        std::cout << "VERIFY FAILURE at height " << h << std::endl;
      continue; // do not run to_record on a header we could not parse/verify (ph may be
                // left unset by the short-circuit); a nonzero verify_failures aborts below
    }
    hc::to_record(ph, d.records.data() + i * REC);
    d.ids[i] = our_id;
    const difficulty_type cd = db->get_block_cumulative_difficulty(h);
    d.cumdiff_low[i] = (cd & std::numeric_limits<uint64_t>::max()).convert_to<uint64_t>();
    d.cumdiff_high[i] = (cd >> 64).convert_to<uint64_t>();

    if ((i + 1) % 100000 == 0)
      std::cout << "loaded " << (i + 1) << "/" << d.count << " headers" << std::endl;
  }
  std::cout << "load complete, verification failures: " << verify_failures << " (id, parser, serializer and chain linkage checked on every header)" << std::endl;
  if (verify_failures)
    return 1;

  const std::string dump_nonces = command_line::get_arg(vm, arg_dump_nonces);
  if (!dump_nonces.empty())
  {
    std::ofstream nf(dump_nonces.c_str(), std::ios::binary | std::ios::trunc);
    if (!nf)
    {
      std::cout << "cannot write " << dump_nonces << std::endl;
      return 1;
    }
    for (size_t i = 0; i < d.count; ++i)
    {
      const uint32_t n = record_nonce(d.records, i);
      const char b[4] = {char(n & 0xff), char((n >> 8) & 0xff), char((n >> 16) & 0xff), char((n >> 24) & 0xff)};
      nf.write(b, 4);
    }
    nf.close();
    std::cout << "wrote " << d.count << " nonces (" << d.count * 4 << " bytes, u32 LE, heights ["
              << d.start_height << ", " << (db_height - 1) << "]) to " << dump_nonces << std::endl;
    core_storage->deinit();
    return 0;
  }

  // ---- per-stage encoding pipeline dumps ---------------------------------------------
  const std::string dump_stages = command_line::get_arg(vm, arg_dump_stages);
  if (!dump_stages.empty())
  {
    const hc::codec_params& params = hc::v1_params();
    const size_t M = d.count - 1; // sample header 0 seeds the deltas and is not dumped
    const uint8_t* seed = d.records.data();
    const uint8_t* window = d.records.data() + REC;

    const boost::filesystem::path dir(dump_stages);
    boost::filesystem::create_directories(dir);
    const auto write_file = [&dir](const char* name, const void* data, size_t size) -> bool
    {
      const std::string path = (dir / name).string();
      std::ofstream f(path.c_str(), std::ios::binary | std::ios::trunc);
      f.write(reinterpret_cast<const char*>(data), size);
      f.close();
      if (!f)
      {
        std::cout << "cannot write " << path << std::endl;
        return false;
      }
      std::cout << "  " << path << ": " << size << " bytes" << std::endl;
      return true;
    };

    std::cout << "dumping " << M << " headers, heights [" << (d.start_height + 1) << ", " << (db_height - 1)
              << "], deltas seeded by the header at height " << d.start_height << std::endl;

    std::string raw;
    for (size_t i = 1; i < d.count; ++i)
      raw += sample_blob(d, i);

    std::vector<uint8_t> deltas(M * REC), stream(M * REC);
    hc::delta_encode(seed, window, M, deltas.data(), params.variant);
    if (!write_file("stage1_raw_headers.bin", raw.data(), raw.size()) ||
        !write_file("stage2_records.bin", window, M * REC) ||
        !write_file("stage3_records_delta.bin", deltas.data(), deltas.size()))
      return 1;
    hc::permute_nonce_bits(deltas.data(), M, params.nonce_bit_order); // in place: only nonce bytes change
    if (!write_file("stage4_records_delta_noncebits.bin", deltas.data(), deltas.size()))
      return 1;
    hc::transpose(deltas.data(), M, params.order, stream.data());
    if (!write_file("stage5_records_transposed.bin", stream.data(), stream.size()))
      return 1;

    const std::string encoded = hc::compress_records(seed, window, M, params);
    std::vector<uint8_t> roundtrip;
    if (encoded.empty() ||
        !hc::decompress_records(reinterpret_cast<const uint8_t*>(encoded.data()), encoded.size(), M, seed, params, roundtrip) ||
        roundtrip.size() != M * REC || memcmp(roundtrip.data(), window, M * REC) != 0)
    {
      std::cout << "ERROR: encoded stage failed to round-trip" << std::endl;
      return 1;
    }
    if (!write_file("stage6_records_encoded.bin", encoded.data(), encoded.size()))
      return 1;

    // region breakdown of the encoded stream, for reference
    uint64_t vals[2] = {0, 0};
    size_t pos = 0;
    for (int field = 0; field < 2; ++field)
    {
      unsigned shift = 0;
      uint8_t b;
      do { b = uint8_t(encoded[pos++]); vals[field] |= uint64_t(b & 0x7f) << shift; shift += 7; } while (b & 0x80);
    }
    const uint64_t zero_run = vals[0], csize = vals[1];
    const size_t raw_tail = encoded.size() - pos - csize;
    const size_t split = M * REC - raw_tail;
    std::cout << "encoded breakdown: " << pos << " B varints | zero run " << zero_run
              << " B elided | rANS cblob " << csize << " B coding stream bytes [" << zero_run << ", " << split
              << ") | raw tail " << raw_tail << " B; " << std::fixed << std::setprecision(3)
              << double(encoded.size()) / M << " bytes/header" << std::endl;
    core_storage->deinit();
    return 0;
  }

  // ---- split candidate sweep with the baked v1 parameters ----------------------------
  if (command_line::get_arg(vm, arg_split_sweep))
  {
    std::vector<size_t> all_chunk_bases;
    for (size_t b = 0; b + chunk_size <= d.count; b += chunk_size)
      all_chunk_bases.push_back(b);
    std::cout << "\nsplit sweep: " << all_chunk_bases.size() << " chunks of " << chunk_size
              << " headers, baked split ratio " << std::fixed << std::setprecision(6) << hc::v1_params().split_ratio << std::endl;
    const sweep_result sw = split_sweep(d, chunk_size, hc::v1_params(), all_chunk_bases);
    std::cout << "win counts per k (percentage points; only nonzero shown):" << std::endl;
    for (int i = 0; i < SWEEP_POINTS; ++i)
      if (sw.wins[i])
      {
        char buf[64];
        snprintf(buf, sizeof(buf), "  k = %+5.1f   wins %6llu", sweep_k(i), (unsigned long long)sw.wins[i]);
        std::cout << buf << std::endl;
      }
    std::cout << "chunks with tied winners: " << sw.ties << ", all-raw fallback wins: " << sw.fallback_wins << std::endl;

    const std::array<double, hc::SPLIT_CANDIDATES> by_wins = pick_split_offsets(sw);
    std::cout << "top " << hc::SPLIT_CANDIDATES << " by win count (percentage points):";
    for (double off : by_wins)
      std::cout << " " << std::setprecision(1) << std::fixed << off * 100.0;
    std::cout << std::endl;
    double greedy_mean = 0.0;
    const std::array<double, hc::SPLIT_CANDIDATES> greedy = greedy_split_offsets(sw, &greedy_mean);
    std::cout << "greedy coverage set (percentage points):  ";
    for (double off : greedy)
      std::cout << " " << std::setprecision(1) << std::fixed << off * 100.0;
    std::cout << std::endl;

    const double mean_classic = mean_cost_with_offsets(d, chunk_size, hc::v1_params(), all_chunk_bases, hc::v1_params().split_offsets, hc::SPLIT_CANDIDATES);
    const double mean_by_wins = mean_cost_with_offsets(d, chunk_size, hc::v1_params(), all_chunk_bases, by_wins.data(), by_wins.size());
    std::cout << std::setprecision(2)
              << "mean codec-section bytes/chunk: current candidate set " << mean_classic
              << ", top-by-wins set " << mean_by_wins
              << ", greedy coverage set " << greedy_mean
              << ", full-grid optimum " << sw.mean_best << std::endl;
    if (emit_tables.empty())
    {
      core_storage->deinit();
      return 0;
    }
  }

  const size_t train_end = d.count / 2;

  // ---- per-position statistics ------------------------------------------------------
  const hc::delta_variant variants[3] = {hc::delta_variant::xor_all, hc::delta_variant::zigzag_ts, hc::delta_variant::zigzag_ts_txcount};
  const char* variant_names[3] = {"xor_all", "zigzag_ts", "zigzag_ts_txcount"};

  // ---- per-bit nonce analysis --------------------------------------------------------
  const std::array<double, 32> bit_probs_full = nonce_bit_flip_probs(d.records, 1, d.count);
  // default bit order for the bit-sorted benchmarks: the one baked into the codec, so
  // a plain --emit-tables run is self-consistent; --bit-order overrides (the
  // marginal-entropy heuristic make_bit_order() lost to the searched grouping and is
  // kept only for the statistics printout)
  std::array<uint8_t, 32> bit_order_full, bit_order_train;
  memcpy(bit_order_full.data(), hc::v1_params().nonce_bit_order, 32);
  bit_order_train = bit_order_full;
  const std::array<uint8_t, 32> bit_identity = identity_bit_order();

  const std::string bit_order_arg = command_line::get_arg(vm, arg_bit_order);
  if (!bit_order_arg.empty())
  {
    std::array<uint8_t, 32> custom;
    bool seen[32] = {};
    const char* s = bit_order_arg.c_str();
    size_t n = 0;
    for (; n < 32; ++n)
    {
      char* endp = NULL;
      const unsigned long v = strtoul(s, &endp, 10);
      if (endp == s || v >= 32 || seen[v])
        break;
      custom[n] = static_cast<uint8_t>(v);
      seen[v] = true;
      s = endp;
      if (*s == ',')
        ++s;
    }
    if (n != 32 || *s != '\0')
    {
      std::cout << "--bit-order must be a comma-separated permutation of 0..31" << std::endl;
      return 1;
    }
    bit_order_full = bit_order_train = custom;
    std::cout << "using custom nonce bit order from --bit-order for the bit-sorted benchmarks" << std::endl;
  }

  std::cout << "\nnonce bit-flip statistics over the full sample (XOR of consecutive nonces, bit 0 = LSB):" << std::endl;
  std::cout << "bit   P(flip)    entropy     bit   P(flip)    entropy     bit   P(flip)    entropy     bit   P(flip)    entropy" << std::endl;
  for (unsigned row = 0; row < 8; ++row)
  {
    for (unsigned col = 0; col < 4; ++col)
    {
      const unsigned b = col * 8 + row;
      char buf[48];
      snprintf(buf, sizeof(buf), "%2u    %8.6f  %8.6f", b, bit_probs_full[b], binary_entropy(bit_probs_full[b]));
      std::cout << buf << (col < 3 ? "     " : "");
    }
    std::cout << std::endl;
  }
  double bit_sum = 0.0;
  for (unsigned b = 0; b < 32; ++b)
    bit_sum += binary_entropy(bit_probs_full[b]);
  std::cout << "sum of nonce bit entropies: " << std::fixed << std::setprecision(4) << bit_sum << " bits" << std::endl;
  std::cout << "bit order (highest -> lowest entropy):";
  for (unsigned b = 0; b < 32; ++b)
    std::cout << " " << int(bit_order_full[b]);
  std::cout << std::endl;

  // [variant][bitmode]: bitmode 0 = identity, 1 = entropy-sorted nonce bits
  pos_stats full_stats[3][2], train_stats[3][2];
  for (int v = 0; v < 3; ++v)
  {
    accumulate_hists(d.records, 1, d.count, variants[v], NULL, full_stats[v][0]);
    accumulate_hists(d.records, 1, d.count, variants[v], bit_order_full.data(), full_stats[v][1]);
    accumulate_hists(d.records, 1, train_end, variants[v], NULL, train_stats[v][0]);
    accumulate_hists(d.records, 1, train_end, variants[v], bit_order_train.data(), train_stats[v][1]);
  }

  std::cout << "nonce byte entropies before bit reordering:";
  double nonce_sum0 = 0.0, nonce_sum1 = 0.0;
  for (size_t b = 0; b < 4; ++b)
  {
    const double e = full_stats[0][0].entropy(hc::REC_OFF_NONCE + b);
    nonce_sum0 += e;
    std::cout << " " << std::setprecision(4) << e;
  }
  std::cout << "  (sum " << nonce_sum0 << ")" << std::endl;
  std::cout << "nonce byte entropies after bit reordering: ";
  for (size_t b = 0; b < 4; ++b)
  {
    const double e = full_stats[0][1].entropy(hc::REC_OFF_NONCE + b);
    nonce_sum1 += e;
    std::cout << " " << std::setprecision(4) << e;
  }
  std::cout << "  (sum " << nonce_sum1 << ", " << std::setprecision(4) << (nonce_sum0 - nonce_sum1) << " bits/header saved)" << std::endl;

  std::cout << "\nper-position delta statistics over the full sample (entropy bits | P(nonzero)):" << std::endl;
  std::cout << std::left << std::setw(12) << "position";
  for (int v = 0; v < 3; ++v)
    std::cout << std::setw(26) << variant_names[v];
  std::cout << std::endl;
  for (size_t pos = 0; pos < REC; ++pos)
  {
    std::cout << std::left << std::setw(12) << position_name(pos);
    for (int v = 0; v < 3; ++v)
    {
      char buf[32];
      snprintf(buf, sizeof(buf), "%7.4f | %8.6f", full_stats[v][0].entropy(pos), full_stats[v][0].p_nonzero(pos));
      std::cout << std::setw(26) << buf;
    }
    std::cout << std::endl;
  }
  for (int v = 0; v < 3; ++v)
  {
    for (int bm = 0; bm < 2; ++bm)
    {
      double total = 0.0;
      for (size_t pos = 0; pos < REC; ++pos)
        total += full_stats[v][bm].entropy(pos);
      std::cout << "ideal bits/header (" << variant_names[v] << (bm ? ", bit-sorted nonce" : "") << "): "
                << std::fixed << std::setprecision(2) << total
                << "  -> ideal bytes/" << chunk_size << "-chunk payload: " << (total / 8.0) * (chunk_size - 1) << std::endl;
    }
  }

  // ---- calibration + benchmarks ------------------------------------------------------
  std::vector<size_t> train_bases, eval_bases;
  for (size_t b = 0; b + chunk_size <= train_end; b += chunk_size)
    train_bases.push_back(b);
  for (size_t b = train_end; b + chunk_size <= d.count; b += chunk_size)
    eval_bases.push_back(b);
  const size_t M = chunk_size - 1;
  std::cout << "\ntrain half: " << train_end << " headers (" << train_bases.size() << " chunks), eval half: "
            << (d.count - train_end) << " headers (" << eval_bases.size() << " chunks)" << std::endl;

  std::vector<bench_result> results;
  std::map<std::string, std::pair<hc::codec_params, double>> rans_combo_params; // name -> (params, mean)

  for (int v = 0; v < 3; ++v)
  {
    for (int bm = 0; bm < 2; ++bm)
    {
    const std::array<uint8_t, 32>& bit_order = bm ? bit_order_train : bit_identity;
    for (int ord = 0; ord < 2; ++ord)
    {
      const bool by_entropy = ord == 0;
      const std::array<uint8_t, REC> order = make_order(train_stats[v][bm], by_entropy);
      hc::codec_params params = make_params(variants[v], order, train_stats[v][bm], 0.5, bit_order);

      // calibrate the split ratio on the train half (exact under the rANS cost model)
      std::vector<double> ratios;
      std::vector<uint8_t> deltas(M * REC), stream(M * REC);
      for (size_t b : train_bases)
      {
        hc::delta_encode(d.records.data() + b * REC, d.records.data() + (b + 1) * REC, M, deltas.data(), variants[v]);
        hc::permute_nonce_bits(deltas.data(), M, params.nonce_bit_order);
        hc::transpose(deltas.data(), M, params.order, stream.data());
        size_t zero_run = 0;
        while (zero_run < stream.size() && stream[zero_run] == 0) ++zero_run;
        ratios.push_back(double(optimal_split_estimate(stream, zero_run, M, params)) / stream.size());
      }
      std::sort(ratios.begin(), ratios.end());
      params.split_ratio = ratios.empty() ? 0.5 : ratios[ratios.size() / 2];

      // rANS benchmark on the eval half, full production path + round-trip check
      std::vector<size_t> sizes;
      size_t window_excess = 0;
      for (size_t b : eval_bases)
      {
        const uint8_t* seed = d.records.data() + b * REC;
        const uint8_t* recs = d.records.data() + (b + 1) * REC;
        const std::string coded = hc::compress_records(seed, recs, M, params);
        std::vector<uint8_t> back;
        if (coded.empty() ||
            !hc::decompress_records(reinterpret_cast<const uint8_t*>(coded.data()), coded.size(), M, seed, params, back) ||
            memcmp(back.data(), recs, M * REC) != 0)
        {
          std::cout << "FATAL: rANS round trip failed on real data, base " << b << std::endl;
          return 1;
        }
        sizes.push_back(container_overhead(d, b, chunk_size) + coded.size());

        hc::delta_encode(seed, recs, M, deltas.data(), variants[v]);
        hc::permute_nonce_bits(deltas.data(), M, params.nonce_bit_order);
        hc::transpose(deltas.data(), M, params.order, stream.data());
        size_t zero_run = 0;
        while (zero_run < stream.size() && stream[zero_run] == 0) ++zero_run;
        const size_t opt = optimal_split_estimate(stream, zero_run, M, params);
        hc::codec_params exact = params;
        exact.split_ratio = double(opt) / stream.size();
        const std::string at_opt = hc::compress_records(seed, recs, M, exact);
        if (coded.size() > at_opt.size())
          window_excess += coded.size() - at_opt.size();
      }
      const std::string name = std::string("rans/") + variant_names[v] + (by_entropy ? "/entropy" : "/p_nonzero") + (bm ? "/bitsorted" : "");
      summarize(name, sizes, chunk_size, results);
      std::cout << "    split ratio " << std::setprecision(4) << params.split_ratio
                << ", window excess vs optimal split: " << std::setprecision(2)
                << double(window_excess) / std::max<size_t>(eval_bases.size(), 1) << " bytes/chunk" << std::endl;
      double mean = 0;
      for (size_t s : sizes) mean += s;
      mean /= std::max<size_t>(sizes.size(), 1);
      rans_combo_params.emplace(name, std::make_pair(params, mean));

      // deflate benchmark with the same delta+transpose stages
      std::vector<double> dratios;
      size_t ncal = std::min<size_t>(deflate_chunks, train_bases.size());
      for (size_t c = 0; c < ncal; ++c)
      {
        const size_t b = train_bases[c];
        hc::delta_encode(d.records.data() + b * REC, d.records.data() + (b + 1) * REC, M, deltas.data(), variants[v]);
        hc::permute_nonce_bits(deltas.data(), M, params.nonce_bit_order);
        hc::transpose(deltas.data(), M, params.order, stream.data());
        size_t zero_run = 0;
        while (zero_run < stream.size() && stream[zero_run] == 0) ++zero_run;
        // plane-boundary grid is enough to calibrate the ratio
        size_t best_cost = SIZE_MAX, best_split = zero_run;
        for (size_t plane = 0; plane <= REC; ++plane)
        {
          const size_t split = std::max(zero_run, plane * M);
          std::string z;
          if (split > zero_run && !deflate_raw9(stream.data() + zero_run, split - zero_run, z))
            continue;
          const size_t cost = z.size() + (stream.size() - split);
          if (cost < best_cost)
          {
            best_cost = cost;
            best_split = split;
          }
          if (split == stream.size())
            break;
        }
        dratios.push_back(double(best_split) / stream.size());
      }
      std::sort(dratios.begin(), dratios.end());
      const double dratio = dratios.empty() ? 0.5 : dratios[dratios.size() / 2];

      std::vector<size_t> dsizes;
      for (size_t b : eval_bases)
      {
        hc::delta_encode(d.records.data() + b * REC, d.records.data() + (b + 1) * REC, M, deltas.data(), variants[v]);
        hc::permute_nonce_bits(deltas.data(), M, params.nonce_bit_order);
        hc::transpose(deltas.data(), M, params.order, stream.data());
        size_t zero_run = 0;
        while (zero_run < stream.size() && stream[zero_run] == 0) ++zero_run;
        size_t best_cost = SIZE_MAX;
        for (int k = -4; k <= 3; ++k) // -4 stands in for the all-raw fallback
        {
          size_t split;
          if (k == -4)
            split = zero_run;
          else
          {
            long long c = std::llround((dratio + 0.01 * k) * double(stream.size()));
            c = std::max<long long>(c, zero_run);
            c = std::min<long long>(c, stream.size());
            split = c;
          }
          std::string z;
          if (split > zero_run && !deflate_raw9(stream.data() + zero_run, split - zero_run, z))
            continue;
          const size_t cost = uvarint_size(zero_run) + uvarint_size(z.size()) + z.size() + (stream.size() - split);
          best_cost = std::min(best_cost, cost);
        }
        dsizes.push_back(container_overhead(d, b, chunk_size) + best_cost);
      }
      summarize(std::string("deflate/") + variant_names[v] + (by_entropy ? "/entropy" : "/p_nonzero") + (bm ? "/bitsorted" : ""), dsizes, chunk_size, results);
      std::cout << "    split ratio " << std::setprecision(4) << dratio << std::endl;
    }
    }
  }

  // ---- pick the winner and emit tables -----------------------------------------------
  const bench_result* best = NULL;
  for (const auto& r2 : results)
    if (!best || r2.mean < best->mean)
      best = &r2;
  if (best)
    std::cout << "\nwinner: " << best->name << " (mean " << std::setprecision(1) << best->mean << " bytes/chunk)" << std::endl;

  if (!emit_tables.empty())
  {
    // bake the best rANS combo (the wire format uses the built-in coder; if deflate ever
    // wins this needs revisiting) with tables regenerated from the full sample
    const std::pair<const std::string, std::pair<hc::codec_params, double>>* best_rans = NULL;
    for (const auto& kv : rans_combo_params)
      if (!best_rans || kv.second.second < best_rans->second.second)
        best_rans = &kv;
    if (!best_rans)
    {
      std::cout << "no rANS combo to bake" << std::endl;
      return 1;
    }
    const std::string& name = best_rans->first;
    const bool by_entropy = name.find("/entropy") != std::string::npos;
    const bool bitsorted = name.find("/bitsorted") != std::string::npos;
    int v = 0;
    for (int i = 0; i < 3; ++i)
      if (name.find(variant_names[i]) != std::string::npos)
        v = i;

    const std::array<uint8_t, 32>& baked_bits = bitsorted ? bit_order_full : bit_identity;
    const std::array<uint8_t, REC> order = make_order(full_stats[v][bitsorted], by_entropy);
    hc::codec_params baked = make_params(variants[v], order, full_stats[v][bitsorted], 0.5, baked_bits);
    std::vector<double> ratios;
    std::vector<uint8_t> deltas(M * REC), stream(M * REC);
    std::vector<size_t> all_bases = train_bases;
    all_bases.insert(all_bases.end(), eval_bases.begin(), eval_bases.end());
    for (size_t b : all_bases)
    {
      hc::delta_encode(d.records.data() + b * REC, d.records.data() + (b + 1) * REC, M, deltas.data(), variants[v]);
      hc::permute_nonce_bits(deltas.data(), M, baked.nonce_bit_order);
      hc::transpose(deltas.data(), M, baked.order, stream.data());
      size_t zero_run = 0;
      while (zero_run < stream.size() && stream[zero_run] == 0) ++zero_run;
      ratios.push_back(double(optimal_split_estimate(stream, zero_run, M, baked)) / stream.size());
    }
    std::sort(ratios.begin(), ratios.end());
    baked.split_ratio = ratios.empty() ? 0.5 : ratios[ratios.size() / 2];

    // calibrate the candidate offsets: sweep the +-5 point grid with the freshly
    // baked parameters and keep the greedy coverage set
    {
      const sweep_result sw = split_sweep(d, chunk_size, baked, all_bases);
      const std::array<double, hc::SPLIT_CANDIDATES> chosen = greedy_split_offsets(sw, NULL);
      for (size_t k = 0; k < hc::SPLIT_CANDIDATES; ++k)
        baked.split_offsets[k] = chosen[k];
    }

    std::ofstream f(emit_tables.c_str());
    if (!f)
    {
      std::cout << "cannot write " << emit_tables << std::endl;
      return 1;
    }
    f << "// Copyright (c) 2014-2022, The Monero Project\n//\n";
    f << "// All rights reserved.\n//\n";
    f << "// Redistribution and use in source and binary forms, with or without modification, are\n";
    f << "// permitted provided that the following conditions are met:\n//\n";
    f << "// 1. Redistributions of source code must retain the above copyright notice, this list of\n";
    f << "//    conditions and the following disclaimer.\n//\n";
    f << "// 2. Redistributions in binary form must reproduce the above copyright notice, this list\n";
    f << "//    of conditions and the following disclaimer in the documentation and/or other\n";
    f << "//    materials provided with the distribution.\n//\n";
    f << "// 3. Neither the name of the copyright holder nor the names of its contributors may be\n";
    f << "//    used to endorse or promote products derived from this software without specific\n";
    f << "//    prior written permission.\n//\n";
    f << "// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\" AND ANY\n";
    f << "// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF\n";
    f << "// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL\n";
    f << "// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n";
    f << "// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,\n";
    f << "// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS\n";
    f << "// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,\n";
    f << "// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF\n";
    f << "// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n\n";
    f << "// GENERATED FILE, DO NOT EDIT - produced by monero-blockchain-header-stats\n";
    f << "// combo: " << name << "\n";
    f << "// sample: " << d.count << " mainnet headers, heights [" << d.start_height << ", " << (db_height - 1) << "]\n";
    f << "// tip id: " << epee::string_tools::pod_to_hex(db->get_block_hash_from_height(db_height - 1)) << "\n";
    f << "// chunk size used for split calibration: " << chunk_size << "\n";
    f << "// This file is included only by header_codec.cpp.\n\n";
    f << "#pragma once\n\n#include <cstdint>\n\n";
    f << "namespace tools { namespace header_codec { namespace detail {\n\n";
    f << "static const uint8_t V1_VARIANT = " << int(baked.variant) << ";\n";
    f << "static const double V1_SPLIT_RATIO = " << std::setprecision(6) << std::fixed << baked.split_ratio << ";\n\n";
    f << "static const double V1_SPLIT_OFFSETS[" << hc::SPLIT_CANDIDATES << "] = {\n ";
    for (size_t k = 0; k < hc::SPLIT_CANDIDATES; ++k)
      f << " " << std::setprecision(6) << std::fixed << baked.split_offsets[k] << (k + 1 < hc::SPLIT_CANDIDATES ? "," : "");
    f << "\n};\n\n";
    f << "static const uint8_t V1_NONCE_BIT_ORDER[32] = {\n ";
    for (size_t i = 0; i < 32; ++i)
      f << " " << int(baked.nonce_bit_order[i]) << (i + 1 < 32 ? "," : "");
    f << "\n};\n\n";
    f << "static const uint8_t V1_ORDER[54] = {\n ";
    for (size_t i = 0; i < REC; ++i)
      f << " " << int(baked.order[i]) << (i + 1 < REC ? "," : "");
    f << "\n};\n\n";
    f << "static const uint16_t V1_FREQ[54][256] = {\n";
    for (size_t pos = 0; pos < REC; ++pos)
    {
      f << "  {";
      for (size_t s = 0; s < 256; ++s)
        f << baked.freq[pos][s] << (s + 1 < 256 ? "," : "");
      f << "},\n";
    }
    f << "};\n\n}}}\n";
    f.close();
    std::cout << "tables written to " << emit_tables << " (" << name << ", split ratio "
              << std::setprecision(4) << baked.split_ratio << ")" << std::endl;
  }

  // ---- evaluate the baked v1 parameters through the production chunk API -------------
  if (eval_baked)
  {
    std::cout << "\nbaked v1 parameters, full chunk container API on the eval half:" << std::endl;
    std::vector<size_t> sizes;
    for (size_t b : eval_bases)
    {
      std::vector<std::string> blobs;
      blobs.reserve(chunk_size);
      for (size_t i = 0; i < chunk_size; ++i)
        blobs.push_back(sample_blob(d, b + i));
      hc::chunk_info info;
      info.height = d.start_height + b;
      info.cumulative_difficulty_low = d.cumdiff_low[b];
      info.cumulative_difficulty_high = d.cumdiff_high[b];
      std::string chunk;
      if (!hc::compress_chunk(blobs, info, chunk))
      {
        std::cout << "FATAL: compress_chunk failed at base " << b << std::endl;
        return 1;
      }
      std::vector<std::string> back;
      std::vector<crypto::hash> ids;
      hc::chunk_info info2;
      if (!hc::decompress_chunk(chunk, info2, back, &ids) || back != blobs ||
          info2.height != info.height ||
          info2.cumulative_difficulty_low != info.cumulative_difficulty_low ||
          info2.cumulative_difficulty_high != info.cumulative_difficulty_high)
      {
        std::cout << "FATAL: chunk round trip failed at base " << b << std::endl;
        return 1;
      }
      for (size_t i = 0; i < chunk_size; ++i)
      {
        if (ids[i] != d.ids[b + i])
        {
          std::cout << "FATAL: id mismatch at base " << b << " + " << i << std::endl;
          return 1;
        }
      }
      sizes.push_back(chunk.size());
    }
    std::vector<bench_result> final_results;
    summarize("baked v1 (compress_chunk)", sizes, chunk_size, final_results);
    std::cout << "round trips verified: blobs byte-exact, all block ids match the database" << std::endl;
  }

  core_storage->deinit();
  return 0;

  CATCH_ENTRY("main", 1);
}

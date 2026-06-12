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

// Searches for the nonce bit-to-byte grouping that minimizes the sum of measured
// joint byte entropies of nonce XOR deltas, for the header codec's NONCE_BIT_ORDER
// table (see src/common/header_codec.h and docs/HEADER_CODEC.md).
//
// Input: a binary file of u32 little-endian nonce values in height order, as written
// by `monero-blockchain-header-stats --dump-nonces`. The tool XORs consecutive values,
// packs each of the 32 delta bit columns into its own bitvector, and runs
// multi-threaded simulated annealing with basin hopping over assignments of the 32
// bits into 4 groups of 8. Only the grouping matters for the objective (joint entropy
// is invariant under bit order within a byte and under byte order); the final result
// is canonicalized with the highest-entropy byte first and bits within a byte sorted
// by descending marginal entropy, matching the codec's convention (destination bit 0
// gets the highest-entropy content).
//
// The search keeps every thread busy until the deadline: threads restart from random
// assignments or perturbations of the global best and keep annealing, so the wall
// time is spent in full regardless of when the optimum is first found.
//
// No monero dependencies; plain C++14 and std::thread.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace
{

using clock_type = std::chrono::steady_clock;

struct bit_columns
{
  size_t deltas = 0;                       // number of XOR deltas
  size_t words = 0;                        // 64-bit words per column
  std::vector<uint64_t> col[32];           // col[b] holds bit b of every delta
};

bool load_columns(const std::string& path, bit_columns& bc)
{
  std::ifstream f(path.c_str(), std::ios::binary | std::ios::ate);
  if (!f)
    return false;
  const std::streamoff size = f.tellg();
  const size_t count = static_cast<size_t>(size) / 4;
  if (size < 0 || (size % 4) != 0 || count < 2)
    return false;
  f.seekg(0);
  std::vector<uint32_t> nonces(count);
  std::vector<unsigned char> raw(static_cast<size_t>(size));
  if (!f.read(reinterpret_cast<char*>(raw.data()), size))
    return false;
  for (size_t i = 0; i < count; ++i)
    nonces[i] = (uint32_t)raw[i * 4] | ((uint32_t)raw[i * 4 + 1] << 8) | ((uint32_t)raw[i * 4 + 2] << 16) | ((uint32_t)raw[i * 4 + 3] << 24);

  bc.deltas = count - 1;
  bc.words = (bc.deltas + 63) / 64;
  for (unsigned b = 0; b < 32; ++b)
    bc.col[b].assign(bc.words, 0);
  for (size_t i = 0; i < bc.deltas; ++i)
  {
    const uint32_t d = nonces[i] ^ nonces[i + 1];
    const size_t w = i >> 6;
    const uint64_t bit = uint64_t(1) << (i & 63);
    for (unsigned b = 0; b < 32; ++b)
      if ((d >> b) & 1)
        bc.col[b][w] |= bit;
  }
  return true;
}

// joint entropy (bits) of the byte formed by the 8 source bit columns in `src`
double byte_entropy(const bit_columns& bc, const uint8_t src[8])
{
  uint32_t hist[256];
  memset(hist, 0, sizeof(hist));
  const uint64_t* c[8];
  for (int k = 0; k < 8; ++k)
    c[k] = bc.col[src[k]].data();
  for (size_t w = 0; w < bc.words; ++w)
  {
    const uint64_t v0 = c[0][w], v1 = c[1][w], v2 = c[2][w], v3 = c[3][w];
    const uint64_t v4 = c[4][w], v5 = c[5][w], v6 = c[6][w], v7 = c[7][w];
    const unsigned lim = (w + 1 == bc.words && (bc.deltas & 63)) ? unsigned(bc.deltas & 63) : 64;
    for (unsigned j = 0; j < lim; ++j)
    {
      const unsigned byte = unsigned((v0 >> j) & 1) | (unsigned((v1 >> j) & 1) << 1) |
                            (unsigned((v2 >> j) & 1) << 2) | (unsigned((v3 >> j) & 1) << 3) |
                            (unsigned((v4 >> j) & 1) << 4) | (unsigned((v5 >> j) & 1) << 5) |
                            (unsigned((v6 >> j) & 1) << 6) | (unsigned((v7 >> j) & 1) << 7);
      ++hist[byte];
    }
  }
  double h = 0.0;
  const double n = double(bc.deltas);
  for (unsigned s = 0; s < 256; ++s)
  {
    if (!hist[s])
      continue;
    const double p = double(hist[s]) / n;
    h -= p * std::log2(p);
  }
  return h;
}

double marginal_entropy(const bit_columns& bc, unsigned b)
{
  uint64_t ones = 0;
  for (size_t w = 0; w < bc.words; ++w)
    ones += uint64_t(__builtin_popcountll(bc.col[b][w]));
  const double p = double(ones) / double(bc.deltas);
  if (p <= 0.0 || p >= 1.0)
    return 0.0;
  return -p * std::log2(p) - (1.0 - p) * std::log2(1.0 - p);
}

// an assignment is order[32]: group g owns source bits order[8g .. 8g+8)
struct state
{
  std::array<uint8_t, 32> order;
  std::array<double, 4> e;
  double total = 0.0; // objective: sum of e[g] for counted groups only
};

// the first free_bytes groups land in the raw region of the stream and cost a flat
// 8 bits/byte on the wire, so their measured entropy is excluded from the objective
void evaluate(const bit_columns& bc, state& st, unsigned free_bytes)
{
  st.total = 0.0;
  for (unsigned g = 0; g < 4; ++g)
  {
    if (g < free_bytes)
    {
      st.e[g] = 0.0; // not part of the objective; filled in for reporting later
      continue;
    }
    st.e[g] = byte_entropy(bc, st.order.data() + g * 8);
    st.total += st.e[g];
  }
}

struct shared_best
{
  std::mutex lock;
  state best;
  std::atomic<bool> have{false}; // atomic: read without the lock when picking a restart mode

  bool offer(const state& st)
  {
    std::lock_guard<std::mutex> g(lock);
    if (!have || st.total < best.total - 1e-12)
    {
      best = st;
      have = true;
      return true;
    }
    return false;
  }

  state get()
  {
    std::lock_guard<std::mutex> g(lock);
    return best;
  }
};

void search_thread(const bit_columns& bc, shared_best& global, std::atomic<uint64_t>& evals, clock_type::time_point deadline, uint64_t seed, unsigned free_bytes, const std::vector<state>* starts)
{
  std::mt19937_64 rng(seed);
  std::uniform_real_distribution<double> uni(0.0, 1.0);

  while (clock_type::now() < deadline)
  {
    // restarts: explicit starting points, perturbations of the global best, and
    // random assignments, mixed
    state cur;
    const unsigned pick = unsigned(rng() % 4);
    if (starts && !starts->empty() && pick == 0)
    {
      cur = (*starts)[rng() % starts->size()];
    }
    else if (global.have && pick <= 2)
    {
      cur = global.get();
      const int kicks = 2 + int(rng() % 6);
      for (int k = 0; k < kicks; ++k)
        std::swap(cur.order[rng() % 32], cur.order[rng() % 32]);
    }
    else
    {
      for (unsigned b = 0; b < 32; ++b)
        cur.order[b] = uint8_t(b);
      std::shuffle(cur.order.begin(), cur.order.end(), rng);
    }
    evaluate(bc, cur, free_bytes);
    evals += 4 - free_bytes;
    global.offer(cur);

    // simulated annealing on cross-group bit swaps (within-group swaps are no-ops)
    double temperature = 0.02;
    unsigned since_improve = 0;
    while (clock_type::now() < deadline && since_improve < 3000 && temperature > 1e-7)
    {
      const unsigned a = unsigned(rng() % 32);
      unsigned b = unsigned(rng() % 32);
      while (b / 8 == a / 8)
        b = unsigned(rng() % 32);
      const unsigned ga = a / 8, gb = b / 8;

      state cand = cur;
      std::swap(cand.order[a], cand.order[b]);
      cand.total = cur.total;
      if (ga >= free_bytes)
      {
        cand.e[ga] = byte_entropy(bc, cand.order.data() + ga * 8);
        cand.total += cand.e[ga] - cur.e[ga];
        evals += 1;
      }
      if (gb >= free_bytes)
      {
        cand.e[gb] = byte_entropy(bc, cand.order.data() + gb * 8);
        cand.total += cand.e[gb] - cur.e[gb];
        evals += 1;
      }

      const double delta = cand.total - cur.total;
      if (delta < 0.0 || uni(rng) < std::exp(-delta / temperature))
      {
        cur = cand;
        if (delta < -1e-12)
        {
          since_improve = 0;
          if (global.offer(cur))
            continue;
        }
      }
      ++since_improve;
      temperature *= 0.999;
    }
  }
}

void canonicalize(const bit_columns& bc, state& st, unsigned free_bytes)
{
  // highest-entropy byte first (destination byte 0), bits within a byte by
  // descending marginal entropy; free bytes stay in front. None of this changes
  // the objective. Free-byte entropies are filled in here for reporting.
  for (unsigned g = 0; g < free_bytes; ++g)
    st.e[g] = byte_entropy(bc, st.order.data() + g * 8);

  std::array<std::array<uint8_t, 8>, 4> groups;
  std::array<int, 4> idx = {{0, 1, 2, 3}};
  for (int g = 0; g < 4; ++g)
    for (int k = 0; k < 8; ++k)
      groups[g][k] = st.order[g * 8 + k];
  std::stable_sort(idx.begin(), idx.begin() + free_bytes, [&](int a, int b) { return st.e[a] > st.e[b]; });
  std::stable_sort(idx.begin() + free_bytes, idx.end(), [&](int a, int b) { return st.e[a] > st.e[b]; });

  double marg[32];
  for (unsigned b = 0; b < 32; ++b)
    marg[b] = marginal_entropy(bc, b);

  state out;
  for (int g = 0; g < 4; ++g)
  {
    std::array<uint8_t, 8> grp = groups[idx[g]];
    std::stable_sort(grp.begin(), grp.end(), [&](uint8_t a, uint8_t b) {
      if (marg[a] != marg[b]) return marg[a] > marg[b];
      return a < b;
    });
    for (int k = 0; k < 8; ++k)
      out.order[g * 8 + k] = grp[k];
    out.e[g] = st.e[idx[g]];
  }
  out.total = st.total;
  st = out;
}

void print_state(const char* label, const state& st, unsigned free_bytes)
{
  printf("%s: objective %.6f bits (bytes:", label, st.total);
  for (unsigned g = 0; g < 4; ++g)
    printf(g < free_bytes ? " [%.4f]" : " %.4f", st.e[g]);
  printf(")%s\n", free_bytes ? "  [..] = free, transmitted raw" : "");
  printf("  order:");
  for (unsigned b = 0; b < 32; ++b)
    printf(" %u%s", st.order[b], b + 1 < 32 ? "," : "");
  printf("\n");
}

// fill in the display-only entropies of free bytes without touching the objective
void fill_free_entropies(const bit_columns& bc, state& st, unsigned free_bytes)
{
  for (unsigned g = 0; g < free_bytes; ++g)
    st.e[g] = byte_entropy(bc, st.order.data() + g * 8);
}

} // anonymous namespace

static bool parse_order(const char* s, std::array<uint8_t, 32>& order)
{
  bool seen[32] = {};
  for (unsigned n = 0; n < 32; ++n)
  {
    char* endp = NULL;
    const unsigned long v = strtoul(s, &endp, 10);
    if (endp == s || v >= 32 || seen[v])
      return false;
    order[n] = uint8_t(v);
    seen[v] = true;
    s = endp;
    if (*s == ',')
      ++s;
  }
  return *s == '\0';
}

int main(int argc, char* argv[])
{
  std::string input;
  unsigned threads = 20;
  unsigned free_bytes = 0;
  double minutes = 30.0;
  uint64_t seed = 0x5eed0001;
  std::vector<std::array<uint8_t, 32>> start_orders;

  const char* usage = "usage: %s --input nonces.bin [--threads 20] [--minutes 30] [--free-bytes 0] [--start ORDER]... [--seed N]\n"
                      "  --free-bytes N  exclude the first N destination bytes from the objective\n"
                      "                  (they end up in the raw region and cost 8 bits regardless)\n"
                      "  --start ORDER   comma-separated 32-entry permutation used as a starting point\n";

  for (int i = 1; i < argc; ++i)
  {
    const std::string a = argv[i];
    if (a == "--input" && i + 1 < argc) input = argv[++i];
    else if (a == "--threads" && i + 1 < argc) threads = unsigned(strtoul(argv[++i], NULL, 10));
    else if (a == "--minutes" && i + 1 < argc) minutes = strtod(argv[++i], NULL);
    else if (a == "--seed" && i + 1 < argc) seed = strtoull(argv[++i], NULL, 10);
    else if (a == "--free-bytes" && i + 1 < argc) free_bytes = unsigned(strtoul(argv[++i], NULL, 10));
    else if (a == "--start" && i + 1 < argc)
    {
      std::array<uint8_t, 32> ord;
      if (!parse_order(argv[++i], ord))
      {
        printf("--start must be a comma-separated permutation of 0..31\n");
        return 1;
      }
      start_orders.push_back(ord);
    }
    else
    {
      printf(usage, argv[0]);
      return 1;
    }
  }
  if (input.empty() || threads == 0 || minutes <= 0.0 || free_bytes > 3)
  {
    printf(usage, argv[0]);
    return 1;
  }

  bit_columns bc;
  if (!load_columns(input, bc))
  {
    printf("failed to load %s (need a binary file of u32 LE nonces)\n", input.c_str());
    return 1;
  }
  printf("loaded %zu nonces -> %zu XOR deltas\n", bc.deltas + 1, bc.deltas);

  // baselines
  state identity;
  for (unsigned b = 0; b < 32; ++b)
    identity.order[b] = uint8_t(b);
  evaluate(bc, identity, free_bytes);
  fill_free_entropies(bc, identity, free_bytes);
  print_state("identity grouping (natural bytes)", identity, free_bytes);

  double marg[32];
  double marg_sum = 0.0;
  for (unsigned b = 0; b < 32; ++b)
  {
    marg[b] = marginal_entropy(bc, b);
    marg_sum += marg[b];
  }
  printf("sum of marginal bit entropies: %.6f bits\n", marg_sum);
  state by_marginal;
  for (unsigned b = 0; b < 32; ++b)
    by_marginal.order[b] = uint8_t(b);
  std::stable_sort(by_marginal.order.begin(), by_marginal.order.end(), [&](uint8_t a, uint8_t b) {
    if (marg[a] != marg[b]) return marg[a] > marg[b];
    return a < b;
  });
  evaluate(bc, by_marginal, free_bytes);
  fill_free_entropies(bc, by_marginal, free_bytes);
  print_state("marginal-entropy-sorted grouping", by_marginal, free_bytes);

  shared_best global;
  global.offer(identity);
  std::vector<state> starts;
  starts.push_back(identity);
  for (size_t i = 0; i < start_orders.size(); ++i)
  {
    state st;
    st.order = start_orders[i];
    evaluate(bc, st, free_bytes);
    fill_free_entropies(bc, st, free_bytes);
    char label[48];
    snprintf(label, sizeof(label), "starting point %u", unsigned(i + 1));
    print_state(label, st, free_bytes);
    global.offer(st);
    starts.push_back(st);
  }

  std::atomic<uint64_t> evals(0);
  const clock_type::time_point start = clock_type::now();
  const clock_type::time_point deadline = start + std::chrono::milliseconds(int64_t(minutes * 60000.0));
  printf("searching with %u threads for %.1f minutes (objective: bytes %u..3)...\n", threads, minutes, free_bytes);
  fflush(stdout);

  std::vector<std::thread> pool;
  for (unsigned t = 0; t < threads; ++t)
    pool.emplace_back(search_thread, std::cref(bc), std::ref(global), std::ref(evals), deadline, seed + t * 0x9e3779b97f4a7c15ull, free_bytes, &starts);

  // progress line once a minute
  while (clock_type::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::seconds(60));
    if (clock_type::now() >= deadline)
      break;
    const state best = global.get();
    const double elapsed = std::chrono::duration<double>(clock_type::now() - start).count();
    printf("[%6.0fs] best sum %.6f bits, %llu byte evaluations\n", elapsed, best.total, (unsigned long long)evals.load());
    fflush(stdout);
  }
  for (auto& th : pool)
    th.join();

  state best = global.get();
  canonicalize(bc, best, free_bytes);
  // the tracked total is an incrementally accumulated sum of float deltas; recompute it
  // (and the free-byte display entropies) once from scratch so the reported objective is
  // exact rather than carrying the accumulated rounding drift of the annealing run
  evaluate(bc, best, free_bytes);
  fill_free_entropies(bc, best, free_bytes);
  printf("\n");
  print_state("best grouping found", best, free_bytes);
  printf("\nvs identity: %.6f bits/header on the objective (%+.1f bytes per 1000-header chunk at the entropy bound)\n",
         best.total - identity.total, (best.total - identity.total) * 999.0 / 8.0);
  if (free_bytes == 0)
    printf("intra-byte correlation captured: %.6f bits (identity captured %.6f)\n",
           marg_sum - best.total, marg_sum - identity.total);
  else
    printf("effective nonce wire entropy (8 bits per free byte + objective): %.6f bits (identity: %.6f)\n",
           8.0 * free_bytes + best.total, 8.0 * free_bytes + identity.total);
  printf("\n--bit-order ");
  for (unsigned b = 0; b < 32; ++b)
    printf("%u%s", best.order[b], b + 1 < 32 ? "," : "\n");
  printf("total byte evaluations: %llu\n", (unsigned long long)evals.load());
  return 0;
}

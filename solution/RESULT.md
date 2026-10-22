# hfhe-challenge v2 — resolved from scratch

**Verdict.** The published ciphertext is a **statistically perfect one-time pad** on
every plaintext block. It is not "hard to invert" — it publishes **no function of the
plaintext at all**. The 500,000 OCT bounty cannot be claimed by cryptanalysis of
[`secret.ct`](../secret.ct); it requires [`sk.prf_k`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L87), which is 256 bits of CSPRNG output
that never leaves the generator's process.

Reproduce: `python solution/verify.py` → **36 checks, 0 failures, exit 0**.

This analysis re-derives the scheme from the pinned engine source rather than inheriting
any prior conclusion; where two readings disagreed, the disagreement was resolved by
measurement. The engine source is not copied into this repository — every citation below
is a link to a specific line of
[`octra-labs/pvac_hfhe_cpp`](https://github.com/octra-labs/pvac_hfhe_cpp) at
[commit `071b0e9`](https://github.com/octra-labs/pvac_hfhe_cpp/tree/071b0e909c119de815e284b347c4bd979cb59ef3),
which is the commit recorded in both [`pvac_commit.txt`](../pvac_commit.txt) and
[`manifest.json`](../manifest.json). Because the links are pinned to that commit rather
than to a branch, each one keeps resolving to the exact tree that produced the artifact.

---

## 1. What the artifact actually publishes

[`secret.ct`](../secret.ct) = 1,963,107 B = 16-byte magic `OCTRA-HFHE-BTY02` + u64 cipher
count (22) + 22 × {u64 length | PVAC cipher blob}. Each blob is **exactly consumed** by
the parser — there is no trailing [`R_com`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/types.hpp#L95)
field, which is the v2 fix.

Every one of the 22 ciphers:

| property | value |
|---|---|
| `slots` | 1 |
| layers | exactly 2, **both `BASE`** (no `PROD` layer) |
| `c0` | zero (empty) |
| Pedersen [`PC`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/types.hpp#L96) | exactly 1 per layer → 44 total |

So for each cipher, decryption is a two-term sum with no additive term:

```
v = T_0 · R_0⁻¹  +  T_1 · R_1⁻¹
T_i = Σ_edges ± w · g^idx        (public, computable from secret.ct + pk.bin alone)
R_i = prf_R(pk, sk, seed_i)      (secret)
```

`T_i` is published by construction and independently confirmed by the organiser's own
[`verify_lpn_sample_binding.cpp`](../source/tools/verify_lpn_sample_binding.cpp), which
computes it with **no `R` and no `c0`**. The secret term is
[`prf_R`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/lpn.hpp#L404)
applied to each layer seed.

## 2. The finding: perfect hiding, by witness

The two layers are a wrapped encryption — [`enc_fp_wrapped_depth`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L981)
fuses `enc(v+m)` with `enc(−m)` — so layer 0 holds `v + m` and layer 1 holds `−m`, for a
secret mask `m = ` [`rand_fp_nonzero()`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/types.hpp#L209).
Therefore

```
T_0 = R_0 · (v + m)        T_1 = R_1 · (−m)
```

For **any** candidate `v` and **any** nonzero mask `m` you choose, set

```
R_0 = T_0 · (v+m)⁻¹        R_1 = T_1 · (−m)⁻¹
```

and the published `(T_0, T_1)` are reproduced exactly. [`verify.py`](verify.py) executes this:

- cipher 0 (the length carrier, so `v ∈ [1,315]`): **315/315 candidate lengths fit**,
  for five unrelated masks.
- an arbitrary 15-byte ASCII block (`the quick brown`, chosen by me, not the real
  plaintext): **21/21 block ciphers reproduce it exactly**.

This is not a probabilistic statement. `R` is uniform over `F_p*`, so `T = R·v` is
uniform over `F_p*` **for every nonzero `v`** — the distribution of `T` is *identical*
for all plaintexts. The artifact is an information-theoretic OTP, not a computational one.

### Why the obvious handles fail

| candidate handle | measured outcome |
|---|---|
| [`R_com`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/types.hpp#L95) offline guess oracle (the v1 bug) | **absent from the wire**; parser consumes exactly `len(blob)` bytes |
| Pedersen [`PC = R⁻¹·G + rho·H`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/ristretto255.hpp#L754) | `rho` is `sc_reduce256(sha256(...))` — a **full 252-bit blind**. Perfectly hiding. (Also: group order is prime, so every point is a multiple of `H`; the "is `PC − guess·G` a valid point" test is vacuous.) |
| zero plaintext → zero aggregate | closed by [`enc_fp_wrapped_depth`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L981); all 44 aggregates nonzero |
| `R²` from an opposite-sign edge pair | 0 hits; cipher-0 length window **0 hits** at ~10⁶ candidates |
| mask reuse across ciphers/layers | 44 distinct seeds, 44 distinct `PC`, 44 distinct `T`, 4 independent reuse tests negative |
| degenerate build (`R = 1`, `T` in `⟨g⟩`) | 0/44 aggregates in the order-337 subgroup; `R ≠ 1` (132/330 printable = chance) |
| `T` leaking through a small multiple | the cipher-0 length window is the only high-signal discriminator without `sk`, and it stays quiet |
| `R` recoverable from the LPN samples | the LPN stream is keyed by `dom` **inside the AES key**, so the published `A` rows and the Toeplitz stream are different keys |
| the recryption / proof layer, where the engine's own recent fixes land | **unreachable from the artifact**: all 44 published layers are BASE, so `secret.ct` carries no PROD layer, no recryption transcript and no proof for those defects to act on |
| a third party's public "plaintext recovery" writeup | a **template**: it describes a syndrome-encryption scheme the engine does not implement, asserts a 2^60 complexity with no computation behind it, and ships no results file |

## 3. The LPN side target (a separate prize, not a route to the key)

[`lpn_samples/`](../lpn_samples/) publishes, for all 44 BASE layers, the full
`y = ⟨A,S⟩ ⊕ e` instance: `n=4096`, `t=16384`, `τ=1/8`, with the **entire `A` matrix** as
the `"a"` field.

- Noise is genuine: streaming GF(2) elimination gives **rank 4096 with 6133/16384
  (37.4%) inconsistent rows** — the exact signature of LPN noise. Gaussian elimination
  does **not** recover `S`.
- The instance is **above** the decoding threshold (`t=16384` vs `n·H(τ)≈2226`, 7.4×),
  but decoding a random `[16384,4096]` code at `δ=1/8` costs Prange ≈ `(7/8)⁻⁴⁰⁹⁶ ≈ 2⁷⁸⁹`;
  BKW's correlation decays as `0.75^(2^a)`, so folding destroys the signal. Infeasible.
- **Even a full recovery of `S` would not yield `R`.** [`S`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L151)
  ([`lpn_s_bits`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L151)) is generated independently of [`prf_k`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L87),
  and [`prf_R_core`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/lpn.hpp#L376)
  needs `top` from [`derive_aes_key(..., Dom::TOEP, ...)`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/lpn.hpp#L307),
  which absorbs [`prf_k`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L87). `dom` is folded into the **key** at
  [lpn.hpp:331](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/lpn.hpp#L331),
  not just the nonce, so the two streams are unrelated. The LPN samples are an independent
  sub-challenge, not a step toward the plaintext.

## 4. Provenance, verified

| item | value |
|---|---|
| pinned engine commit | [`071b0e909c119de815e284b347c4bd979cb59ef3`](https://github.com/octra-labs/pvac_hfhe_cpp/tree/071b0e909c119de815e284b347c4bd979cb59ef3) |
| [`pk.bin`](../pk.bin) | 3,042,901 B compressed → 17,110,454 B raw |
| `canon_tag` | `0x0760802093a19931` |
| `H_digest` | `601435f4977dd2a0c396bd96c7947fb884b602a52b6d7e0660b3fce3508497f5` |
| [params](../params.json) | B=337, m=8192, n=16384, h_col_wt=192, x_col_wt=128, err_wt=128, noise_entropy_bits=128, tuple2_fraction=0.55, depth_slope_bits=16, lpn 4096/16384, τ=1/8 |

The artifact is **faithful** to the pinned source: edge counts track the entropy-budget
formula `2·(8 + 2q₂ + 3q₃)` from [`struct Budget`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L199)
for depth hints `d = 0..22` with deltas in `[-5,0]` (the merge/permute collapse), and the
44 `ztag` values recompute from published data via
[`prg_layer_ztag`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/matrix.hpp#L286)
(`sha256("pvac.dom.ztag" ‖ canon_tag ‖ nonce)` truncated to LE64) with **0/44 mismatches**.
Both of those statements are executed by [`verify.py`](verify.py) as C10, not asserted.

## 5. Recorded provenance oddities (not exploitable)

- The shipped generator [hardcodes `"status": "pre-release"`](../source/hfhe_bounty_artifact.cpp#L304)
  while the published [`manifest.json`](../manifest.json) says `"active"`.
- [`compute_R_com_base`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/hash.hpp#L198)
  hashes [`R_slots.size()`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/hash.hpp#L210)
  and never reads a slot — so even if a future release republished [`R_com`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/types.hpp#L95), it would hand
  over a hash of the slot *count*, not a commitment. This is a **soundness** defect, not a
  confidentiality one.
- Per-edge 8192-bit [`sigma`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/matrix.hpp#L298)
  is produced at four sites
  ([arithmetic.hpp:62](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/arithmetic.hpp#L62),
  [arithmetic.hpp:67](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/arithmetic.hpp#L67),
  [encrypt.hpp:386](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L386),
  [encrypt.hpp:390](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L390))
  and verified at none, and the Pedersen [`PC`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/types.hpp#L96) is produced at
  [encrypt.hpp:728](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L728)
  and [:749](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L749)
  and never opened. Both are soundness/integrity defects. None of the three touches the
  plaintext.

## 6. The container does not pin its own payload

A second, independent defect lives in the compressed wrapper rather than in the cipher. The
container is an adaptive range coder: the decoder refills with zeros past the end of input
([`RangeDecoder::next_byte`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/pvac_compress.hpp#L136)),
and
[`unpack`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/pvac_compress.hpp#L193)
ends at a declared-size comparison
([:209](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/pvac_compress.hpp#L209))
without ever comparing the consumed position against the input length.

Measured ([`probe_container.py`](probe_container.py), re-executed as C9):

| file | sha256 | decodes to | payload consumed |
|---|---|---|---|
| [`pk.bin`](../pk.bin) | `1e788edf…e9410` | 17,110,454 B | 3,042,896 of 3,042,896 |
| `pk.bin` + 64 zero bytes | differs | **the same 17,110,454 B** | 3,042,899 of 3,042,960 |

So `sha256(pk.bin)` pins a *byte string*, not a key: the published `SHA256SUMS` does not
determine which public key the engine will load. The tolerance is narrow — a **non-zero**
suffix is rejected (`output exceeds declared size`), because the decoder pulls the appended
bytes into its code register during the final renormalisation *before* it lands on the
end-of-stream symbol. The container is therefore non-canonical on a zero-byte alphabet, not
arbitrarily malleable.

The two published readers also disagree on the same bytes. The pinned C++ deserializer
[`deserialize_pubkey_raw`](../source/pvac_artifact_serialize.hpp#L425) ends at
[`validate_pubkey_structure(pk)`](../source/pvac_artifact_serialize.hpp#L464) with no
`r.p == len` comparison and accepts trailing bytes, while the port used here
[asserts full consumption](parse.py#L198) and rejects them.

Impact: an **integrity and canonicality** defect. It does not hand over the plaintext, does
not weaken §2, and does not make the bounty claimable. It does mean an artifact digest is the
wrong thing to pin.

## 7. Conclusion

Three independent lines of evidence agree:

1. **Algebraic** — `T = R·v` with `R` uniform means `T` is uniform for every `v`.
2. **Constructive** — an explicit witness `(R_0, R_1)` exists for every candidate
   plaintext, executed in [`verify.py`](verify.py) at 315/315 and 21/21.
3. **Structural** — the wire carries no [`R_com`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/types.hpp#L95), [`PC`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/types.hpp#L96) is perfectly blinded, and every
   plaintext-dependent term is multiplied by `R` before publication.

The ciphertext is correct. The barrier is the 256-bit [`prf_k`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L87) CSPRNG draw. No amount of
work on `secret.ct` closes that gap, and the `lpn_samples` are a separate, infeasible
instance rather than a shortcut.

**This is a negative result, and it is a sound one.** The bounty is not claimable by
cryptanalysis. Anyone reporting a plaintext for this artifact either guessed a
low-entropy payload (impossible here — no oracle exists to confirm it) or holds `sk`.

---

### Files

Everything below lives in `solution/`. The bounty package itself sits unmodified at the
repository root.

| file | role |
|---|---|
| [`verify.py`](verify.py) | the whole finding as 43 re-runnable checks |
| [`RESULT.md`](RESULT.md) | this document |
| [`parse.py`](parse.py) | PVAC v0x03 container parser (stdlib only) |
| [`rist.py`](rist.py) | pure-Python Ristretto255 (stdlib only) |
| [`README.upstream.md`](README.upstream.md) | the upstream README body, pinned so this file's preservation of it is checkable |
| [`commit_msg_guard.py`](commit_msg_guard.py) | commit-message guard (names issues in words, never in reference syntax) |
| [`probe_container.py`](probe_container.py) | the container measurement behind C9, including the two full decodes of `pk.bin` |

[`verify.py`](verify.py) needs nothing beyond the Python standard library and the artifacts
at the repository root. The engine source it cites is deliberately not vendored: the
citations are line-anchored links to a fixed upstream commit, so they stay resolvable
without this repository carrying a copy of someone else's GPL-3.0 code.

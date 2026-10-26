# hfhe-challenge v2 — resolved from scratch

**Verdict.** The published ciphertext is a **statistically perfect one-time pad** on
every plaintext block. It is not "hard to invert" — it publishes **no function of the
plaintext at all**. The 500,000 OCT bounty cannot be claimed by cryptanalysis of
[`secret.ct`](../secret.ct); it requires [`sk.prf_k`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L87), which is 256 bits of CSPRNG output
that never leaves the generator's process.

Reproduce: `python solution/verify.py` → **85 checks, 0 failures, exit 0**.

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

- Gaussian elimination does **not** recover `S`: the instance has full column rank 4096 over
  16,384 rows and the dependent rows carry a syndrome bit, so elimination terminates with
  12,288 unsatisfied equations and no solution. That is a fact about the rank, not a
  measurement of noise, and the next sentence is why the distinction matters.
  **The census is not the evidence, and an earlier version of this document said it was.**
  For any `[t, n]` system of full column rank the dependent-row count is exactly `t − rank`,
  and the syndrome is one bit per dependent row, so "rank 4096 with 6133 of 16,384
  inconsistent" is arithmetic: a random dense system of the same shape gives rank 4096,
  12,288 dependent rows and 6,099 inconsistent rows. The published 6,133 sits **−0.20σ**
  from the 6,144 a fair coin predicts, so the syndrome weight distinguishes this instance
  from a random one by nothing. What the sample files *do* establish is that the `A` rows
  and the `y` bits are the published objects they claim to be and that the instance is
  the size §3 says — not that the noise is "genuine" in any sense a random code lacks.
  Verified as C17, including the random control.
- The published `y` is the **raw PRF output bit**, not the error vector: the 44 files carry
  8,196 ones across 16,384 rows, so the error term `e` is baked into what is published. That is
  the correct thing to publish for a decoding instance (`y = ⟨A,S⟩ ⊕ e` is what an attacker
  gets), and it means the effective noise rate for anyone attacking `S` is the `τ=1/8` of the
  engine, not the 50% the field values suggest.
- The instance is **above** the decoding threshold (`t=16384` vs `n·H(τ)≈2226`, 7.4×),
  but decoding a random `[16384,4096]` code at `δ=1/8` costs Prange ≈ `(7/8)⁻⁴⁰⁹⁶ ≈ 2⁷⁸⁹`;
  BKW's correlation decays as `0.75^(2^a)`, so folding destroys the signal. Infeasible.
- **Even a full recovery of `S` would not yield `R` — and the reason is sharper than key
  separation.** [`S`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L151)
  ([`lpn_s_bits`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L151)) is indeed generated
  independently of [`prf_k`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L87), and
  [`prf_R_core`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/lpn.hpp#L376) does need `top`
  from [`derive_aes_key(…, Dom::TOEP, …)`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/lpn.hpp#L307),
  which absorbs [`prf_k`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L87); `dom` is folded into the
  **key** at [lpn.hpp:331](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/lpn.hpp#L331), not just the nonce,
  so the two streams are unrelated. That was the argument this document shipped first, and it
  is true but weak: it justifies "separate prize" by pointing at a secret, when the structure
  says something stronger.
- **The real barrier is that `prf_R` reads 127 bits out of 16384.** [`toep_127_scalar`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/toeplitz.hpp#L121)
  computes the full GF(2) convolution and then keeps only bits `0..126` of it
  ([toeplitz.hpp:133](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/toeplitz.hpp#L133)), and convolution
  bit `j` only sums inputs of index `≤ j`. So
  `out_j = Σ_{i≤j} top_i · y_{j−i} mod 2`, every output bit is a triangular product, and
  **no input bit at index ≥ 127 can reach the output at all**. `prf_R_core` allocates
  `((16384 + 127 + 63)/64) = 258` words = **16,512 bits of `top`** at
  [lpn.hpp:393](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/lpn.hpp#L393) and uses 127 of them;
  16,385 are discarded. The same holds for `y`. Verified as C18, including the closed form
  and a bit-exact port of `gf2_conv_scalar`.
- **And the 127 bits of `y` that do matter are published in the clear.** Every one of the 44
  sample files carries the `"y"` field for each row, so `y[0..126]` — the entire input to the
  Toeplitz step — is handed out directly. This makes the LPN sub-challenge not merely
  orthogonal to `R` but **redundant with respect to it**: an attacker who recovers all of `S`
  obtains `y` for 16,384 rows, of which `prf_R` consumes 127, and those 127 are already in the
  file. Recovering `S` cannot help with `R`, and the published instance cannot be *made* to
  help by any choice of attack, because the map from `y` to the output discards all but 127
  bits before the secret-dependent step even begins. C18 checks this on all 44 files.
- Consequence for the bounty framing: the LPN target is a self-contained decoding problem with
  a published answer-checking oracle, not a foothold. It is worth saying plainly because the
  natural reading of "44 published LPN samples" is that they weaken the mask — they do not
  touch it.

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
- The shipped audit [prints `wire_v3 = 1` from a string literal](../source/hfhe_bounty_artifact.cpp#L414)
  in both `public_audit` and [`selftest`](../source/hfhe_bounty_artifact.cpp#L448): no value is
  computed, so that line cannot fail and reports nothing about the artifact. The property it
  names *is* enforced — [`deserialize_cipher`](../source/pvac_artifact_serialize.hpp#L204)
  rejects any version byte other than `VERSION` — so this is an audit-reporting defect, not an
  artifact defect. It is recorded because it is the same defect class §7 charges a third-party
  tool with, found in the organiser's own audit path. Verified as C15.

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
determine which public key the engine will load. An immediate high-bit suffix like `0xff`
is rejected (`output exceeds declared size`), because the decoder pulls it into its code register
during final renormalisation *before* landing on the end-of-stream symbol. However, once past
the EOF boundary (e.g. via a 4-byte zero pad or past the decoder's unconsumed tail), arbitrary
non-zero payloads are completely unread and silently accepted — in fact, the authentic `pk.bin`
itself leaves its final 5 bytes unconsumed. The container is therefore unanchored and malleable
to arbitrary trailing data injection.

The two published readers also disagree on the same bytes. The pinned C++ deserializer
[`deserialize_pubkey_raw`](../source/pvac_artifact_serialize.hpp#L425) ends at
[`validate_pubkey_structure(pk)`](../source/pvac_artifact_serialize.hpp#L464) with no
`r.p == len` comparison and accepts trailing bytes, while the port used here
[asserts full consumption](parse.py#L198) and rejects them.

Impact: an **integrity and canonicality** defect. It does not hand over the plaintext, does
not weaken §2, and does not make the bounty claimable. It does mean an artifact digest is the
wrong thing to pin.

## 7. What the public analyses get wrong

The most detailed public writeup on this challenge reaches the same verdict by two
checkable wrong turns.

It states the plaintext length is **110 bytes**. The wire says otherwise. `enc_text`
emits one length cipher and then one cipher per 15-byte block, looping while the position
is below the length
([`text.hpp:39-61`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/utils/text.hpp#L39)),
so `ceil(n/15) = 21` forces `300 < n ≤ 315`. [`secret.ct`](../secret.ct) carries 22
ciphers, so the plaintext is **301–315 bytes**; a 110-byte payload would produce 9
ciphers, not 22. Verified as C11.

It also states the LPN instance is unexposed ("exposed LPN equations: 0"). The artifact
publishes 44 sample files, one per cipher/layer, each holding `t = 16384` rows of a
4096-bit `a` and a bit `y` — **720,896 equations** at the published τ = 1/8. That is a
real instance of the side target, just an infeasible one: 16384 samples is 7.4× the 2226
needed for a unique solution in principle, with Prange ≈ 2^789 and BKW ≈ 2^341. §3 has
the numbers. Verified as C11.

Both errors run in the safe direction, so the verdict is unchanged — but they are the
reason this result is stated by witness rather than by survey. The other public writeups
are no stronger: one describes a syndrome-encryption scheme the engine does not implement,
and another's cross-layer tool prints "no observable correlation between layers" as a
literal, unconditionally, without testing anything.

## 8. The three public reports on the engine, and how each fares here

Three reports are open against the engine at the pinned commit. None of them changes the
verdict, and two name mechanisms that sound like they should apply here, so each was tested
rather than dismissed.

**A structural claim about layer-0 edge pairs.** One report states, of a different
artifact: "In layer-0, two edges sharing the same idx with opposite ch expose ±R²·g[idx]
(cancel g → recover R² → R = sqrt(R²), field p ≡ 3 mod 4)". The precondition is real in
this one: **56 `(layer, idx)` groups carry both signs, 31 of them in layer 0**, and the
multiplicity is exactly 2 in every group.

Testing it naively would prove nothing, which is the trap worth recording. The aggregate is
`T_l = R_l·v_l`, so isolating a *single* layer's mask returns `v_l` — and for one half of the
wrap that is `v + m`, the plaintext plus a fresh mask, not the plaintext. The wrap is what
closes it: `T_0 = R_0(v + m)` and `T_1 = R_1(−m)`, so `v = T_0/R_0 + T_1/R_1`. The test
therefore closes over **both** layers of a cipher, with `cand_l` hypothesised to equal
`R_l^k` for `k ∈ {1, −1, 2, −2}` independently per layer and both square roots per `k = ±2`
term (`p ≡ 3 mod 4`). That is only possible where a cipher carries such a pair in **both**
layers — 11 of the 22 do; 8 more carry one in a single layer, where the recovered value
stays hidden by the other layer's mask, and ciphers 0, 1 and 5 — the length carrier among
them — carry none at all.

**0 recoveries** in 1862 closing combinations, with the scorer positively controlled first
so that a real recovery could not pass unnoticed (cipher 0 is a length in 301–315; every
other cipher is 15 printable bytes). Verified as C12.

The arithmetic reason is one line of the engine: every edge weight is a coefficient
times the mask, `field::Op::mul(n.coef, R)`
([`encrypt.hpp:779`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L779)),
and `merge()` keeps the two signs in separate accumulators
([`encrypt.hpp:619-624`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L619)),
so a same-idx opposite-sign pair contributes `(c_P − c_M)·g^idx·R` — **linear in `R` with
an unknown coefficient**, one equation in two unknowns. An `R²` term would require the
*difference* of two public coefficients to equal `R`, which no construction in the engine
sets — the coefficients are drawn independently of the mask. The report is
also made against a different artifact (a homomorphic `a.ct + b.ct` sum), and the engine
ships a regression test for its shape that asserts zero leaks (`tests/bounty_r2_attack.cpp`
at the pin).

**The recryption soundness gaps.** Two unmerged engine changes, plus an open report that
reproduces them, concern the native-recrypt statement digest and the unbound
`proof.digest`. The report runs the escalation itself and reaches the same conclusion this
document reaches from the artifact side: the surface is **integrity-only**, no function on
it produces the reset secrets, and **zero plaintext elements** come back. That is consistent
with what `secret.ct` publishes — 22 ciphers, all BASE layers, no PROD layer, no recryption
transcript, no proof. Those reports are about a surface the bounty artifact does not
contain, so they cannot decrypt it. Verified structurally as C1.

**Non-canonical Ristretto255 encodings.** The third report is correct about the engine and
irrelevant to this artifact, and the difference is worth recording. At the pin,
`fe_frombytes` masks bit 255 instead of rejecting it and nothing range-checks the integer
([`ristretto255.hpp:149`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/ristretto255.hpp#L149)),
so `rist_decode` accepts two distinct byte strings for one group element. That matters here
because the natural check — "44 distinct `PC`" — compares **bytes**, and under a lenient
decoder byte-distinctness does not imply commitment-distinctness. Measured under the strict
rule the decoder omits: all 44 encodings have bit 255 clear, all are below `2^255 − 19` as
integers, all decode, and the 44 points are **distinct as group elements**, not merely as
bytes. Verified as C13.

## 9. Conclusion

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

## 10. A soundness question the cipher does not answer: which ciphertext is the bounty

Everything above is a confidentiality result, and §5 recorded the integrity fields as inert
without asking what that costs. It costs the claim, not the plaintext.

A verifier holding `sk` decides "this ciphertext decrypts to that plaintext" by running
[`dec_text`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/utils/text.hpp#L63)
and comparing. The published artifact offers no such route to anyone else:

| what would bind a cipher to a key | state in this artifact | measured |
|---|---|---|
| `R_com`, the offline guess oracle (v1's bug) | absent from the wire | C1: exact byte consumption, no trailer |
| Pedersen `PC = R⁻¹·G + rho·H` | one per BASE layer, produced at [encrypt.hpp:728](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L728) and [:749](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L749), never opened | 44 well-formed points (C13), and nothing verifies them against anything |
| per-edge `sigma`, 8192 bits each | produced at four sites ([arithmetic.hpp:62](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/arithmetic.hpp#L62), [:67](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/arithmetic.hpp#L67), [encrypt.hpp:386](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L386), [:390](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L390)), verified at none | **published in full and checked by nothing**: all 1829 edges carry a distinct 128-word sigma, and no verifier recomputes one (C15). An earlier draft of this table said sigma was absent from the wire; the measurement corrected it, and the corrected form is the worse of the two — a decoy is harder to notice than a gap |
| the container's own digest | none | C9: an all-zero suffix changes the file's sha256 and not its payload |

So the only statement a third party can make about `secret.ct` is about its **shape** — 22
ciphers, 44 BASE layers, 1829 edges inside the budget model (C10), 44 canonical commitments
(C13) — and shape is not content. Two consequences follow, and they are the reason this
section exists:

1. **A "recovered plaintext" claim for this artifact is unverifiable by construction**, not
   merely unsupported. §2 supplies the witness: for every `(v, m)` there is an `(R_0, R_1)`
   that reproduces `(T_0, T_1)` exactly, so any claimed plaintext is consistent with the wire
   and no computation on public data can rank one claim above another. Verification requires
   `sk`, which is exactly what the bounty asks for.
2. **The artifact's own authenticity is shape-deep.** An attacker who rebuilds the bundle with
   different plaintext under a key they generate produces a `secret.ct` that passes every
   public structural check in this document, because none of those checks reaches the key. The
   published `SHA256SUMS` is the only binding, and C9 shows a compressed artifact can be
   extended without changing what it decodes to — so the digest binds a byte string, not a
   semantic object.

This does not weaken §2 and it does not make the bounty claimable; it is the mirror image.
Perfect hiding means the ciphertext carries no verifiable trace of the plaintext, and
verifiability of "this is the organiser's ciphertext" would be exactly such a trace. The
construction is self-consistent: the same property that makes it unbreakable makes it
un-attestable. Recorded here so the two are not confused for each other in either direction —
nobody should read §5's inert fields as "a leak was missed", and nobody should read §2 as
"the artifact is sound" when what was proven is "the artifact is opaque".


## 11. Upstream watch, and what this result does not cover

Observed 2026-10-23, this session: the engine's `main` and `HEAD` are still at the pin
`071b0e9`, and its three open pull refs (490, 499, 500) are the three reports §8 already
treats — nothing new landed, so no finding above was re-established against a new tree. The
challenge repository's `main` is at the LPN-sample clarification commit.

Recorded so they are not mistaken for covered:

- **Attestability, in full, is §10's subject** — it is listed here only so this section's
  "not covered" list is complete. The short form: no published field lets a third party verify
  a plaintext claim for this artifact, so a third-party "recovered plaintext" report is
  unverifiable by construction rather than merely unsupported.
- **The LPN bound is Prange/BKW, not ISD.** A Stern/BJMM estimate would tighten §3's 2^789. It
  cannot change the conclusion, because `S` does not produce `R`.
- **The suite's own accounting was wrong for two sessions and C21 now catches it.** Five
  places in these documents kept promising a count the suite had outgrown, and one of them
  already carried the newer number, so the file contradicted itself. C21 reads every stated
  count out of both documents and fails when it differs from the run — which is how the drift
  was found, and how it was found again while the census check, the Toeplitz check and the
  budget check were being added. The count is a property of the tree, so it is read from the
  tree rather than written down once and forgotten.
- **An earlier version of §3 claimed the noise census was evidence.** It is not: see §3's
  corrected wording. The figure is arithmetic and a random control reproduces it, so the claim
  was demoted to what it supports. C17 executes both halves so it cannot silently return.
- **One engine citation shipped pointing at the wrong line.** `dec_text` was linked to
  `text.hpp#L39`, which is `enc_text`; `dec_text` is at `:63`. Every other anchor resolved, so
  this was the one defect in an otherwise correct citation set, and nothing in the suite could
  have caught it: C8 checks that a link is pinned and clickable, which is a claim about the URL,
  not about the code. C8b now resolves each anchor against a local clone at the pin and requires
  the named symbol to appear inside the cited line window — 43 anchors enforced, 12 skipped
  because their label names a concept (`sigma`, `S`) or a file pointer (`encrypt.hpp:779`) rather
  than an identifier. The skip rule is deliberate: demanding a literal match for a prose label
  would force the prose to be worse in order to satisfy the test.
- **No rebuild.** This machine has no C++ toolchain (`g++` and `clang++` are both absent), so
  every statement about the source is a reading of the pinned text, never a measurement of a
  compiled binary. Routes that need a build are `inconclusive-needs(c++ toolchain)`, not done.
- **No positive control for the length-window scorer.** A v1-era artifact, or one whose
  plaintext had a known prefix, would test §2 and §8's scorer against a case where a recovery
  *should* fire. This artifact supplies no such case.

### Files

Everything below lives in `solution/`. The bounty package itself sits unmodified at the
repository root.

| file | role |
|---|---|
| [`verify.py`](verify.py) | the whole finding as 85 re-runnable checks |
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

## 12. The shipped binding tool verifies a header, not a sample

[`source/tools/verify_lpn_sample_binding.cpp`](../source/tools/verify_lpn_sample_binding.cpp)
is the tool the challenge provides to answer "does this LPN sample belong to this ciphertext".
It reads **one line** of the sample —
[`read_first_line(argv[3])`](../source/tools/verify_lpn_sample_binding.cpp#L169) — parses it as
a header, and compares four fields (`seed_ztag`, `nonce_lo_hex`, `nonce_hi_hex`,
`public_T_hex`) against the wire targets at
[:174-182](../source/tools/verify_lpn_sample_binding.cpp#L174). The 16,384 rows are never
opened; the parameters `n`, `t`, `tau_num`, `tau_den`, `row_words` are parsed and never used;
`cipher_index`, `layer_id` and `slot` are not compared at all.

The predicate is therefore a property of the first line alone. C19 transcribes it and shows
three mutations still returning `binding = 1`:

| mutation | binds? |
| --- | --- |
| header with `cipher_index=999, layer_id=7, slot=3` | yes |
| header with `n=1, t=1, tau_num=0, tau_den=1, row_words=1` | yes |
| header only — all 16,384 rows deleted | yes |

The published samples are genuine: all 44 headers do bind, and §3's measurements show the 44
instances are distinct and correctly sized. The defect is scope, not correctness — the tool
cannot tell the real instance from an empty file, so a third party can use it to check a
label but not a claim. Closing the gap means streaming the rows and recomputing `public_T`
from them, which is what `parse.py` and this suite already do.

## 13. The advertised entropy budget is a staircase, not a slope

[`params.json`](../params.json) publishes `noise_entropy_bits: 128` and
`depth_slope_bits: 16`, and [`manifest.json`](../manifest.json) repeats the first. Read
literally that is "128 bits of noise entropy at depth 0, and 16 more bits per level". What
[`Budget::compute`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L205)
actually does is floor the cap twice:

```cpp
double cap = p.noise_entropy_bits + p.depth_slope_bits * std::max(0, d);      // :206
double c2  = 2.0 * std::log2(p.B);  double c3 = 3.0 * std::log2(p.B);          // :207-208
int q2 = floor(cap * p.tuple2_fraction / c2);                                  // :210
int q3 = floor(cap * (1 - p.tuple2_fraction) / c3);                            // :211
```

The entropy actually drawn is `q2·c2 + q3·c3`, and with `B = 337` the two quanta are
`c2 = 16.7932` and `c3 = 25.1898` bits. Both floors are coarse, so the model spends a
**staircase** of whole tuple draws:

| depth | cap | q₂ | q₃ | spent | shortfall |
| --- | --- | --- | --- | --- | --- |
| 0 | 128 | 4 | 2 | 117.55 | 10.45 |
| 1 | 144 | 4 | 2 | 117.55 | 26.45 |
| 2 | 160 | 5 | 2 | 134.35 | 25.65 |
| 3 | 176 | 5 | 3 | 159.54 | 16.46 |
| 4 | 192 | 6 | 3 | 176.33 | 15.67 |
| 5 | 208 | 6 | 3 | 176.33 | 31.67 |
| 6 | 224 | 7 | 4 | 218.31 | 5.69 |
| 7 | 240 | 7 | 4 | 218.31 | 21.69 |
| 8 | 256 | 8 | 4 | 235.10 | 20.90 |
| 9 | 272 | 8 | 4 | 235.10 | 36.90 |
| 10 | 288 | 9 | 5 | 277.09 | 10.91 |
| 11 | 304 | 9 | 5 | 277.09 | 26.91 |
| 12 | 320 | 10 | 5 | 293.88 | 26.12 |
| 13 | 336 | 11 | 6 | 335.86 | 0.14 |
| 14 | 352 | 11 | 6 | 335.86 | 16.14 |
| 15 | 368 | 12 | 6 | 352.66 | 15.34 |
| 16 | 384 | 12 | 6 | 352.66 | 31.34 |
| 17 | 400 | 13 | 7 | 394.64 | 5.36 |
| 18 | 416 | 13 | 7 | 394.64 | 21.36 |
| 19 | 432 | 14 | 7 | 411.43 | 20.57 |
| 20 | 448 | 14 | 8 | 436.62 | 11.38 |
| 21 | 464 | 15 | 8 | 453.42 | 10.58 |
| 22 | 480 | 15 | 8 | 453.42 | 26.58 |

Three things follow from that table, all of them arithmetic on the model's own definitions:

- **Depth 0 does not deliver the advertised 128 bits.** It draws 117.55, a 10.45-bit gap
  before the first level is even considered.
- **Nine of the 22 steps add exactly zero bits** — `(0,1)`, `(4,5)`, `(6,7)`, `(8,9)`,
  `(10,11)`, `(13,14)`, `(15,16)`, `(17,18)`, `(21,22)` — because neither floor moves across
  the step. The artifact itself walks 21 of those steps (cipher 0 is depth 0 and `enc_text`
  starts at depth 2), and eight of them are zero-gain. The advertised `depth_slope_bits: 16`
  never appears as an increment: the only step sizes the model can produce are `0`, `16.79`,
  `25.19` and `41.98` bits.
- **No depth ever reaches its cap.** Mean shortfall 18.88 bits, worst 36.90 at `d = 9`
  (272 advertised, 235.10 drawn), best 0.14 at `d = 13`.

This is a mismatch between the published parameters and the code that consumes them, of the
same class as §5's other provenance oddities, and it is invisible in the engine's own
documentation: a grep of every `.md` in the pinned clone for `noise_entropy`, `tuple2` or
`depth_slope` returns nothing, and [`validate_params`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L17)
never validates them. So `params.json` is the only description of this model, and it
describes something the code does not do.

**What this is not.** It is not a measured entropy loss in the artifact, and it is not a
route to the plaintext. §2's hiding argument is a witness over the field — `T_0 = R_0·(v+m)`,
`T_1 = R_1·(−m)` — and it does not consume the noise budget at all; likewise the edge counts
in §4 are *consistent* with the staircase (`deltas in [-5,0]`), which is exactly why the
staircase is visible from the wire rather than merely inferred from the source. Whether
117.55 bits instead of 128 at depth 0 matters for the construction's claimed security is not
decided here, and the honest report is the bound, not a verdict. Executed as C20.


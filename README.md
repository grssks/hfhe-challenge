# HFHE Challenge v2

This is the second version of the challenge. The first version was canceled because the public artifact included an unnecessary `R_com` commitment. That commitment allowed structured plaintext guesses to be checked offline, creating an unintended verification oracle. This issue has been removed in v2.

The task is to recover the plaintext from `secret.ct`. This file contains a private key and metadata associated with the address `octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`.

No additional information is provided. If recovery is successful, the Octra web client can be used to access the wallet and claim the reward of 500,000 oct. The solver may also contact `dev@octra.org` to receive an additional 500,000 oct, for a total of 1,000,000 oct, or the equivalent amount in USDC.

The rest of the bounty package remains unchanged:

- `manifest.json`
- `params.json`
- `pk.bin`
- `pvac_commit.txt`
- `secret.ct`
- `source/hfhe_bounty_artifact.cpp`
- `source/pvac_artifact_serialize.hpp`

The ciphertext was generated using an updated version of `pvac_hfhe_cpp`, pinned to commit `071b0e9`. It is recommended to use this specific version when reproducing the artifact format or testing attacks.

**updated (july 11)**

At the request of the majority, we are providing additional LPN artifacts associated with the live challenge ciphertext.

- `lpn_samples`

These samples expose the side target `y = <A, S> xor e`, with `tau = 1/8` and `n = 4096`. Recovering `S` is an additional cryptanalysis target; the main bounty condition remains recovery of the plaintext/wallet payload from `secret.ct`.

A tool has also been added to validate the public metadata binding between the LPN artifacts and `secret.ct`.

- `source/tools/verify_lpn_sample_binding.cpp`
---

## Fork Note — Result

**No file from the bounty package has been edited**: the upstream text above the rule is preserved byte-for-byte (1,780 B, `sha256 b795650113ad43941be20d5bff7cf0274e2a675cd550a880b9c49b570c8b7cff`, the digest published in `SHA256SUMS`), and the remaining 52 package files are byte-identical to upstream.

> [!IMPORTANT]
> **Verdict: the ciphertext is a statistically perfect one-time pad.**
> The bounty is not reachable by cryptanalysis of `secret.ct`. It requires [`sk.prf_k`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L87),
> 256 bits of CSPRNG output that never leaves the generator's process.

Reproduce the whole finding with one command:

```
python solution/verify.py        # 36 checks, 0 failures, exit 0
```

## Layout

Everything that is **not** part of the published bounty package lives under [`solution/`](solution/). The package itself is untouched at the root.

```
secret.ct  pk.bin  params.json  manifest.json  pvac_commit.txt  SHA256SUMS   package
lpn_samples/  source/                                                        package
README.md                                                                    package body + this note
solution/                                                                    fork only
├── verify.py              36 checks; exit 0 = the finding reproduces
├── RESULT.md              the written analysis
├── parse.py               PVAC v0x03 container parser (stdlib only)
├── rist.py                pure-Python Ristretto255 (stdlib only)
├── README.upstream.md     the upstream README body, pinned for the C7 check
└── commit_msg_guard.py    commit-message guard (local hook, not shipped logic)
```

## Reading the citations

The engine source is not copied into this repository. Every citation is a link to a specific line of [`octra-labs/pvac_hfhe_cpp`](https://github.com/octra-labs/pvac_hfhe_cpp) **at the commit the artifact was built from** — [`071b0e9`](https://github.com/octra-labs/pvac_hfhe_cpp/tree/071b0e909c119de815e284b347c4bd979cb59ef3) — which is the commit recorded in both [`pvac_commit.txt`](pvac_commit.txt) and [`manifest.json`](manifest.json). Because the links are pinned to that commit rather than to a branch, they keep resolving to the exact tree that produced `secret.ct`.

Check `C8` in [`solution/verify.py`](solution/verify.py) enforces this: it reads the pin from the manifest, confirms `pvac_commit.txt` agrees, and fails if the docs ever cite a moving branch instead of that commit.

## Why it is information-theoretically hidden, not merely hard

Every cipher is a wrapped pair: layer 0 holds `v + m`, layer 1 holds `−m`, where `m = ` [`rand_fp_nonzero()`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/types.hpp#L209) is secret. Since each layer publishes `T_i = R_i · u_i` and nothing else, for **any** candidate plaintext `v` and **any** mask `m` you choose:

```
R_0 = T_0 · (v+m)⁻¹        R_1 = T_1 · (−m)⁻¹
```

reproduces the published `(T_0, T_1)` exactly. [`solution/verify.py`](solution/verify.py) executes that witness:

| test | result |
| :--- | :--- |
| cipher 0 is the length carrier, so `v ∈ [1,315]` | **315/315** candidate lengths fit, five unrelated masks |
| an arbitrary 15-byte ASCII block I invented | **21/21** block ciphers fit it exactly |

Algebraically: `R` is uniform over `F_p*`, so `T = R·v` is uniform over `F_p*` for every nonzero `v`. The distribution of `T` is *identical* for all plaintexts — the wire publishes no function of the plaintext at all.

## What was measured and killed

| candidate handle | outcome |
| :--- | :--- |
| [`R_com`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/types.hpp#L95) offline guess oracle (the v1 bug) | absent from the wire; the parser consumes exactly `len(blob)` bytes |
| Pedersen [`PC = R⁻¹·G + ρ·H`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/ristretto255.hpp#L754) | `ρ` is a full 252-bit blind — perfectly hiding; and the group order is prime, so "is `PC − guess·G` a valid point" is vacuous |
| zero plaintext → zero aggregate | closed by [`enc_fp_wrapped_depth`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L981); all 44 aggregates are nonzero |
| `R²` from an opposite-sign edge pair | 0 hits; the cipher-0 length window gives 0 hits at ~10⁶ candidates |
| mask reuse across ciphers or layers | 44 distinct seeds, 44 distinct `PC`, 44 distinct `T`; four independent reuse tests negative |
| degenerate build (`R = 1`, `T ∈ ⟨g⟩`) | 0/44 aggregates lie in the order-337 subgroup |
| `T` leaking through a small multiple | the same length window is the only high-signal discriminator, and it stays quiet |

Deeper measurements — the LPN noise census, the [`prf_k`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L87) consumer sweep, the [`sigma`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/matrix.hpp#L298)/[`PC`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/types.hpp#L96) call-site audit — are recorded in [`solution/RESULT.md`](solution/RESULT.md).

## The LPN side target is a separate prize

`lpn_samples/` publishes the complete `y = ⟨A, S⟩ ⊕ e` instance for all 44 BASE layers (`n = 4096`, `t = 16384`, `τ = 1/8`), including the entire `A` matrix.

- The noise is genuine: streaming GF(2) elimination gives **rank 4096 with 6,133/16,384 (37.4%) inconsistent rows** — the signature of real LPN noise. Gaussian elimination does not recover `S`.
- The instance sits above the decoding threshold (`t = 16384` vs `n·H(τ) ≈ 2226`, 7.4×), but decoding a random `[16384, 4096]` code at `δ = 1/8` costs Prange ≈ `(7/8)⁻⁴⁰⁹⁶ ≈ 2⁷⁸⁹`; BKW's correlation decays as `0.75^(2^a)`, so folding destroys the signal.
- **Even full recovery of `S` would not yield `R`.** [`S`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L151) is generated independently of [`prf_k`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L87), and [`prf_R_core`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/lpn.hpp#L376) additionally needs `top` from [`derive_aes_key(…, Dom::TOEP, …)`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/lpn.hpp#L307), which absorbs [`prf_k`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/keygen.hpp#L87). `dom` enters the AES **key** ([lpn.hpp:331](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/lpn.hpp#L331)), so the published `A` rows and the Toeplitz stream are different keys.

## Provenance

| item | value |
| :--- | :--- |
| pinned engine commit | [`071b0e909c119de815e284b347c4bd979cb59ef3`](https://github.com/octra-labs/pvac_hfhe_cpp/tree/071b0e909c119de815e284b347c4bd979cb59ef3) |
| `pk.bin` | 3,042,901 B compressed → 17,110,454 B raw |
| `canon_tag` | `0x0760802093a19931` |
| `H_digest` | `601435f4977dd2a0c396bd96c7947fb884b602a52b6d7e0660b3fce3508497f5` |
| params | B=337, m=8192, n=16384, h_col_wt=192, x_col_wt=128, err_wt=128, noise_entropy_bits=128, tuple2_fraction=0.55, depth_slope_bits=16, lpn 4096/16384, τ=1/8 |

The artifact is faithful to the pinned source: edge counts track the entropy budget `2·(8 + 2q₂ + 3q₃)` from [`struct Budget`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/ops/encrypt.hpp#L199) for depth hints `d = 0..22` with deltas in `[-5, 0]` (the merge/permute collapse), and all 44 `ztag` values recompute from public data via [`prg_layer_ztag`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/matrix.hpp#L286) with 0/44 mismatches.

Two provenance oddities, neither exploitable: the shipped generator [hardcodes `"status": "pre-release"`](source/hfhe_bounty_artifact.cpp#L304) while the published [`manifest.json`](manifest.json) says `"active"`; and [`compute_R_com_base`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/hash.hpp#L198) hashes [`R_slots.size()`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/hash.hpp#L210) without ever reading a slot, so even a future release that republished [`R_com`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/types.hpp#L95) would hand over a hash of the slot *count*. That is a soundness defect, not a confidentiality one — as are the unverified per-edge [`sigma`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/crypto/matrix.hpp#L298) and the never-opened Pedersen [`PC`](https://github.com/octra-labs/pvac_hfhe_cpp/blob/071b0e909c119de815e284b347c4bd979cb59ef3/include/pvac/core/types.hpp#L96).

## Files

Everything under [`solution/`](solution/) is fork work; nothing above it was added to the package.

| path | contents |
| :--- | :--- |
| [`solution/verify.py`](solution/verify.py) | the whole finding as 34 re-runnable checks |
| [`solution/RESULT.md`](solution/RESULT.md) | the written analysis: wire shape, the hiding witness, every killed handle, the LPN bound |
| [`solution/parse.py`](solution/parse.py) | PVAC v0x03 container parser (stdlib only) |
| [`solution/rist.py`](solution/rist.py) | pure-Python Ristretto255 (stdlib only) |
| [`solution/README.upstream.md`](solution/README.upstream.md) | the upstream README body, pinned so this file's preservation of it stays checkable |
| [`solution/commit_msg_guard.py`](solution/commit_msg_guard.py) | commit-message guard: names issues in words, never in reference syntax |

`solution/verify.py` needs nothing beyond the Python standard library and the artifacts at the repository root. The engine source the analysis cites is not vendored here; the citations are line-anchored links to a fixed upstream commit, so they stay resolvable without carrying a copy of someone else's code.

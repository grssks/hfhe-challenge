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
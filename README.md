# Morse enclave

This is the source of the image that runs Morse's AWS Nitro enclave. The enclave holds the worker that opens sealed requests, calls the model vendor, and seals the reply. Morse's relay sits between your app and the enclave. It cannot read a sealed request.

Morse exports this code from its private monorepo on each release. The export holds exactly the files the image build reads, so rebuilding it gives the image Morse runs. You can check that yourself.

## How this repository is published

Morse publishes this repository from its private monorepo. Each commit here is one image Morse pinned for production. A bot makes the commit when the deploy pins the image, and the commit message lists the image's PCR0, PCR1, and PCR2. The bot tags the commit with the release, such as `v2026.10.1`. An image rebuilt with newer pins for the same release gets its own tag, such as `v2026.10.5-pins-6ab5d36`. Morse does not publish its day-to-day commits.

The first release here is `v2026.10.1`. [morse-pins](https://github.com/trymorse/morse-pins) also lists older prod images, `v0.6.26` to `v0.6.34`, that ran before Morse published this source. This repository has no source for them. An entry marked `revoked: true` is an image the app no longer accepts. If Morse revoked an image before it deployed, its tag may be missing here too.

This repository does not take pull requests. To report a bug, open an issue. To report a security problem, follow `SECURITY.md`.

## What is here

- `cmd/worker` is the worker that runs inside the enclave.
- `cmd/enclave` starts the worker with the credentials the host passes in, and drops every other setting.
- `internal/` holds the packages those two programs use, with their tests where the tests need nothing outside this repo.
- `routes.json` lists the vendors and models the worker may call.
- `internal/attestation/*_pins.json` holds the pins for the vendor enclaves the worker checks. They are part of the image.
- `check-enclave.py` checks the enclaves Morse runs right now. See [Check the running enclave](#check-the-running-enclave).
- `deploy/enclave/build.sh` builds the image. `deploy/enclave/prod.env` and `dev.env` are the image settings for each environment. `deploy/enclave/veil-commit` names the version of [veil](https://github.com/Amnesic-Systems/veil) that serves the attestation document.

## Services the enclave calls

The worker calls these services.

Model and media vendors:

- Anthropic, `api.anthropic.com`
- fal, `queue.fal.run`
- Google, `generativelanguage.googleapis.com`
- Meta, `api.meta.ai`
- NEAR AI, `cloud-api.near.ai`
- OpenAI, `api.openai.com`
- OpenRouter, `openrouter.ai`
- Parallel, `api.parallel.ai`
- Phala, `inference.phala.com`
- Runware, `api.runware.ai`
- Together AI, `api.together.xyz`
- Venice, `api.venice.ai`
- xAI, `api.x.ai`

Lookup tools:

- Wikipedia, `en.wikipedia.org`
- Photon by komoot, `photon.komoot.io`
- MET Norway, `api.met.no`
- Frankfurter, `api.frankfurter.dev`
- CoinGecko, `api.coingecko.com` and `pro-api.coingecko.com`
- OpenAlex, `api.openalex.org`

Attestation checks for the NEAR AI and Phala enclaves:

- NVIDIA's attestation service, `nras.attestation.nvidia.com`
- Intel's Provisioning Certification Service, for TDX collateral

## What is not here

The relay, accounts, payments, and the rest of Morse's servers are not in this repo. None of them run in the enclave. The relay does not have the key that opens a sealed request, so it can pass the request along but cannot read it.

Only the enclave can read a request and its reply, so the enclave counts the tokens each request uses and reports that usage, priced at the vendor's list price in `routes.json`. It does not hold account balances, plan prices, or what Morse charges.

## Rebuild the image

You need an arm64 Linux machine with Docker, `jq`, and `sha256sum`. The Nitro CLI step takes its kernel from the machine's own architecture, so an x86 machine cannot build the image.

1. Check out the tag of the release you want to compare.
2. Make a tar of the source. It must be this repo's files and nothing else:

   ```sh
   git archive --format=tar -o /tmp/src.tar HEAD
   ```

3. Build the image. `<environment>` is `prod` or `dev`. The version string is not part of the image, so any value works:

   ```sh
   deploy/enclave/build.sh eif /tmp/src.tar rebuild <environment> /tmp/out
   ```

4. Read the measurements:

   ```sh
   jq .Measurements /tmp/out/measurements.json
   ```

5. Open `enclave_pins.json` in [morse-pins](https://github.com/trymorse/morse-pins). Find the entry whose `tag` is the tag you checked out. Its `pcr0`, `pcr1`, and `pcr2` must equal the ones you built, and the tag's commit message here lists the same three.

The app refuses an enclave whose attestation document does not carry PCRs from that file. If your PCRs match, this source builds the image Morse runs.

To check only the build's root filesystem, run `build.sh rootfs` instead of `eif`. It stops after writing `/tmp/out/rootfs.sha256` and works on any machine with Docker. Compare that hash with the `rootfs sha256` line in the tag's commit message. Older tags have no such line. A match shows this source gives the files the image runs. Only the PCRs show the kernel and init that `nitro-cli` adds.

## Check the running enclave

A rebuild shows what this source builds. To see what Morse runs right now, ask the enclave. `GET https://api.trymorse.ai/v1/attestation` needs no account. It returns one attestation document per running enclave. AWS's Nitro hardware signs each one, and each one carries the PCRs of the image it runs.

`check-enclave.py` checks each document the way the app does. It needs [uv](https://docs.astral.sh/uv/):

```sh
uv run check-enclave.py
```

For each enclave, the script checks that the document's certificate chain ends at AWS's Nitro root certificate, as [Verifying the root of trust](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html) describes. It checks that the signature verifies and that the document is under 30 minutes old. Then it looks the PCRs up among the `prod` entries of `enclave_pins.json` in morse-pins. It prints each enclave's PCRs and the tag here whose source the enclave runs. It exits 1 if any enclave fails a check, or runs an image that morse-pins does not list for prod or marks revoked.

The document's `user_data` holds the public key the app seals requests to. The enclave makes that key when it starts and refuses one from outside (`internal/nitro/key.go`), so only an enclave with those PCRs can open a sealed request.

## License

Copyright (C) 2026 Morse

This code is under the GNU Affero General Public License v3.0. See `LICENSE`. The tokenizer files in `internal/tokenizer/data` come from others and keep their own licenses. See `THIRD_PARTY_NOTICES.md`.

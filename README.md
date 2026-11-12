# Morse enclave

[![License: AGPL-3.0](https://img.shields.io/github/license/trymorse/morse-enclave)](LICENSE)
[![CodeQL](https://github.com/trymorse/morse-enclave/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/trymorse/morse-enclave/actions/workflows/github-code-scanning/codeql)

Quick check: `npx @askmorse/verify` checks the enclaves serving Morse's API against this source and the pins in [morse-pins](https://github.com/trymorse/morse-pins). [morse-verifier](https://github.com/trymorse/morse-verifier) says what it checks and how, and lists its releases if you want to pin one.

This is the source of the image that runs Morse's AWS Nitro enclave. The enclave holds the worker that opens sealed requests, calls the model vendor, and seals the reply. Morse's relay passes requests between your app and the enclave, and cannot read a sealed one.

Morse exports this code from its private monorepo on each release. The export holds exactly the files the image build reads, so rebuilding it gives the image Morse runs. The sections below show how to check that.

## How this repository is published

Each commit here is one image Morse pinned for production. A bot makes the commit when the deploy pins the image, and the commit message lists the image's PCR0, PCR1, and PCR2. The bot tags the commit with the release, such as `v2026.10.1`. Newer tags also get a GitHub Release that lists the same PCRs. The earliest tags have no Release, and carry the PCRs only in their commit message. An image rebuilt with newer pins for the same release gets its own tag, such as `v2026.10.5-pins-6ab5d36`. Morse does not publish its day-to-day commits.

The first release here is `v2026.10.1`. [morse-pins](https://github.com/trymorse/morse-pins) also lists older prod images, `v0.6.26` to `v0.6.34`, that ran before Morse published this source. This repository has no source for them. An entry marked `revoked: true` is an image the app no longer accepts. If Morse revoked an image before it deployed, its tag may be missing here too.

This repository does not take pull requests. To report a bug, open an issue. To report a security problem, follow `SECURITY.md`. `CONTRIBUTING.md` says more.

## What is here

- `cmd/worker` is the worker that runs inside the enclave.
- `cmd/enclave` starts the worker with the credentials the host passes in, and drops every other setting.
- `internal/` holds the packages those two programs use, with their tests where the tests need nothing outside this repo.
- `routes.json` lists the vendors and models the worker may call.
- `internal/attestation/*_pins.json` holds the pins for the vendor enclaves the worker checks. They are part of the image.
- `check-enclave.py` checks the enclaves Morse runs right now. See [Check the running enclave](#check-the-running-enclave).
- `check-door.py` checks that every certificate for `inference.trymorse.ai` holds a key whose boot record a pinned prod enclave logged in Sigstore's Rekor. See [Watch the door](#watch-the-door). `rekor.py` holds its Rekor v2 verification, `revocation.py` its OCSP and CRL lookup, `signer_watch.py` its check 7 of the public image signer, and `signer.py` that check's verification of the signer's statements. `test_check_door.py`, `test_rekor.py` and `test_signer.py` test them, with the fixtures in `check_door_fixtures.py`.
- `deploy/enclave/build.sh` builds the image. `deploy/enclave/prod.env` and `dev.env` are the image settings for each environment. `deploy/enclave/veil-commit` names the version of [veil](https://github.com/Amnesic-Systems/veil) that serves the attestation document.

## Services the enclave calls

The worker calls these services.

Model and media vendors that serve the developer API, and the Morse Chat app too:

- DeepInfra, `api.deepinfra.com`
- Isoquant, `api.isoquant.ai`
- Morph, `api.morphllm.com`
- NEAR AI, `cloud-api.near.ai`
- Novita AI, `api.novita.ai`
- Phala, `inference.phala.com`
- Tinfoil, `inference.tinfoil.sh`
- Tinfoil's privacy filter, `pii-filter.tinfoil.sh`, which reads the text of a chat that asks for the Privacy Veil, over TLS pinned to the key its attested report binds
- Wafer, `pass.wafer.ai`

Model and media vendors that only the Morse Chat app reaches. An API key cannot list or call their models:

- Anthropic, `api.anthropic.com`
- fal, `queue.fal.run`
- Google, `generativelanguage.googleapis.com`
- Meta, `api.meta.ai`
- OpenAI, `api.openai.com`
- Parallel, `api.parallel.ai`
- Runware, `api.runware.ai`
- Venice, `api.venice.ai`
- xAI, `api.x.ai`

Lookup tools:

- Wikipedia, `en.wikipedia.org`
- Photon by komoot, `photon.komoot.io`
- MET Norway, `api.met.no`
- Frankfurter, `api.frankfurter.dev`
- CoinGecko, `api.coingecko.com` and `pro-api.coingecko.com`
- OpenAlex, `api.openalex.org`

Attestation checks for the NEAR AI, Phala and Tinfoil enclaves:

- NVIDIA's attestation service, `nras.attestation.nvidia.com`
- Intel's Provisioning Certification Service, for TDX collateral
- AMD's Key Distribution Service, `kdsintf.amd.com`, for the VCEK that signs a Tinfoil router's SEV-SNP report

## What is not here

The relay, accounts, payments, and the rest of Morse's servers are not in this repo. None of them run in the enclave. The relay does not have the key that opens a sealed request, so it can pass the request along but cannot read it.

Only the enclave can read a request and its reply, so the enclave counts the tokens each request uses and reports that usage. The relay prices it. What each host charges Morse is in `relay.json`, a file the relay alone holds, and `routes.json` carries no cost. The enclave does not hold account balances, plan prices, or what Morse charges.

## Rebuild the image

You need an arm64 or x86_64 Linux machine with Docker and `jq`. The image is arm64. The Nitro CLI step takes its kernel from its own architecture, so on x86_64 `build.sh` takes the arm64 kernel from the arm64 package of the same Nitro CLI release, checks that package's SHA-256, and builds for arm64. Either machine builds the same PCRs. An older release's `deploy/enclave/build.sh` has no `amazonlinux_amd64=` line and builds only on arm64. To build one on x86_64, first turn on arm64 emulation with `docker run --privileged --rm tonistiigi/binfmt --install arm64`. The build is then slower.

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

## Watch the door

`inference.trymorse.ai` is a door that ends TLS inside the enclave. Before a boot serves on a TLS key, it logs a record of that key in Rekor v2, Sigstore's public transparency log: a `hashedrekord` entry whose certificate carries the boot's Nitro attestation document. The document attests the TLS key, the boot's HPKE key and the key's origin. A boot that cannot log its record never serves. `check-door.py` checks from outside that no certificate for the door's name holds a key without such a record.

Rekor v2 cannot be searched, so Morse lists the entries it logs in [trymorse/morse-records](https://github.com/trymorse/morse-records). `prod.jsonl` holds one pointer a line, `{"log": …, "index": …, "spki_sha256": …, "boot": …}`, and `leaves/<log>/<index>.json` holds a copy of each entry for the day a shard stops serving it. A pointer is only a hint. The watcher verifies the entry it names, prints a note for one that does not verify, and counts only those that do. Morse has not made morse-records public yet, and check 9 fails until it does.

For each entry the watcher checks:

- the entry's inclusion in a checkpoint that the shard signed, with the shard's key from Sigstore's TUF repository, walked forward from the root the door's image embeds (`TUF_ROOT_SHA256`);
- that at least `WITNESS_K` operators of the witnesses in `WITNESSES` cosigned that checkpoint;
- the record in the entry's certificate. The certificate's signature proves nothing and is not checked. The record's Nitro document must verify under AWS's root at the document's own time, carry the PCRs of an image that `enclave_pins.json` in morse-pins listed unrevoked for prod at that time, attest the P-256 TLS key that the record and the entry's digest name, and carry a nonce that attests the record's origin.

`CHECKS` in the script lists what it then checks: every certificate in Certificate Transparency for the name has a verified record within 20 minutes of being logged, and was issued before its key was 60 days old, unless its CA revoked it; the custody of each key ends at a key born in an enclave, with a floor that never falls; each shard's tree only grows, by a consistency proof from the checkpoint the last run accepted; the histories of morse-pins and morse-records only grow; CAA names only Morse's ACME accounts; every boot `/v1/attestation` lists has a verified record within 2 hours; no listed witness has missed a checkpoint of a shard still in service for 24 hours and no unknown one cosigns; and the newest pinned image's `internal/door/trust.go` here lists no witness `WITNESSES` does not, and no smaller k. The witness list is the script's own on purpose, so one change to this repository cannot relax both the enclave and the watcher. When check 8 fails on a new witness, read the change before you add it.

Check 1 asks a failing certificate's OCSP responder, then its CRL, and accepts an answer only when it verifies against the issuer that signed the certificate. It lists a revoked certificate as `revoked, skipped` and does not fail it. It still fails one whose revocation it cannot read, or that its CA holds and may release, and says why. A client that does not check revocation still accepts a revoked certificate, so a `revoked, skipped` line names a certificate that could have served the name.

Check 7 watches the public image signer, `.github/workflows/sign.yml` in morse-pins, whose statements decide which images a door hands its keys to. Every statement ever added to the `statements/images` branch must verify as the enclave verifies it: a Rekor v2 entry with `WITNESS_K` cosignatures, a Fulcio certificate issued to `sign.yml` on `main` of morse-pins in the first attempt of a push or schedule run, at the commit the statement names. That commit must be on `main`, and the statement must say exactly what `enclave_pins.json`, or the vendor pins files, at that commit give, with its commit count as its sequence. GitHub's activity API must list every push to `main` since `sign.yml` was added, each starting where the last ended: data pushed by `morse-pins-publisher[bot]`, which never changes `.github/`, or a pull request an admin merged, which never changes a file the signer signs. Every commit's `.github/` tree must be one `SIGNER_TREES` names, and no `sign.yml` run number may be missing, since a deleted run leaves a gap. When check 7 fails on a new `.github/` tree, read the change to the signer's code, then pass `--signer-tree <tree>` to allow it. A refused push, a push that does not start where the last ended, a refused `sign.yml` run, or a missing run number fails every run. To clear a refused push once you have read it, pass `--ack-refused <sha>` once, with the commit the push ends at, which the failure names. To clear a refused or missing run, pass `--ack-run <number>` once, with the run number the failure names. Each clears that push or run and no other. A run that has not completed stays pending, and check 7 judges it when it completes, or fails it as missing when it is deleted. A push the activity API has not yet listed is a note until this watcher has seen `main` unlisted for an hour, and then it fails. A new watcher checks only the last 14 days on its first run: the pushes to `main` since the one 14 days back, while its state holds no `last_push`, and the `sign.yml` runs created since then, while it holds no time of its last runs read, so the runs before them do not count as missing. When that first run cannot read the activity, or lists no run in the window, the next run starts that part afresh. Later runs carry on from where it stopped: the state file keeps the id and time of the last push event on `main` that check 7 judged, as `last_push`, and each run reads the activity newest first back to that event, then judges the newer pushes oldest first, even when `main` is back where it was. If the activity no longer lists that event, check 7 fails and keeps its state. Check 7 keeps no tip of its own: `tips["morse-pins"]` is check 2's. Check 7 reads GitHub's API with no token, at most two requests a run once it has caught up, and uses `GH_TOKEN` when it is set. It is not enforced on a run that cannot reach the API.

It needs [uv](https://docs.astral.sh/uv/) and full clones of the three repositories:

```sh
git clone https://github.com/trymorse/morse-pins
git clone https://github.com/trymorse/morse-records
git clone https://github.com/trymorse/morse-enclave
uv run check-door.py --pins morse-pins --records morse-records --enclave morse-enclave \
  --caa-history caa.jsonl --sequence-state state.json \
  --caa-account letsencrypt.org=<account URI> --caa-account pki.goog=<account URI>
```

Take the two account URIs from the CAA record of `inference.trymorse.ai` the first time. Each later run fails if a CAA sample names any other. Pull the three clones and run the script at least every 5 minutes, and keep `state.json`, `caa.jsonl` and the `state.json.cache` directory between runs. The state holds each shard's last accepted checkpoint, the commits each repository's `main` was at, every boot seen live, and for check 7 where it stopped in the activity of morse-pins `main`, the highest `sign.yml` run number judged and when the runs were last read, the runs still pending and the refused or missing runs not yet acknowledged, the statements already verified, the refused pushes not yet acknowledged, and since when `main` has been unlisted. A clone or a pull of morse-pins fetches `statements/images` as `origin/statements/images`, which check 7 reads. Check 6 is enforced only on a run within 7 minutes of the last. The script reads CT from crt.sh and certspotter. When one of them cannot be read, check 1 prints a note naming it and the error and judges from the other; when neither can, the run cannot read its evidence. The script exits 0 when every check passes, 1 when one fails, and 2 when none fails but a check is not enforced.

## License

Copyright (C) 2026 Morse

This code is under the GNU Affero General Public License v3.0. See `LICENSE`. The tokenizer files in `internal/tokenizer/data` come from others and keep their own licenses. See `THIRD_PARTY_NOTICES.md`.

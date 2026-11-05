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
- `check-door.py` checks that every certificate for `inference.trymorse.ai` holds a key that a pinned prod enclave attests. See [Watch the door](#watch-the-door). `test_check_door.py` tests it.
- `deploy/enclave/build.sh` builds the image. `deploy/enclave/prod.env` and `dev.env` are the image settings for each environment. `deploy/enclave/veil-commit` names the version of [veil](https://github.com/Amnesic-Systems/veil) that serves the attestation document.

## Services the enclave calls

The worker calls these services.

Model and media vendors:

- Anthropic, `api.anthropic.com`
- fal, `queue.fal.run`
- Fireworks AI, `api.fireworks.ai`
- Google, `generativelanguage.googleapis.com`
- Meta, `api.meta.ai`
- NEAR AI, `cloud-api.near.ai`
- OpenAI, `api.openai.com`
- OpenRouter, `openrouter.ai`
- Parallel, `api.parallel.ai`
- Phala, `inference.phala.com`
- Runware, `api.runware.ai`
- Tinfoil, `inference.tinfoil.sh`
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

Attestation checks for the NEAR AI, Phala and Tinfoil enclaves:

- NVIDIA's attestation service, `nras.attestation.nvidia.com`
- Intel's Provisioning Certification Service, for TDX collateral
- AMD's Key Distribution Service, `kdsintf.amd.com`, for the VCEK that signs a Tinfoil router's SEV-SNP report

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

## Watch the door

`inference.trymorse.ai` ends TLS inside the enclave. The enclave makes its TLS key at boot and never lets it out. Each attestation document carries that key's SubjectPublicKeyInfo in its `public_key` field. When a boot first serves, Morse publishes a record of it in morse-pins under `records/prod/`. Anyone at Morse who wants to read prompts needs a certificate for the name with a key they hold. A public CA logs such a certificate in Certificate Transparency (CT), and `check-door.py` reports it.

Run it at least every 5 minutes from one persistent watcher, with a checkout of morse-pins, a file that keeps the CAA samples between runs, and a file that keeps the watcher's state between runs. Keep both files on storage that outlives the runner:

```sh
git clone https://github.com/trymorse/morse-pins
uv run check-door.py --pins morse-pins --caa-history caa.jsonl --sequence-state sequence.json \
  --caa-account letsencrypt.org=<account URI> --caa-account pki.goog=<account URI>
```

The script runs these checks. It exits 1 if any of them fails, or if it cannot read a source. It exits 2 if none fails but check 6 is not enforced, as on the first run of a new watcher, or a run more than 7 minutes after the last.

1. It reads every certificate in CT that names `inference.trymorse.ai`, or a wildcard that covers it such as `*.trymorse.ai`, from crt.sh and from Cert Spotter. If morse-pins has a record and a source returns no covering certificate, counted before `--since`, the check fails, because the door's own certificate is always in CT. A boot that orders a new certificate is in CT before its record is public, so a certificate whose key is the `public_key` of a document live now, from an image morse-pins lists unrevoked at the document's time, passes check 1 until 2 hours after this watcher first saw any boot with that key live. A certificate for a key that no boot this watcher saw live ever held gets no such time, and fails at once, as does every certificate on a run where check 6 is not enforced, and every certificate for a key held by a boot first seen on such a run. Check 6 still fails the new boot at once, because no record attests its `public_key`, so the watcher stays red until the record is public.
2. Each certificate needs a record whose document AWS's Nitro root signed. The chain is checked at the document's own time, because records are older than 30 minutes. The document's `user_data` must start with `morse-proxy-hpke-v1|prod|` and hold a 32-byte key. Its PCRs must be an unrevoked prod image in `enclave_pins.json` as that file stood at the document's own time, which the script reads from the git history of morse-pins, so a later revocation fails only the records made after it. The checkout needs its full history. The script walks the first-parent history of `enclave_pins.json` in git's order and dates each commit by its committer time, never its author time, so a revocation landed by a merge counts from the merge. When two commits share a second, the one git lists first, the newer, governs. The committer times must not rise as the walk goes back, and an image that one commit revokes must not be listed unrevoked by a later one. If either breaks, the run fails, because the history was back-dated or reordered. Its `public_key` must parse as a P-256 SubjectPublicKeyInfo whose SHA-256 is the certificate's. The record's own `spki_sha256` field is a label, and the script never reads it. The document's `nonce` must be the SHA-256 of the record's origin statement, `{"origin":{"born":<born>,"floor":<floor>,"from":<from>},"spki_sha256":<the SHA-256 of public_key>,"type":"morse-door-origin-v1"}`, with no spaces, the keys in that order, `born` in UTC with trailing zeros of its fraction dropped, as in `2026-11-04T17:12:03.12Z`, and `from` either null or the sender's key ID. The enclave signs its origin this way, so whoever publishes a record cannot choose its `origin`.
3. A key moves from one enclave to the next on a deploy. A record's `origin.from` names the HPKE key ID of the enclave that sent the key, the first 16 hex digits of the SHA-256 of the key in the sender's `user_data`. Each record's chain of senders must end at a record whose `from` is null, every link must pass check 2, and `origin.floor` must never fall along the chain. Each boot has one record, so two records that carry the same HPKE key ID fail, which includes one document published under two file names.
4. `records/prod/statements/<sequence>.json` holds the `morse-door-records-v1` statements, each mapping every record's file name to its SHA-256. The sequences must run from 1 with no gaps. No statement may drop or change a record that the one before it lists, and the latest must list every record file as it is. `--sequence-state` names a JSON file, `{"sequence": 2, "tip": "<commit>", "last_run": "<time>", "boots": {"<key ID>": {"first_seen": "<time or null>", "spki_sha256": "<hex>"}}}`, that holds the highest sequence any run has seen, the morse-pins commit it checked out, when the watcher last ran, and every boot it has seen live. Each run raises the sequence, and a checkout whose latest statement is lower fails, so a rollback of morse-pins between runs shows. The checkout's `HEAD` must also descend from the remembered commit, so a force-push that rewrites the history shows, and a failing run keeps the old commit. A missing file, or one without a `tip`, means a first run.
5. Each run adds the live CAA record of the name, or of the nearest parent that has one, to the history file. A DNS answer whose `Status` is neither 0 (no error) nor 3 (no such name) is a failed read. The run exits 1 and adds no sample. Every sample must have an `issue` property, and every `issue` and `issuewild` property must name one of the `--caa-account` accounts with `validationmethods=dns-01`, or be `;`.
6. Every document that `GET https://inference.trymorse.ai/v1/attestation` returns must carry a `public_key` that a record attests, or the check fails at once. Each document's `timestamp`, which AWS's Nitro hardware signs, must be no more than 30 minutes before the run's clock, the same bound `check-enclave.py` uses, and no more than 2 minutes after it, or that document fails at once. The backend's verifier allows 5 minutes ahead (`MaxAhead`), because a client's clock may be loose. A watcher runs on a server that keeps its clock, so 2 minutes ties its clock to AWS's twice as tightly: a watcher clock running at half speed fails at the first refresh, 10 minutes in, where 5 minutes would let it pass until 20. The run reads its clock and the attestation when it starts, before it reads CT, so a slow CT read moves neither. The relay asks each enclave for a new document every 10 minutes, so a live document stays well under 30 minutes old. A relay lists another instance's document only while it is under 25 minutes old, so an instance that died without unlisting itself drops out before its document reads as stale here. The relay's own document stays listed however old it grows, so a serving boot whose relay cannot refresh its document fails. The two bounds tie the watcher's clock to AWS's. A watcher clock that stops, runs slow, or steps back falls behind the newest document and fails within one refresh, so it cannot keep a boot inside its 2 hours. A document made before its image was revoked cannot keep passing while the image keeps serving. A stale document, or one ahead of the clock, adds no boot to the state file and gives its key no time under check 1. Every boot the watcher has seen live must have a record that carries the HPKE key in its `user_data`. A boot that took the key from a recorded sender shares that sender's `public_key`, so only its HPKE key shows that its own record is missing, and no other check sees it. Each run adds each live boot to the `--sequence-state` file and never removes one. It dates a boot it has not seen before to the file's `last_run`, the last time the watcher looked and did not see it, not to the run that first saw it. A boot's record reaches the public copy only after its record pull request, a signed statement and its pull request, and a publish run, so a boot with no record whose `public_key` a record attests passes until 2 hours after that date. From then on it fails on every run, whether or not it is still live, until its record is public. A boot with no record whose `public_key` no record attests fails at once. A live document whose PCRs are not an unrevoked prod image in `enclave_pins.json` at the document's own time, such as a debug-mode enclave with zero PCRs or a revoked image, fails at once with its own line, `is from an image no record can admit`, whatever its key, and its key gets no time under check 1.

   Check 6 sees only the boots that are live when the watcher samples, so it needs one persistent watcher that samples at least every 5 minutes. A boot that serves for less time than the gap between samples can serve without a record and never show.

   Check 6 trusts the state file to have been written by this watcher's own runs, and it is built so that a copy of the file that is older than the last run, as a cache restore or a backup gives, cannot restart any boot's 2 hours:

   - A boot that the restored copy does not hold is dated to that copy's `last_run`, which is earlier than the run that first saw the boot, so it gets less time, never more.
   - A run more than 7 minutes after the file's `last_run` reports check 6 as not enforced and exits 2 if nothing else fails, because a boot that served only in the gap cannot show. The 7 minutes are the 5-minute sampling and 2 minutes for a run that starts late. A restored copy older than 7 minutes shows this way. A restored copy younger than that is the same as one run that did not happen, and a boot it forgets had served for less than 7 minutes.
   - A file that is missing, or has no `last_run` (main's format, or `{"boots": {}}`), cannot date anything. The run reports check 6 as not enforced, exits 2 if nothing else fails, and writes each live boot with `first_seen` null. A null boot gets no 2 hours, so it fails on that run and every later run until its record is public, and its key gets no time under check 1.
   - A run whose clock reads more than 2 minutes before the file's `last_run` fails, because a clock that goes backwards stretches the 2 hours. A boot that run sees for the first time is written with `first_seen` null. A `first_seen` more than 2 minutes after the run's clock, written by a run whose clock was fast, is read as null too.

   Each run writes its own time as `last_run`. A state file that does not parse, or holds a time with no zone, fails the run and is left as it is. A restored copy also holds an older `sequence` and `tip`, so check 4 then catches only a rollback or rewrite of what that copy saw. Anyone who can write the file can still forge it, so keep it where only the watcher writes.

   Check 6 means something only from a watcher whose state file Morse cannot write. Anyone who can write the file can delete a boot from it, or move its `last_run`, and a boot with no record then never fails. The check also sees only the boots in the `instances` list of `/v1/attestation`, and the relay builds that list from its own Postgres table of instances, which Morse controls. A boot the relay leaves out of the list never shows in check 6.

   The scheduled watcher (DOOR.md PR 8) must treat exit 2 as red, the same as exit 1, and never as a notice. It must keep the state file on storage that only it writes and that is never restored from an older copy, so not in `actions/cache`, whose restore keys hand a run an older copy. It must run every 5 minutes and start each run on time, because a run more than 7 minutes after the last is red. GitHub documents that a `schedule` run can start late when Actions is busy, so a GitHub Actions schedule alone cannot keep that time.

`--ct` takes `crt.sh`, `certspotter`, or a file of Cert Spotter issuances, and `--attestation` takes a file in place of the URL. `--since` skips certificates that expired before a date.

## License

Copyright (C) 2026 Morse

This code is under the GNU Affero General Public License v3.0. See `LICENSE`. The tokenizer files in `internal/tokenizer/data` come from others and keep their own licenses. See `THIRD_PARTY_NOTICES.md`.

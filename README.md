# Morse enclave

[![License: AGPL-3.0](https://img.shields.io/github/license/trymorse/morse-enclave)](LICENSE)
[![CodeQL](https://github.com/trymorse/morse-enclave/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/trymorse/morse-enclave/actions/workflows/github-code-scanning/codeql)

This is the source of the AWS Nitro enclave that runs Morse's worker. The worker reads each request, calls the model vendor, and returns the reply. Morse's other servers cannot read a prompt or a reply. The Morse web app seals each request to the enclave's key. An API key calls `https://inference.trymorse.ai/v1`, where TLS ends inside the enclave, and `api.trymorse.ai` refuses `sk_` keys. The [limits](#limits) say what this does not cover.

For a quick check, run `npx @askmorse/verify`. It checks the enclaves serving Morse's API against this source and the pins in [morse-pins](https://github.com/trymorse/morse-pins). [morse-verifier](https://github.com/trymorse/morse-verifier) says what it checks and how, and lists its releases if you want to pin one.

Each commit here is one image Morse pinned for production. [`VERIFY.md`](VERIFY.md) says how releases are tagged and published.

The relay, accounts, and payments are not here and do not run in the enclave. The enclave counts the tokens each request uses. The relay prices them from `relay.json`, which only it holds, and the enclave holds no balances or prices. `routes.json` lists the vendors and models the worker may call and carries no cost.

This repository does not take pull requests. To report a bug, open an issue. To report a security problem, follow `SECURITY.md`. `CONTRIBUTING.md` says more.

## Limits

- **Metadata.** The host and the relay see which account or `sk_` key calls, the caller's IP address, when it called, the model and vendor, the token counts, the request and reply sizes to the nearest 1 KiB, the reply's timing, and the character a chat names.
- **Plain API calls.** No client check guards a plain request's connection. To read one, Morse would need another certificate for `inference.trymorse.ai`. A certificate from a CA that logs appears in the public logs that [Watch the door](#watch-the-door) checks.
- **Vendors outside an enclave.** Only NEAR AI, Phala and Tinfoil models run in enclaves the worker checks. Every other model and media vendor in [`SERVICES.md`](SERVICES.md) reads the request and writes the reply in plain text, under Morse's account, and keeps both under its own terms.
- **The Privacy Veil.** Tinfoil's filter reads the chat's text, in an enclave the worker checks. Detection is best-effort, and images, audio and files go to the vendor as written.
- **Plugins.** Each plugin vendor in `SERVICES.md` sees the user's account and what the worker sends it.
- **Character framing.** The relay picks a chat's character prompt and the hashes the worker checks it against, so it could add system text, or the character writer's example turns, to a sealed chat. Receipts would not show it. Binding the character inside the seal is planned.
- **The JavaScript Morse serves.** The web app's check runs in code Morse serves, and a different build could skip it. Run `npx @askmorse/verify` yourself.
- **Pin changes.** Every check here trusts the images morse-pins lists. No second person reviews a change to that list. Morse's changes go through a pull request that must pass automated checks. Only Morse's publisher app pushes image approvals to its main branch. Changes to the signing code land only as pull requests an admin merges, and the watcher checks both.

## What is here

- `cmd/worker` is the worker. `cmd/enclave` starts it with the credentials the host passes in, and drops every other setting. `internal/` holds their packages and the tests that need nothing outside this repo.
- `internal/attestation/*_pins.json` pins the vendor enclaves the worker checks, as part of the image.
- `check-enclave.py` checks the running enclaves. `check-door.py` watches the door, with `rekor.py`, `revocation.py`, `signer_watch.py`, `signer.py`, their tests, and `check_door_fixtures.py`.
- `deploy/enclave/build.sh` builds the image, from `prod.env` or `dev.env`. `deploy/enclave/veil-commit` names the version of [veil](https://github.com/Amnesic-Systems/veil) that serves the attestation document.
- [`SERVICES.md`](SERVICES.md) lists every service the worker calls.

## Rebuild the image

On an arm64 or x86_64 Linux machine with Docker and `jq`, check out a release tag, then:

```sh
git archive --format=tar -o /tmp/src.tar HEAD
deploy/enclave/build.sh eif /tmp/src.tar rebuild prod /tmp/out
jq .Measurements /tmp/out/measurements.json
```

The PCRs must equal the `pcr0`, `pcr1`, and `pcr2` of the tag's entry in morse-pins' `enclave_pins.json`, and the app refuses an enclave whose PCRs that file does not list. The tag's commit message lists the same three. If they match, this source builds the image Morse runs.

[`VERIFY.md`](VERIFY.md) has notes on dev images, x86_64 builds, and the rootfs hash.

## Check the running enclave

With [uv](https://docs.astral.sh/uv/), check the attestation of each enclave serving Morse's API the way the app does:

```sh
uv run check-enclave.py
```

[`VERIFY.md`](VERIFY.md) says what it checks.

## Watch the door

Each boot logs its TLS key in Sigstore's Rekor v2 before it serves, and Morse lists those entries in [trymorse/morse-records](https://github.com/trymorse/morse-records). `check-door.py` checks that every certificate for `inference.trymorse.ai` holds a key whose record shows it was born in a pinned prod enclave. [`DOOR.md`](DOOR.md) has every check and how to keep its state. Run it at least every 5 minutes:

```sh
git clone https://github.com/trymorse/morse-pins
git clone https://github.com/trymorse/morse-records
git clone https://github.com/trymorse/morse-enclave
uv run check-door.py --pins morse-pins --records morse-records --enclave morse-enclave \
  --caa-history caa.jsonl --sequence-state state.json \
  --caa-account letsencrypt.org=<account URI> --caa-account pki.goog=<account URI>
```

## License

Copyright (C) 2026 Morse

This code is under the GNU Affero General Public License v3.0. See `LICENSE`. The tokenizer files in `internal/tokenizer/data` come from others and keep their own licenses. See `THIRD_PARTY_NOTICES.md`.

# Watch the door

`inference.trymorse.ai` is a door that ends TLS inside the enclave. Before a boot serves on a TLS key, it logs a record of that key in Rekor v2, Sigstore's public transparency log. The record is a `hashedrekord` entry whose certificate carries the boot's Nitro attestation document. The document attests the TLS key, the boot's HPKE key and the key's origin. A boot that cannot log its record never serves. `check-door.py` checks from outside that no certificate for the door's name holds a key without such a record.

Rekor v2 cannot be searched, so Morse lists the entries it logs in [trymorse/morse-records](https://github.com/trymorse/morse-records). `prod.jsonl` holds one pointer a line, `{"log": …, "index": …, "spki_sha256": …, "boot": …}`, and `leaves/<log>/<index>.json` holds a copy of each entry for the day a shard stops serving it. A pointer is only a hint. The watcher verifies the entry it names, prints a note for one that does not verify, and counts only those that do.

For each entry the watcher checks:

- the entry's inclusion in a checkpoint that the shard signed, with the shard's key from Sigstore's TUF repository, walked forward from the root the door's image embeds (`TUF_ROOT_SHA256`);
- that at least `WITNESS_K` operators of the witnesses in `WITNESSES` cosigned that checkpoint;
- the record in the entry's certificate. The watcher does not check the certificate's signature, which proves nothing. The record's Nitro document must verify under AWS's root at the document's own time, carry the PCRs of an image that `enclave_pins.json` in morse-pins listed unrevoked for prod at that time, attest the P-256 TLS key that the record and the entry's digest name, and carry a nonce that attests the record's origin.

`CHECKS` in the script lists what it then checks:

- Check 1: every certificate in Certificate Transparency for the name has a verified record within 20 minutes of being logged, and was issued before its key was 60 days old, unless its CA revoked it.
- Check 2: the histories of morse-pins and morse-records only grow.
- Check 3: the custody of each key ends at a key born in an enclave, with a floor that never falls.
- Check 4: each shard's tree only grows, by a consistency proof from the checkpoint the last run accepted.
- Check 5: CAA names only Morse's ACME accounts.
- Check 6: every boot `/v1/attestation` lists has a verified record within 2 hours. A boot that takes a handed key drops the key it was born with unlogged, so a born key it was listed holding before that take is a note, not a failure. Check 1 still fails any certificate for it.
- Check 7: the public image signer's statements, and every push to morse-pins `main` and `sign.yml` run, pass the rules below.
- Check 8: no listed witness has missed a checkpoint of a shard still in service for 24 hours, no unknown one cosigns, and the newest pinned image's `internal/door/trust.go` here lists no witness `WITNESSES` does not, and no smaller k.
- Check 9: morse-records is public. GitHub's API, read with no token, must call it public. A 404 or a plain 403 fails. A 403 that names a rate limit, or a 429 that still refuses after the usual retries of GitHub reads, makes the run print a note and not judge check 9.

Check 1 asks a failing certificate's OCSP responder, then its CRL, and accepts an answer only when it verifies against the issuer that signed the certificate. It lists a revoked certificate as `revoked, skipped` and does not fail it. It still fails one whose revocation it cannot read, or that its CA holds and may release, and says why. A client that does not check revocation still accepts a revoked certificate, so a `revoked, skipped` line names a certificate that could have served the name.

Check 7 watches the public image signer, `.github/workflows/sign.yml` in morse-pins, whose statements decide which images a door hands its keys to. Every statement ever added to the `statements/images` branch must verify as the enclave verifies it: a Rekor v2 entry with `WITNESS_K` cosignatures, and a Fulcio certificate issued to `sign.yml` on `main` of morse-pins in the first attempt of a push or schedule run, at the commit the statement names. That commit must be on `main`, and the statement must say exactly what `enclave_pins.json`, or the vendor pins files, at that commit give, with its commit count as its sequence. GitHub's activity API must list every push to `main` since `sign.yml` was added, each starting where the last ended: data pushed by `morse-pins-publisher[bot]`, which never changes `.github/`, or a pull request an admin merged, which never changes a file the signer signs. Every commit's `.github/` tree must be one `SIGNER_TREES` names, and no `sign.yml` run number may be missing, since a deleted run leaves a gap.

- A new `.github/` tree fails check 7. Read the change to the signer's code, then pass `--signer-tree <tree>` to allow it.
- A refused push, a push that does not start where the last ended, a refused `sign.yml` run, or a missing run number fails every run. Once you have read a refused push, pass `--ack-refused <sha>` once, with the commit the push ends at, which the failure names. For a refused or missing run, pass `--ack-run <number>` once, with the run number the failure names. Each clears that push or run and no other.
- A run that has not completed stays pending. Check 7 judges it when it completes, or fails it as missing when it is deleted.
- A push the activity API has not yet listed is a note until this watcher has seen `main` unlisted for an hour, and then it fails.

On its first run a new watcher checks only the last 14 days: the pushes to `main` since the one 14 days back, while its state holds no `last_push`, and the `sign.yml` runs created since then, while it holds no time of its last runs read, so the runs before them do not count as missing. When that first run cannot read the activity, or lists no run in the window, the next run starts that part afresh. Later runs carry on where it stopped. The state keeps the id and time of the last push event on `main` that check 7 judged, as `last_push`. Each run reads the activity newest first back to that event, then judges the newer pushes oldest first, even when `main` is back where it was. If the activity no longer lists that event, check 7 fails and keeps its state. Check 7 keeps no tip of its own: `tips["morse-pins"]` is check 2's. It reads GitHub's API with no token, at most two requests a run once it has caught up, and uses `GH_TOKEN` when it is set. It is not enforced on a run that cannot reach the API.

The witness list is the script's own on purpose, so one change to this repository cannot relax both the enclave and the watcher. When check 8 fails on a new witness, read the change before you add it.

It needs [uv](https://docs.astral.sh/uv/) and full clones of the three repositories:

```sh
git clone https://github.com/trymorse/morse-pins
git clone https://github.com/trymorse/morse-records
git clone https://github.com/trymorse/morse-enclave
uv run check-door.py --pins morse-pins --records morse-records --enclave morse-enclave \
  --caa-history caa.jsonl --sequence-state state.json \
  --caa-account letsencrypt.org=<account URI> --caa-account pki.goog=<account URI>
```

Take the two account URIs from the CAA record of `inference.trymorse.ai` the first time. Each later run fails if a CAA sample names any other. Pull the three clones and run the script at least every 5 minutes, and keep `state.json`, `caa.jsonl` and the `state.json.cache` directory between runs. The state holds each shard's last accepted checkpoint, the commits each repository's `main` was at, and every boot seen live. For check 7 it also holds where it stopped in the activity of morse-pins `main`, the highest `sign.yml` run number judged and when the runs were last read, the runs still pending, the refused or missing runs and refused pushes not yet acknowledged, the statements already verified, and since when `main` has been unlisted. A clone or a pull of morse-pins fetches `statements/images` as `origin/statements/images`, which check 7 reads. The watcher enforces check 6 only on a run within 7 minutes of the last. It reads CT from crt.sh and certspotter. When one of them cannot be read, check 1 prints a note naming it and the error and judges from the other. When neither can, the run cannot read its evidence. crt.sh sometimes answers with no certificate for the name while certspotter returns some, so the script reads crt.sh twice more, 2 and 5 seconds apart, and if it still has none, takes it as unread. The script exits 0 when every check passes, 1 when one fails, and 2 when none fails but a check is not enforced. With `--verdict verdict.json` it also writes that outcome as JSON: the kind of run (`passed`, `failed`, `unenforced`, or `unread` when it could not read its evidence), the exit code, whether a retry may read the evidence, the checks that failed and those not enforced, and each check's messages.

To run it on a schedule, `door_watch.py` wraps the command. It tries a run that could not read its evidence twice more, 20 seconds apart, keeps how many runs in a row ended the same way in `<state dir>/streak`, and with `--alerts` names the alert a run sends: a failed check at once, a run with no kept state at once, and the third run in a row that could not read its evidence or left a check unenforced. Morse's `door-watch` workflow runs it as `python3 door_watch.py --state door-state --alerts --restored <cache key> --run-url <url> --alert-body alert.md -- uv run check-door.py ...`.

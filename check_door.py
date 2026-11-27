"""Checks that every certificate for Morse's inference door holds a key whose boot record a pinned enclave logged in Rekor.

Usage: uv run check-door.py --pins <morse-pins checkout> --records <morse-records checkout> --enclave <morse-enclave checkout> --caa-history caa.jsonl --sequence-state state.json --caa-account <ca>=<account uri> ...

It reads Certificate Transparency for each --name (inference.trymorse.ai when none is given) and every wildcard that covers it, the enclave_pins.json
history in morse-pins, the pointers in morse-records, each entry a pointer names in Sigstore's Rekor v2, with the log
keys from Sigstore's TUF repository and the witnesses this script lists, each name's CAA record, the door's live
attestation, and for the public image signer the statements branch of morse-pins and GitHub's record of who pushed
its main and which sign.yml runs there were, and runs the checks listed in CHECKS below. GH_TOKEN, if set, raises
GitHub's limit of 60 API requests an hour. It exits 1 if any check fails, and 2 if none fails but a check is not
enforced. With --verdict it also writes that outcome as JSON, which door_watch.py reads.
"""

import argparse
import base64
import binascii
import hashlib
import http.client
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

import door_checks as checks
import door_records as records
import rekor
import revocation
import signer_watch
from check_enclave import Refused
from door_checks import Note
from door_git import descends, git
from github_read import rate_limited, read_github
from rekor import Refusal


NAME = checks.FIRST_NAME
CRTSH_URL = "https://crt.sh/?q=%25.{}&output=json"
CRTSH_CERT_URL = "https://crt.sh/?d={}"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={}&match_wildcards=true&expand=dns_names&expand=cert_der"
ATTESTATION_URL = "https://inference.trymorse.ai/v1/attestation"
DOH_URL = "https://dns.google/resolve?name={}&type=CAA"

TUF_URL = "https://tuf-repo-cdn.sigstore.dev"
TUF_ROOT = 16
TUF_ROOT_SHA256 = "27aea7e372aa7864065174f0661784fcf8b0e28b1dbfebeada31a0f1fb19167f"
TUF_FETCHER = None

WITNESS_K = 3
WITNESSES = [
    ("krabbel.ct.ipng.ch+4b10dbd8+BO4sLOtnhktlqMCejDx9C5LDd+/xZxbmBb6BP9ZD2Def", "IPng Networks"),
    ("staging.witness.transparency.goog/ring-any-bells+2e1a8dc9+BG5JTpLc3FJtwzgh1Uv+Qelz9qeOH2bfWjS1s0s+y4rL", "TrustFabric"),
    ("witness.stagemole.eu+67f7aea0+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv", "Mullvad VPN"),
    ("witness.navigli.sunlight.geomys.org+a3e00fe2+BNy/co4C1Hn1p+INwJrfUlgz7W55dSZReusH/GhUhJ/G", "Geomys"),
]

HEX16 = re.compile(r"[0-9a-f]{16}", re.ASCII)
HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)


@dataclass(frozen=True)
class Certificate:
    source: str
    names: list
    spki_sha256: str
    not_before: datetime
    not_after: datetime
    logged: datetime
    der: bytes = field(repr=False)


@dataclass(frozen=True)
class Pointer:
    log: str
    index: int
    spki_sha256: str
    boot: str

    def name(self):
        return f"{self.log}/{self.index}"


def utcnow():
    return datetime.now(timezone.utc)


def fetch(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "check-door"}), timeout=60) as reply:
        return reply.read()


def parse_certificate(source, der, logged):
    cert = x509.load_der_x509_certificate(der)
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    names += [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    try:
        scts = [s.timestamp.replace(tzinfo=timezone.utc) for s in cert.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps).value]
    except x509.ExtensionNotFound:
        scts = []
    when = min(scts) if scts else logged or cert.not_valid_before_utc
    return Certificate(source, list(dict.fromkeys(names)), records.spki_sha256(cert.public_key()), cert.not_valid_before_utc, cert.not_valid_after_utc, when, der)


def crtsh_time(row):
    try:
        return datetime.fromisoformat(row["entry_timestamp"]).replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError):
        return None


def read_ct(source, name):
    if source == "crt.sh":
        rows = json.loads(fetch(CRTSH_URL.format(name.split(".", 1)[1])))
        logged = {}
        for r in rows:
            if any(checks.covers(n, name) for n in r["name_value"].split("\n")):
                t = crtsh_time(r)
                logged[r["id"]] = min(t, logged[r["id"]]) if t and logged.get(r["id"]) else t or logged.get(r["id"])
        return [(f"crt.sh {i}", x509.load_pem_x509_certificate(fetch(CRTSH_CERT_URL.format(i))).public_bytes(serialization.Encoding.DER), logged[i]) for i in sorted(logged)]
    if source == "certspotter":
        entries, after = [], None
        while True:
            page = json.loads(fetch(CERTSPOTTER_URL.format(name) + (f"&after={after}" if after else "")))
            if not page:
                return entries
            entries += [(f"certspotter {i['id']}", base64.b64decode(i["cert_der"]), None) for i in page]
            after = page[-1]["id"]
    with open(source) as f:
        return [(f"{source} {i['id']}", base64.b64decode(i["cert_der"]), None) for i in json.load(f)]


CT_UNREAD = (OSError, http.client.HTTPException, json.JSONDecodeError)
# A source's answer that reads but does not hold the certificates it should, such as a DER or PEM that does not parse
# or an entry missing a field. Caught after CT_UNREAD, since json.JSONDecodeError is a ValueError.
CT_MALFORMED = (ValueError, KeyError, TypeError, AttributeError)
CRTSH_RETRY_DELAYS = (2, 5)


def read_parsed(source, name):
    return [(der, parse_certificate(label, der, logged)) for label, der, logged in read_ct(source, name)]


def covering(certs, name):
    return [(der, cert) for der, cert in certs if any(checks.covers(n, name) for n in cert.names)]


def reread_crtsh(name, read, unread):
    """crt.sh sometimes answers with none of the certificates another CT source returns, and has them again minutes
    later."""
    why = None
    for delay in CRTSH_RETRY_DELAYS:
        time.sleep(delay)
        try:
            again = read_parsed("crt.sh", name)
        except CT_UNREAD as e:
            why = e
            continue
        if covering(again, name):
            return again, None
        why = None
    if why is None:
        others = ", ".join(f"{s} returned {len(covering(c, name))}" for s, c in read.items() if covering(c, name))
        why = LookupError(f"it returned no certificate covering {name} in {len(CRTSH_RETRY_DELAYS) + 1} reads, " +
                          (f"though {others}" if others else f"and {', '.join(unread)} could not be read"))
    return [], why


def read_pins_history(pins_dir):
    commits = [line.split() for line in git(pins_dir, "log", "--first-parent", "--format=%H %ct", "--", "enclave_pins.json").splitlines()]
    times = [int(when) for _, when in commits]
    for newer, older in zip(times, times[1:]):
        if older > newer:
            raise Refused(f"the committer times in morse-pins' enclave_pins.json history are not in order: a commit dated {datetime.fromtimestamp(older, timezone.utc).isoformat()} sits below one dated {datetime.fromtimestamp(newer, timezone.utc).isoformat()}")
    history = [
        (datetime.fromtimestamp(when, timezone.utc), json.loads(git(pins_dir, "show", f"{sha}:enclave_pins.json")))
        for (sha, _), when in reversed(list(zip(commits, times)))
    ]
    revoked = set()
    for committed, pins in history:
        for p in pins:
            image = (p["environment"], p["tag"], p["pcr0"], p["pcr1"], p["pcr2"])
            if p["revoked"]:
                revoked.add(image)
            elif image in revoked:
                raise Refused(f"the {p['environment']} image {p['tag']} was revoked and is listed unrevoked again in the commit dated {committed.isoformat()}")
    return history


def read_pointers(records_dir, environment):
    path = records_dir / f"{environment}.jsonl"
    if not path.exists():
        return [], []
    pointers, notes = {}, []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            p = rekor.only(rekor.strict_json(line), "log", "index", "spki_sha256", "boot", required=("log", "index", "spki_sha256", "boot"))
            if not isinstance(p["log"], str) or not rekor.HOST.fullmatch(p["log"]) or type(p["index"]) is not int or p["index"] < 0 \
                    or not isinstance(p["spki_sha256"], str) or not HEX64.fullmatch(p["spki_sha256"]) or not isinstance(p["boot"], str) or not HEX16.fullmatch(p["boot"]):
                raise ValueError("its log, index, spki_sha256 or boot is not in the pointer format")
        except ValueError as e:
            notes.append(Note(f"{path.name} line {n} is not a pointer: {e}"))
            continue
        pointers.setdefault((p["log"], p["index"]), Pointer(p["log"], p["index"], p["spki_sha256"], p["boot"]))
    return list(pointers.values()), notes


def read_trusted_root(cache):
    from tuf.ngclient import Updater

    metadata = cache / "tuf"
    metadata.mkdir(parents=True, exist_ok=True)
    bootstrap = None
    if not (metadata / "root.json").exists():
        bootstrap = fetch(f"{TUF_URL}/{TUF_ROOT}.root.json")
        if hashlib.sha256(bootstrap).hexdigest() != TUF_ROOT_SHA256:
            raise Refused(f"Sigstore's {TUF_ROOT}.root.json is not the root the door's image embeds")
    updater = Updater(str(metadata), TUF_URL, str(metadata), f"{TUF_URL}/targets/", TUF_FETCHER, bootstrap=bootstrap)
    updater.refresh()
    info = updater.get_targetinfo("trusted_root.json")
    if info is None:
        raise Refused("Sigstore's TUF repository lists no trusted_root.json")
    return Path(updater.find_cached_target(info) or updater.download_target(info)).read_bytes()


def saved_checkpoint(origin, saved):
    try:
        return rekor.Checkpoint(origin, int(saved["size"]), base64.b64decode(saved["root"], validate=True), saved["note"], (), ())
    except (KeyError, TypeError, ValueError, binascii.Error):
        return None


def advance(shard, saved, policy, retired):
    def missing(why):
        return Note(f"{shard.origin} is retired, so this run keeps the checkpoint an earlier run accepted: {why}") if retired else why
    try:
        note = fetch(f"{shard.base_url}/api/v2/checkpoint").decode()
    except (OSError, UnicodeDecodeError) as e:
        return saved, None, missing(f"{shard.origin}'s checkpoint could not be read: {e!r}")
    try:
        newest = rekor.verify_note(note, shard, policy)
    except Refusal as e:
        try:
            text, signatures = rekor.parse_note(note)
            origin, size, root = rekor.parse_checkpoint_text(text)
            seen = rekor.Checkpoint(origin, size, root, note, tuple(policy.count(text, signatures)), tuple(n for n, _, _ in signatures)) if e.reason == "witnesses" else None
        except ValueError:
            seen = None
        return saved, seen, missing(f"{shard.origin}'s newest checkpoint does not verify: {e}")
    if saved is not None:
        if newest.size < saved.size:
            return saved, newest, f"{shard.origin}'s newest checkpoint holds {newest.size} entries, fewer than the {saved.size} an earlier run accepted"
        try:
            proof = rekor.Tiles(shard, newest.size, fetch).consistency(saved.size)
            ok = rekor.consistent(saved.size, newest.size, saved.root, newest.root, proof)
        except (OSError, ValueError) as e:
            return saved, newest, missing(f"{shard.origin}'s tiles could not prove its tree of {newest.size} extends the tree of {saved.size} an earlier run accepted: {e!r}")
        if not ok:
            return saved, newest, f"{shard.origin}'s tree of {newest.size} is not consistent with the tree of {saved.size} an earlier run accepted, so the log forked or rewrote its history"
    return newest, newest, None


def prove(pointer, shard, accepted, cache_dir, records_dir, shards, policy):
    cached = cache_dir / pointer.log / f"{pointer.index}.json"
    archived = records_dir / "leaves" / pointer.log / f"{pointer.index}.json"
    tried = []
    if cached.exists():
        try:
            return rekor.verify_logged(cached.read_bytes(), shards, policy)
        except Refusal as e:
            tried.append(f"the cached entry: {e}")
    if shard is not None and accepted is not None and pointer.index < accepted.size:
        try:
            tiles = rekor.Tiles(shard, accepted.size, fetch)
            raw = records.entry_json(shard, accepted, pointer.index, tiles.entry(pointer.index), tiles.inclusion(pointer.index))
            logged = rekor.verify_logged(raw, shards, policy)
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(raw)
            return logged
        except (OSError, ValueError, Refusal) as e:
            tried.append(f"the shard's tiles: {e}")
    elif shard is not None and accepted is not None:
        tried.append(f"the newest checkpoint this watcher accepted holds {accepted.size} entries, so not index {pointer.index} yet")
    if archived.exists():
        try:
            return rekor.verify_logged(archived.read_bytes(), shards, policy)
        except Refusal as e:
            tried.append(f"the archived leaf: {e}")
    raise Refusal("unread", "; ".join(tried) or f"this watcher has no checkpoint of {pointer.log} and morse-records archives no such leaf")


def parse_trust(source):
    k = re.search(r"\bconst witnessK = (\d+)\n", source)
    block = re.search(r"\nvar witnesses = \[\]struct\{ vkey, operator string \}\{\n(.*?)\n\}\n", source, re.S)
    if not k or not block:
        raise Refused("trust.go holds no witnessK or no witnesses list this watcher can read")
    lines = [line.strip() for line in block[1].split("\n") if line.strip() and not line.strip().startswith("//")]
    listed = [re.fullmatch(r'\{"([^"]+)", "([^"]+)"\},', line) for line in lines]
    if not all(listed):
        raise Refused(f"trust.go's witnesses list has a line this watcher cannot read: {lines[[bool(m) for m in listed].index(False)]!r}")
    try:
        return int(k[1]), [rekor.parse_witness(m[1], m[2]) for m in listed]
    except ValueError as e:
        raise Refused(f"trust.go lists a witness this watcher cannot read: {e}") from e


def read_trust(enclave_dir, history, environment):
    pins = history[-1][1] if history else []
    tagged = []
    for p in pins:
        if p["environment"] != environment or p["revoked"] or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", p.get("tag") or "", re.ASCII):
            continue
        r = subprocess.run(["git", "-C", str(enclave_dir), "log", "-1", "--format=%ct", f"refs/tags/{p['tag']}"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip().isdigit():
            tagged.append((int(r.stdout), p["tag"]))
    if not tagged:
        raise Refused(f"no unrevoked {environment} image in morse-pins names a tag in the morse-enclave checkout")
    tag = max(tagged)[1]
    k, witnesses = parse_trust(git(enclave_dir, "show", f"refs/tags/{tag}:internal/door/trust.go"))
    return tag, k, witnesses


CHECKS = [
    (1, "Every certificate in CT for each of the door's names holds a key a verified record attests", checks.check_certificates),
    (2, "Every pointer's entry verifies, and morse-pins and morse-records keep their history", checks.check_records),
    (3, "Every record's custody ends at a born record, with one origin per key and a floor that never falls", checks.check_custody),
    (4, "Each Rekor shard's checkpoint verifies and extends the last one this watcher accepted", checks.check_logs),
    (5, "CAA names only Morse's ACME accounts and dns-01", checks.check_caa),
    (6, "Every boot this watcher saw the door's live attestation list has a verified record of each key it held, 2 hours after it first saw it", checks.check_live),
    (7, "Only the publisher pushes data to morse-pins main, the signer's code is on the allowlist, every statement verifies, and no sign.yml run is missing", signer_watch.check),
    (8, "The shard's witnesses match this watcher's policy and the newest pinned image's", checks.check_witnesses),
    (9, "morse-records is public", checks.check_records_public),
]


def sample_caa(name):
    labels = name.split(".")
    for i in range(len(labels) - 1):
        asked = ".".join(labels[i:])
        answer = json.loads(fetch(DOH_URL.format(asked)))
        if answer.get("Status") not in (0, 3):
            raise Refused(f"the DoH answer for {asked} has Status {answer.get('Status')}")
        caa = [a["data"] for a in answer.get("Answer", []) if a["type"] == 257]
        # A sample is kept and judged on every later run, so a value check 5 cannot read is refused before it is.
        if bad := [d for d in caa if not isinstance(d, str)]:
            raise Refused(f"the DoH answer for {asked} holds a CAA record that is not text: {bad[0]!r}")
        if caa:
            return caa
    return []


CAA_UNREAD = (OSError, http.client.HTTPException, ValueError, KeyError, TypeError, AttributeError, Refused)


def records_visibility():
    """How morse-records answers with no token: "public", why it is not, or a Note when GitHub refuses for a rate
    limit, which proves nothing either way. read_github already retries a 429 before it raises."""
    try:
        visibility = json.loads(read_github(checks.RECORDS_REPO_URL, {"User-Agent": "check-door"})[0]).get("visibility")
    except urllib.error.HTTPError as e:
        if rate_limited(e):
            return Note(f"could not be read: GitHub answers {e.code} for a rate limit")
        return f"answers {e.code}"
    except (OSError, ValueError, AttributeError) as e:
        return f"could not be read: {e!r}"
    return "public" if visibility == "public" else f"answers visibility {visibility!r}"


def gather(args):
    attestation = fetch(args.attestation) if args.attestation.startswith("https://") else Path(args.attestation).read_bytes()
    now = utcnow()
    state_path = Path(args.sequence_state)
    saved, last_run, boots = read_state(state_path)
    cache = Path(args.cache) if args.cache else state_path.with_name(state_path.name + ".cache")

    sources = args.ct or ["crt.sh", "certspotter"]
    names = args.name or [NAME]
    seen, certificates, ct_counts, ct_unread, ct_malformed, ct_inventory = set(), [], {}, {}, {}, {}
    for name in names:
        read, unread, malformed = {}, {}, {}
        for source in sources:
            try:
                read[source] = read_parsed(source, name)
            except CT_UNREAD as e:
                unread[source] = e
            except CT_MALFORMED as e:
                malformed[source] = e
        if "crt.sh" in read and not covering(read["crt.sh"], name) and (any(covering(c, name) for c in read.values()) or unread):
            del read["crt.sh"]
            try:
                again, why = reread_crtsh(name, read, unread)
            except CT_MALFORMED as e:
                malformed["crt.sh"] = e
            else:
                if why is None:
                    read["crt.sh"] = again
                else:
                    unread["crt.sh"] = why
        for source, e in unread.items():
            ct_unread.setdefault(source, {})[name] = e
        if malformed:
            ct_malformed[name] = malformed
        for source in [s for s in sources if s in read]:
            ct_inventory.setdefault(source, {})[name] = [{"entry": cert.source, "sha256": hashlib.sha256(der).hexdigest(), "covers": any(checks.covers(n, name) for n in cert.names),
                                                          "not_after": cert.not_after.isoformat()} for der, cert in read[source]]
            ct_counts.setdefault(source, {})[name] = len(covering(read[source], name))
            for der, cert in covering(read[source], name):
                if hashlib.sha256(der).digest() in seen:
                    continue
                seen.add(hashlib.sha256(der).digest())
                if args.since is None or cert.not_after >= args.since:
                    certificates.append(cert)
    if not ct_counts:
        if ct_malformed:
            raise next(e for errors in ct_malformed.values() for e in errors.values())
        raise OSError("no CT source could be read: " + "; ".join(f"{source}: {checks.unread_why(errors)}" for source, errors in ct_unread.items()))

    pins_dir, records_dir = Path(args.pins), Path(args.records)
    history = read_pins_history(pins_dir)
    pointers, notes = read_pointers(records_dir, args.environment)
    tips, rewound = {}, {}
    for repo, directory in (("morse-pins", pins_dir), ("morse-records", records_dir)):
        tip, seen_tip = git(directory, "rev-parse", "HEAD").strip(), saved["tips"].get(repo)
        if seen_tip is not None and not descends(directory, seen_tip):
            rewound[repo] = (seen_tip, tip)
        tips[repo] = seen_tip if repo in rewound else tip

    policy = rekor.make_policy(WITNESS_K, WITNESSES)
    shard_failures, checkpoints, witnesses = [], {}, {}
    trusted_root = None
    try:
        trusted_root = read_trusted_root(cache)
        shards, skipped = rekor.read_shards(trusted_root)
        notes += [Note(s) for s in skipped]
    except Exception as e:
        shards = {}
        shard_failures.append(f"Sigstore's trusted root could not be read through TUF: {e!r}")
    by_origin = {s.origin: s for s in shards.values()}
    for shard in sorted(by_origin.values(), key=lambda s: s.origin):
        retired = shard.end is not None and shard.end < now
        if retired and shard.origin not in saved["checkpoints"]:
            continue
        kept = saved["checkpoints"].get(shard.origin, {})
        last = saved_checkpoint(shard.origin, kept) if kept else None
        accepted, newest, failure = advance(shard, last, policy, retired and last is not None)
        if isinstance(failure, Note):
            notes.append(failure)
        elif failure:
            shard_failures.append(failure)
        last_seen = {name: datetime.fromisoformat(kept.get("cosigners", {}).get(name) or kept.get("tracked_since") or now.isoformat()) for name in policy.names()}
        counted = {c.name for c in newest.cosigners} if newest else set()
        last_seen.update({name: now for name in counted})
        if shard.end is None or shard.end >= now:
            witnesses[shard.origin] = (newest.lines if newest else (), last_seen)
        counts = kept.get("counts", {})
        if newest:
            day = counts.setdefault(now.strftime("%Y-%m-%d"), {})
            day[str(len(counted))] = day.get(str(len(counted)), 0) + 1
        checkpoints[shard.origin] = {"accepted": accepted, "cosigners": {n: t.isoformat() for n, t in sorted(last_seen.items())},
                                     "counts": counts, "tracked_since": kept.get("tracked_since") or now.isoformat()}
    for origin, kept in saved["checkpoints"].items():
        checkpoints.setdefault(origin, {"kept": kept})

    verified_ = {}
    for p in sorted(pointers, key=lambda p: (p.log, p.index)):
        shard = by_origin.get(p.log)
        accepted = checkpoints.get(p.log, {}).get("accepted")
        try:
            v = records.verify_record(prove(p, shard, accepted, cache / "leaves", records_dir, shards, policy), args.environment, history)
        except Refusal as e:
            notes.append(Note(f"the entry at {p.name()} does not verify, so this run ignores it: {e}"))
            continue
        if (v.boot, v.spki_sha256) != (p.boot, p.spki_sha256):
            notes.append(Note(f"the pointer {p.name()} names boot {p.boot} and SPKI {p.spki_sha256}, and its entry attests boot {v.boot} and SPKI {v.spki_sha256}"))
        verified_[(v.log, v.index)] = v

    try:
        trust = read_trust(Path(args.enclave), history, args.environment)
    except (Refused, subprocess.CalledProcessError, OSError) as e:
        trust = Refused(str(e.stderr.strip()) if isinstance(e, subprocess.CalledProcessError) else str(e))

    caa_unread = {}
    if not args.no_caa_sample:
        when = datetime.now(timezone.utc).isoformat(timespec="seconds")
        samples = []
        for name in names:
            try:
                samples.append({"time": when, "name": name, "caa": sample_caa(name)})
            except CAA_UNREAD as e:
                caa_unread[name] = e
        if not samples:
            raise next(iter(caa_unread.values()))
        with open(args.caa_history, "a") as f:
            f.writelines(json.dumps(sample) + "\n" for sample in samples)
    with open(args.caa_history) as f:
        caa_history = [json.loads(line) for line in f if line.strip()]

    live = []
    for instance in json.loads(attestation)["instances"]:
        try:
            live.append(records.live_boot(base64.b64decode(instance), args.environment, history, now))
        except Refused as e:
            live.append(e)
    accounts = {tuple(a.split("=", 1)) for a in args.caa_account}
    ahead = now + records.MAX_AHEAD
    boots = {key: boot if boot.first_seen is None or boot.first_seen <= ahead else checks.Boot(None, boot.spkis) for key, boot in boots.items()}
    dated = last_run if last_run is not None and last_run <= ahead else None
    for seen_ in live:
        if isinstance(seen_, records.Live):
            boot = boots.get(seen_.key_id, checks.Boot(dated, {}))
            boots[seen_.key_id] = checks.Boot(boot.first_seen, {seen_.spki_sha256: now} | boot.spkis)
    ev = checks.Evidence(names, args.environment, certificates, ct_counts, pointers, list(verified_.values()), notes, shard_failures, caa_history, accounts,
                         live, tips, rewound, witnesses, trust, records_visibility(), policy, now, boots, last_run, ct_unread=ct_unread, caa_unread=caa_unread, ct_malformed=ct_malformed, ct_inventory=ct_inventory, checkpoints=checkpoints, acked_boots=args.ack_boot)
    ev.revocations = {c.der: revocation.revocation(c.der, fetch) for c in checks.failing(ev)}

    ev.signer, ev.signer_state = signer_watch.watch(pins_dir, args, saved["signer"], now, trusted_root, shards, policy)
    return ev


def stamp(text):
    return None if text is None else datetime.fromisoformat(text)


def saved_spkis(boot):
    if "spki_sha256" in boot:
        return {boot["spki_sha256"]: None}
    if isinstance(boot["spkis"], list):
        return dict.fromkeys(boot["spkis"])
    return {spki: stamp(t) for spki, t in boot["spkis"].items()}


def read_state(state):
    saved = json.loads(state.read_text()) if state.exists() else {}
    last_run = None if saved.get("last_run") is None else datetime.fromisoformat(saved["last_run"])
    kept = signer_watch.SignerState.read(saved)
    boots = {key: checks.Boot(stamp(b["first_seen"]), saved_spkis(b)) for key, b in saved.get("boots", {}).items()}
    if any(t is not None and t.tzinfo is None for t in [last_run, kept.unlisted_since, kept.runs_read_at, *(b.first_seen for b in boots.values()), *(t for b in boots.values() for t in b.spkis.values())]):
        raise ValueError(f"{state} holds a time with no zone")
    tips = dict(saved.get("tips") or ({"morse-pins": saved["tip"]} if saved.get("tip") else {}))
    return {"checkpoints": saved.get("checkpoints") or {}, "tips": tips, "signer": kept}, last_run, boots


def write_state(path, ev):
    checkpoints = {}
    for origin, c in sorted(ev.checkpoints.items()):
        if "kept" in c:
            checkpoints[origin] = c["kept"]
            continue
        out = {k: c[k] for k in ("cosigners", "counts", "tracked_since")}
        if c["accepted"] is not None:
            out |= {"size": c["accepted"].size, "root": rekor.b64_string(c["accepted"].root), "note": c["accepted"].note}
        checkpoints[origin] = out
    boots = {key: {"first_seen": b.first_seen and b.first_seen.isoformat(), "spkis": {spki: t and t.isoformat() for spki, t in sorted(b.spkis.items())}} for key, b in sorted(ev.boots.items())}
    path.write_text(json.dumps({"checkpoints": checkpoints, "tips": ev.tips, "last_run": ev.now.isoformat(), "boots": boots, **ev.signer_state.saved()}))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pins", required=True, help="a full-history checkout of morse-pins, for its enclave_pins.json history")
    parser.add_argument("--records", required=True, help="a full-history checkout of trymorse/morse-records, with <environment>.jsonl pointers and leaves/")
    parser.add_argument("--caa-history", required=True, help="a JSON lines file of CAA samples; each run appends one for each --name whose CAA lookup succeeded, and a sample that names no host is inference.trymorse.ai's")
    parser.add_argument("--caa-account", action="append", default=[], metavar="CA=URI", help="an ACME account CAA may name, such as letsencrypt.org=https://acme-v02.api.letsencrypt.org/acme/acct/1")
    parser.add_argument("--sequence-state", required=True, help="a JSON file holding each Rekor shard's last accepted checkpoint and its witnesses, the morse-pins and morse-records commits the last run saw, when this watcher last ran, every boot it has seen live with each SPKI it held and when it first saw it, and for check 7 where it stopped in the activity of morse-pins main, the highest sign.yml run number judged and when its runs were last read, the runs still pending and the runs refused or missing not yet acknowledged, the statements already verified, the refused pushes not yet acknowledged, and since when main has been unlisted")
    parser.add_argument("--cache", help="a directory for the TUF metadata and the entries already proven; beside --sequence-state if omitted")
    parser.add_argument("--enclave", required=True, help="a checkout of trymorse/morse-enclave with its tags, for check 8's reading of the newest pinned image's trust.go")
    signer_watch.add_arguments(parser)
    parser.add_argument("--ack-boot", action="append", default=[], metavar="KEY_ID=URL", help="the HPKE key id of a boot that held an SPKI live and died before it could log a record of it, and the URL of the public note that says so; check 6 prints a note for that boot on every run instead of failing, and fails if the boot it names is kept but holds nothing unrecorded")
    parser.add_argument("--ct", action="append", metavar="SOURCE", help="crt.sh, certspotter, or a JSON file of certspotter issuances with cert_der; both CT services if omitted")
    parser.add_argument("--attestation", default=ATTESTATION_URL, help="the door's /v1/attestation URL, or a file holding its answer")
    parser.add_argument("--no-caa-sample", action="store_true", help="check the CAA history without adding a sample")
    parser.add_argument("--since", type=lambda s: datetime.fromisoformat(s).replace(tzinfo=timezone.utc), help="skip certificates that expired before this date")
    parser.add_argument("--environment", default="prod")
    parser.add_argument("--name", action="append", metavar="HOST", help=f"a hostname of the door to watch; give it once for each, {NAME} if omitted")
    parser.add_argument("--verdict", help="a file to write this run's verdict to as JSON: its kind (passed, failed, unenforced or unread), exit code, whether a retry may read the evidence, the checks that failed and the checks not enforced, each check's messages, each CT source with why it could not be read or parsed for any name, or null when it was read for every name, and which names it read and which it could not (none when the evidence was unread), the watched hosts the failed checks' messages concern, or when no check failed, those the not enforced ones concern, each certificate check 1 judged with the names it covers and its judgment, every entry each CT source returned for each name, and each covering entry check 1 did not judge, with why")
    args = parser.parse_args(argv)

    try:
        ev = gather(args)
    except Exception as e:
        print(f"FAIL: could not read the evidence: {e!r}")
        write_verdict(args.verdict, {"kind": "unread", "exit": 1, "retryable": True, "error": f"could not read the evidence: {e!r}", "failed": [], "unenforced": [], "checks": [], "ct": {}, "hosts": [], "ct_hosts": {}, "certificates": [], "ct_inventory": {}, "unjudged": []})
        sys.exit(1)
    print(f"{len(ev.certificates)} certificates in CT cover {' or '.join(ev.names)}. morse-records has {len(ev.pointers)} {ev.environment} pointers, and {len(ev.verified)} of their entries verify.\n")

    results = []
    for number, title, check in CHECKS:
        print(f"{title} (check {number})")
        try:
            failures = check(ev)
        except Exception as e:
            failures = [f"the check could not run: {e!r}"]
        for failure in failures:
            print(f"  {checks.level(failure)}: {failure}")
        if not [f for f in failures if not isinstance(f, Note)]:
            print("  OK")
        print()
        results.append({"check": number, "title": title, "messages": [{"level": checks.level(f), "text": str(f), "hosts": getattr(f, "hosts", [])} for f in failures]})
    failed = [r["check"] for r in results if any(m["level"] == "FAIL" for m in r["messages"])]
    unenforced = [r["check"] for r in results if any(m["level"] == "NOT ENFORCED" for m in r["messages"])]
    kind, code = ("failed", 1) if failed else ("unenforced", 2) if unenforced else ("passed", 0)
    missed = {source: dict(errors) for source, errors in ev.ct_unread.items()}
    for name, errors in ev.ct_malformed.items():
        for source, e in errors.items():
            missed.setdefault(source, {})[name] = e
    ct = {source: None for source in ev.ct_counts} | {source: checks.unread_why(errors) for source, errors in missed.items()}
    ct_hosts = {source: {"read": [n for n in ev.names if n in ev.ct_counts.get(source, {}) and n not in missed.get(source, {})], "unread": [n for n in ev.names if n in missed.get(source, {})]} for source in ct}
    hosts = hosts_at(results, failed, "FAIL", ev.names) if failed else hosts_at(results, unenforced, "NOT ENFORCED", ev.names)
    write_verdict(args.verdict, {"kind": kind, "exit": code, "retryable": False, "error": None, "failed": failed, "unenforced": unenforced, "checks": results, "ct": ct, "hosts": hosts,
                                 "ct_hosts": ct_hosts, "certificates": certificate_identities(ev), "ct_inventory": ev.ct_inventory, "unjudged": unjudged(ev, args.since)})
    write_state(Path(args.sequence_state), ev)
    sys.exit(code)


def hosts_at(results, numbers, at, names):
    """The watched names the messages at level at of the checks numbered carry, in the order the names were given."""
    hosts = {h for r in results if r["check"] in numbers for m in r["messages"] if m["level"] == at for h in m["hosts"]}
    return [n for n in names if n in hosts]


def certificate_identities(ev):
    return [{"source": c.source, "names": c.names, "sha256": hashlib.sha256(c.der).hexdigest(), "spki_sha256": c.spki_sha256, "not_before": c.not_before.isoformat(),
             "not_after": c.not_after.isoformat(), "logged": c.logged.isoformat(), "hosts": [n for n in ev.names if any(checks.covers(p, n) for p in c.names)],
             **ev.judgments.get(c.der, {"judgment": "unjudged", "revoked": None})} for c in ev.certificates]


def unjudged(ev, since):
    """Each entry a CT source returned covering a watched name whose certificate check 1 did not judge, from the same
    reads: only one that expired before --since should be here."""
    judged = {hashlib.sha256(c.der).hexdigest() for c in ev.certificates}
    return [{"source": source, "name": name, **entry, "why": "expired before --since" if since and datetime.fromisoformat(entry["not_after"]) < since else "not judged"}
            for source, names in ev.ct_inventory.items() for name, entries in names.items() for entry in entries if entry["covers"] and entry["sha256"] not in judged]


def write_verdict(path, verdict):
    if path:
        Path(path).write_text(json.dumps(verdict, indent=2) + "\n")

if __name__ == "__main__":
    main()

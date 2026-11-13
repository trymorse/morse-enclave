# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2==6.1.5", "cryptography==50.0.2", "tuf==7.0.1", "securesystemslib==1.6.0", "urllib3==2.8.0"]
# ///
"""Checks that every certificate for Morse's inference door holds a key whose boot record a pinned enclave logged in Rekor.

Usage: uv run check-door.py --pins <morse-pins checkout> --records <morse-records checkout> --enclave <morse-enclave checkout> --caa-history caa.jsonl --sequence-state state.json --caa-account <ca>=<account uri> ...

It reads Certificate Transparency for inference.trymorse.ai and every wildcard that covers it, the enclave_pins.json
history in morse-pins, the pointers in morse-records, each entry a pointer names in Sigstore's Rekor v2, with the log
keys from Sigstore's TUF repository and the witnesses this script lists, the CAA record, the door's live
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
import types
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID


def load(file, **names):
    module = types.ModuleType(Path(file).stem.replace("-", "_"))
    module.__dict__.update(names)
    exec(compile(Path(__file__).with_name(file).read_text(), file, "exec"), module.__dict__)
    return module


nitro = load("check-enclave.py")
Refused = nitro.Refused
rekor = load("rekor.py")
Refusal = rekor.Refusal
revocation = load("revocation.py")
signer = load("signer.py")
records = load("door_records.py", nitro=nitro, rekor=rekor)
checks = load("door_checks.py", rekor=rekor, records=records, Revocation=revocation.Revocation)
Note, Unenforced = checks.Note, checks.Unenforced

NAME = "inference.trymorse.ai"
CRTSH_URL = "https://crt.sh/?q=%25.{}&output=json"
CRTSH_CERT_URL = "https://crt.sh/?d={}"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={}&match_wildcards=true&expand=dns_names&expand=cert_der"
ATTESTATION_URL = "https://inference.trymorse.ai/v1/attestation"
DOH_URL = "https://dns.google/resolve?name={}&type=CAA"
GITHUB_RETRY_DELAYS = (2, 5)

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


def read_github(url, headers):
    """GitHub's answer to url and its headers. A 5xx, a 429 or a reset or refused connection is tried again after
    each of GITHUB_RETRY_DELAYS, since GitHub answers one now and then; any other failure, a timeout among them, is
    raised at once."""
    for delay in (*GITHUB_RETRY_DELAYS, None):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as reply:
                return reply.read(), reply.headers
        except urllib.error.HTTPError as e:
            if delay is None or (e.code < 500 and e.code != 429):
                raise
        except OSError as e:
            if delay is None or not isinstance(getattr(e, "reason", e), ConnectionError):
                raise
        time.sleep(delay)


def covers(pattern, name):
    pattern = pattern.lower().rstrip(".")
    return pattern == name or (pattern.startswith("*.") and pattern[2:] == name.split(".", 1)[1])


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
            if any(covers(n, name) for n in r["name_value"].split("\n")):
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
CRTSH_RETRY_DELAYS = (2, 5)


def read_covering(source, name):
    certs = [(der, parse_certificate(label, der, logged)) for label, der, logged in read_ct(source, name)]
    return [(der, cert) for der, cert in certs if any(covers(n, name) for n in cert.names)]


def reread_crtsh(name, read):
    """crt.sh sometimes answers with none of the certificates another CT source returns, and has them again minutes
    later. Reads it again, and if it still has none, returns why this run takes it as unread rather than empty."""
    why = None
    for delay in CRTSH_RETRY_DELAYS:
        time.sleep(delay)
        try:
            again = read_covering("crt.sh", name)
        except CT_UNREAD as e:
            why = e
            continue
        if again:
            return again, None
        why = None
    if why is None:
        others = ", ".join(f"{s} returned {len(c)}" for s, c in read.items() if c)
        why = LookupError(f"it returned no certificate covering {name} in {len(CRTSH_RETRY_DELAYS) + 1} reads, though {others}")
    return [], why


def git(directory, *args):
    return subprocess.run(["git", "-C", str(directory), *args], check=True, capture_output=True, text=True).stdout


def descends(directory, seen):
    return subprocess.run(["git", "-C", str(directory), "merge-base", "--is-ancestor", seen, "HEAD"], capture_output=True).returncode == 0


signer_watch = load("signer_watch.py", git=git, descends=descends, Note=Note, Unenforced=Unenforced, read_github=read_github, signer=signer, rekor=rekor)


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
    (1, "Every certificate in CT for the door's name holds a key a verified record attests", checks.check_certificates),
    (2, "Every pointer's entry verifies, and morse-pins and morse-records keep their history", checks.check_records),
    (3, "Every record's custody ends at a born record, with one origin per key and a floor that never falls", checks.check_custody),
    (4, "Each Rekor shard's checkpoint verifies and extends the last one this watcher accepted", checks.check_logs),
    (5, "CAA names only Morse's ACME accounts and dns-01", checks.check_caa),
    (6, "The door's live attestation names only boots with verified records", checks.check_live),
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
        if caa:
            return caa
    return []


def records_visibility():
    try:
        visibility = json.loads(read_github(checks.RECORDS_REPO_URL, {"User-Agent": "check-door"})[0]).get("visibility")
    except urllib.error.HTTPError as e:
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
    read, ct_unread = {}, {}
    for source in sources:
        try:
            read[source] = read_covering(source, args.name)
        except CT_UNREAD as e:
            ct_unread[source] = e
    if read.get("crt.sh") == [] and any(read.values()):
        read["crt.sh"], why = reread_crtsh(args.name, read)
        if why is not None:
            del read["crt.sh"]
            ct_unread["crt.sh"] = why

    seen, certificates, ct_counts = set(), [], {}
    for source in [s for s in sources if s in read]:
        ct_counts[source] = len(read[source])
        for der, cert in read[source]:
            if hashlib.sha256(der).digest() in seen:
                continue
            seen.add(hashlib.sha256(der).digest())
            if args.since is None or cert.not_after >= args.since:
                certificates.append(cert)
    if not ct_counts:
        raise OSError("no CT source could be read: " + "; ".join(f"{source}: {e!r}" for source, e in ct_unread.items()))

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

    if not args.no_caa_sample:
        sample = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "caa": sample_caa(args.name)}
        with open(args.caa_history, "a") as f:
            f.write(json.dumps(sample) + "\n")
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
            boot = boots.get(seen_.key_id, checks.Boot(dated, ()))
            boots[seen_.key_id] = checks.Boot(boot.first_seen, tuple(sorted({*boot.spkis, seen_.spki_sha256})))
    ev = checks.Evidence(args.name, args.environment, certificates, ct_counts, pointers, list(verified_.values()), notes, shard_failures, caa_history, accounts,
                         live, tips, rewound, witnesses, trust, records_visibility(), policy, now, boots, last_run, ct_unread=ct_unread, checkpoints=checkpoints)
    ev.revocations = {c.der: revocation.revocation(c.der, fetch) for c in checks.failing(ev)}

    ev.signer, ev.signer_state = signer_watch.watch(pins_dir, args, saved["signer"], now, trusted_root, shards, policy)
    return ev


def read_state(state):
    saved = json.loads(state.read_text()) if state.exists() else {}
    last_run = None if saved.get("last_run") is None else datetime.fromisoformat(saved["last_run"])
    kept = signer_watch.SignerState.read(saved)
    boots = {key: checks.Boot(None if b["first_seen"] is None else datetime.fromisoformat(b["first_seen"]), tuple(sorted(set(b["spkis"] if "spkis" in b else [b["spki_sha256"]]))))
             for key, b in saved.get("boots", {}).items()}
    if any(t is not None and t.tzinfo is None for t in [last_run, kept.unlisted_since, kept.runs_read_at, *(b.first_seen for b in boots.values())]):
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
    boots = {key: {"first_seen": b.first_seen and b.first_seen.isoformat(), "spkis": list(b.spkis)} for key, b in sorted(ev.boots.items())}
    path.write_text(json.dumps({"checkpoints": checkpoints, "tips": ev.tips, "last_run": ev.now.isoformat(), "boots": boots, **ev.signer_state.saved()}))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pins", required=True, help="a full-history checkout of morse-pins, for its enclave_pins.json history")
    parser.add_argument("--records", required=True, help="a full-history checkout of trymorse/morse-records, with <environment>.jsonl pointers and leaves/")
    parser.add_argument("--caa-history", required=True, help="a JSON lines file of CAA samples; each run appends one")
    parser.add_argument("--caa-account", action="append", default=[], metavar="CA=URI", help="an ACME account CAA may name, such as letsencrypt.org=https://acme-v02.api.letsencrypt.org/acme/acct/1")
    parser.add_argument("--sequence-state", required=True, help="a JSON file holding each Rekor shard's last accepted checkpoint and its witnesses, the morse-pins and morse-records commits the last run saw, when this watcher last ran, every boot it has seen live with each SPKI it held and when it first saw it, and for check 7 where it stopped in the activity of morse-pins main, the highest sign.yml run number judged and when its runs were last read, the runs still pending and the runs refused or missing not yet acknowledged, the statements already verified, the refused pushes not yet acknowledged, and since when main has been unlisted")
    parser.add_argument("--cache", help="a directory for the TUF metadata and the entries already proven; beside --sequence-state if omitted")
    parser.add_argument("--enclave", required=True, help="a checkout of trymorse/morse-enclave with its tags, for check 8's reading of the newest pinned image's trust.go")
    signer_watch.add_arguments(parser)
    parser.add_argument("--ct", action="append", metavar="SOURCE", help="crt.sh, certspotter, or a JSON file of certspotter issuances with cert_der; both CT services if omitted")
    parser.add_argument("--attestation", default=ATTESTATION_URL, help="the door's /v1/attestation URL, or a file holding its answer")
    parser.add_argument("--no-caa-sample", action="store_true", help="check the CAA history without adding a sample")
    parser.add_argument("--since", type=lambda s: datetime.fromisoformat(s).replace(tzinfo=timezone.utc), help="skip certificates that expired before this date")
    parser.add_argument("--environment", default="prod")
    parser.add_argument("--name", default=NAME)
    parser.add_argument("--verdict", help="a file to write this run's verdict to as JSON: its kind (passed, failed, unenforced or unread), exit code, whether a retry may read the evidence, the checks that failed and the checks not enforced, and each check's messages")
    args = parser.parse_args(argv)

    try:
        ev = gather(args)
    except Exception as e:
        print(f"FAIL: could not read the evidence: {e!r}")
        write_verdict(args.verdict, {"kind": "unread", "exit": 1, "retryable": True, "error": f"could not read the evidence: {e!r}", "failed": [], "unenforced": [], "checks": []})
        sys.exit(1)
    print(f"{len(ev.certificates)} certificates in CT cover {ev.name}. morse-records has {len(ev.pointers)} {ev.environment} pointers, and {len(ev.verified)} of their entries verify.\n")

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
        results.append({"check": number, "title": title, "messages": [{"level": checks.level(f), "text": str(f)} for f in failures]})
    failed = [r["check"] for r in results if any(m["level"] == "FAIL" for m in r["messages"])]
    unenforced = [r["check"] for r in results if any(m["level"] == "NOT ENFORCED" for m in r["messages"])]
    kind, code = ("failed", 1) if failed else ("unenforced", 2) if unenforced else ("passed", 0)
    write_verdict(args.verdict, {"kind": kind, "exit": code, "retryable": False, "error": None, "failed": failed, "unenforced": unenforced, "checks": results})
    write_state(Path(args.sequence_state), ev)
    sys.exit(code)


def write_verdict(path, verdict):
    if path:
        Path(path).write_text(json.dumps(verdict, indent=2) + "\n")

if __name__ == "__main__":
    main()

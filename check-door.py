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
enforced.
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
import types
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

nitro = types.ModuleType("check_enclave")
exec(compile(Path(__file__).with_name("check-enclave.py").read_text(), "check-enclave.py", "exec"), nitro.__dict__)
Refused = nitro.Refused
# rekor.py holds the offline Rekor v2 verification, the checks the door's enclave runs on its own entry.
rekor = types.ModuleType("rekor")
exec(compile(Path(__file__).with_name("rekor.py").read_text(), "rekor.py", "exec"), rekor.__dict__)
Refusal = rekor.Refusal
# revocation.py asks a certificate's CA, by OCSP or CRL, whether it revoked the certificate.
revocation = types.ModuleType("revocation")
exec(compile(Path(__file__).with_name("revocation.py").read_text(), "revocation.py", "exec"), revocation.__dict__)
Revocation = revocation.Revocation
# signer.py verifies the public image signer's statements, as the enclave's pinsig does.
signer = types.ModuleType("signer")
exec(compile(Path(__file__).with_name("signer.py").read_text(), "signer.py", "exec"), signer.__dict__)

NAME = "inference.trymorse.ai"
CRTSH_URL = "https://crt.sh/?q=%25.{}&output=json"
CRTSH_CERT_URL = "https://crt.sh/?d={}"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={}&match_wildcards=true&expand=dns_names&expand=cert_der"
ATTESTATION_URL = "https://inference.trymorse.ai/v1/attestation"
DOH_URL = "https://dns.google/resolve?name={}&type=CAA"
RECORDS_REPO_URL = "https://api.github.com/repos/trymorse/morse-records"
ORIGIN_TYPE = "morse-door-origin-v1"
RECORD_TYPE = "morse-door-boot-v1"
RECORD_OID = "1.3.6.1.4.1.67561.1"
LIVE_GRACE = timedelta(hours=2)
RUN_GAP = timedelta(minutes=7)
MAX_AHEAD = timedelta(minutes=2)
MAX_AGE = timedelta(seconds=nitro.MAX_AGE_SECONDS)
MAX_KEY_AGE = timedelta(days=60)
POINTER_LATE = timedelta(minutes=20)
WITNESS_LAPSE = timedelta(hours=24)

# Sigstore's TUF repository, walked forward from the root the door's image embeds.
TUF_URL = "https://tuf-repo-cdn.sigstore.dev"
TUF_ROOT = 16
TUF_ROOT_SHA256 = "27aea7e372aa7864065174f0661784fcf8b0e28b1dbfebeada31a0f1fb19167f"
TUF_FETCHER = None

# This watcher's own witness policy. It must be at least as strict as the image's: it may list fewer witnesses or
# require a larger k, never more witnesses or a smaller k. It is not read from the image, so one Morse commit cannot
# relax both, and check 8 fails when the newest pinned image lists a witness this list does not, or a smaller k.
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


@dataclass(frozen=True)
class Verified:
    log: str
    index: int
    boot: str
    spki_sha256: str
    born: str
    sender: str | None
    floor: int
    made: datetime

    def name(self):
        return f"{self.log}/{self.index}"

    @property
    def pair(self):
        return (self.boot, self.spki_sha256)

    @property
    def origin(self):
        return (self.born, self.sender, self.floor)


@dataclass(frozen=True)
class Live:
    spki_sha256: str
    key_id: str
    unpinned: str | None


@dataclass(frozen=True)
class Boot:
    first_seen: datetime | None
    spkis: tuple

    def young(self, now):
        return self.first_seen is not None and now - self.first_seen < LIVE_GRACE

    def seen(self):
        if self.first_seen is None:
            return "this watcher cannot date when it first saw it live, so how long it served is unknown"
        return f"this watcher first saw it live at {self.first_seen.isoformat(timespec='seconds')}"


class Unenforced(str):
    pass


class Note(str):
    pass


UNENFORCED = Unenforced("check 6 not enforced: needs --sequence-state from this watcher's earlier runs, which keeps every boot it has seen live and when it last ran, and this file has no last_run, so a boot that served before this run without a record cannot show")


def utcnow():
    return datetime.now(timezone.utc)


def fetch(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "check-door"}), timeout=60) as reply:
        return reply.read()


def covers(pattern, name):
    pattern = pattern.lower().rstrip(".")
    return pattern == name or (pattern.startswith("*.") and pattern[2:] == name.split(".", 1)[1])


def spki_sha256(key):
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


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
    # A log's embedded SCT, or the time the CT source saw the precertificate, is when the certificate became public.
    # With neither, notBefore stands in, which a CA may set in the past, so the 20 minutes start early.
    when = min(scts) if scts else logged or cert.not_valid_before_utc
    return Certificate(source, list(dict.fromkeys(names)), spki_sha256(cert.public_key()), cert.not_valid_before_utc, cert.not_valid_after_utc, when, der)


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


def p256_spki(public_key):
    try:
        key = serialization.load_der_public_key(public_key or b"")
    except ValueError as e:
        raise Refused("the document's public_key is not a SubjectPublicKeyInfo") from e
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise Refused("the document's public_key is not a P-256 key")
    return spki_sha256(key)


def git(directory, *args):
    return subprocess.run(["git", "-C", str(directory), *args], check=True, capture_output=True, text=True).stdout


def descends(directory, seen):
    return subprocess.run(["git", "-C", str(directory), "merge-base", "--is-ancestor", seen, "HEAD"], capture_output=True).returncode == 0


# signer_watch.py holds check 7, the watch on the public image signer, with the names it shares with this file.
signer_watch = types.ModuleType("signer_watch")
signer_watch.__dict__.update(git=git, descends=descends, Note=Note, Unenforced=Unenforced, signer=signer, rekor=rekor)
exec(compile(Path(__file__).with_name("signer_watch.py").read_text(), "signer_watch.py", "exec"), signer_watch.__dict__)


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


def pins_at(history, when):
    return next((pins for committed, pins in reversed(history) if committed <= when), [])


def verified(document):
    try:
        return nitro.verify(document)
    except Refused:
        raise
    except Exception as e:
        raise Refused(f"the document does not parse: {e!r}") from e


def hpke_key_id(payload, environment):
    prefix = f"morse-proxy-hpke-v1|{environment}|".encode()
    user_data = payload.get("user_data") or b""
    if not user_data.startswith(prefix) or len(user_data) != len(prefix) + 32:
        raise Refused(f"the document's user_data does not name a {environment} HPKE key")
    return hashlib.sha256(user_data[len(prefix):]).hexdigest()[:16]


def canonical_time(born):
    utc, fraction = rekor.rfc3339(born, "origin.born")
    return utc.strftime("%Y-%m-%dT%H:%M:%S") + (f".{fraction}" if fraction else "") + "Z"


def origin_nonce(spki_sha256, born, sender, floor):
    statement = {"origin": {"born": canonical_time(born), "floor": floor, "from": sender and sender.lower()}, "spki_sha256": spki_sha256, "type": ORIGIN_TYPE}
    return hashlib.sha256(json.dumps(statement, separators=(",", ":"), sort_keys=True).encode()).digest()


def record_digest(spki):
    return hashlib.sha256(f"{RECORD_TYPE}\n{spki}\n".encode()).digest()


def image_refusal(payload, environment, history):
    pcrs = [payload["pcrs"][i].hex() for i in range(3)]
    made = datetime.fromtimestamp(payload["timestamp"] / 1000, timezone.utc)
    if any(p["environment"] == environment and not p["revoked"] and [p["pcr0"], p["pcr1"], p["pcr2"]] == pcrs for p in pins_at(history, made)):
        return None
    return f"morse-pins lists no unrevoked {environment} image with the document's PCRs at {made.isoformat(timespec='seconds')}, when the document was made"


def der_octet_string(raw):
    if len(raw) < 2 or raw[0] != 0x04:
        raise ValueError("the record extension is not one OCTET STRING")
    length, start = raw[1], 2
    if length & 0x80:
        width = length & 0x7F
        if width < 1 or width > 4 or len(raw) < 2 + width or raw[2] == 0:
            raise ValueError("the record extension's length is not DER")
        length, start = int.from_bytes(raw[2:2 + width], "big"), 2 + width
        if length < 0x80 or length < 1 << (8 * (width - 1)):
            raise ValueError("the record extension's length is not DER")
    if len(raw) != start + length:
        raise ValueError("the record extension is not one OCTET STRING")
    return raw[start:]


def read_record(certificate):
    """The record a record certificate carries. Neither the certificate's signature nor its dates prove anything."""
    cert = x509.load_der_x509_certificate(certificate)
    ext = next((e for e in cert.extensions if e.oid.dotted_string == RECORD_OID), None)
    if ext is None:
        raise ValueError("the certificate carries no record extension")
    record = rekor.only(rekor.strict_json(der_octet_string(ext.value.value)), "type", "environment", "document", "spki_sha256", "origin",
                  required=("type", "environment", "document", "spki_sha256", "origin"))
    origin = rekor.only(record["origin"], "born", "from", "floor", required=("born", "floor"))
    if "from" not in origin:
        raise ValueError("the origin has no from")
    if not isinstance(record["type"], str) or not isinstance(record["environment"], str) or not isinstance(record["spki_sha256"], str):
        raise ValueError("type, environment or spki_sha256 is not a string")
    sender, floor = origin["from"], origin["floor"]
    if not isinstance(origin["born"], str) or not (sender is None or isinstance(sender, str) and re.fullmatch(r"[0-9a-fA-F]{16}", sender, re.ASCII)):
        raise ValueError("origin.born is not a string or origin.from is not null or a boot's 16 hex digits")
    if type(floor) is not int or not 0 <= floor < 1 << 64:
        raise ValueError("origin.floor is not an unsigned integer")
    return record, rekor.b64(record["document"], "the document"), origin["born"], sender and sender.lower(), floor


def verify_record(logged, environment, history):
    """The boot record a logged entry carries, verified as a watcher must: by its Nitro document, at the document's
    own time and against the pins in force then, never by the entry's certificate or K's signature."""
    try:
        record, document, born, sender, floor = read_record(logged.body.certificate)
        if record["type"] != RECORD_TYPE or record["environment"] != environment:
            raise ValueError(f"the record is a {record['environment']} {record['type']}, not a {environment} {RECORD_TYPE}")
        born = canonical_time(born)
    except (ValueError, TypeError, UnicodeDecodeError, Refused) as e:
        raise Refusal("record", str(e)) from e
    try:
        payload = verified(document)
        key_id = hpke_key_id(payload, environment)
        refusal = image_refusal(payload, environment, history)
        if refusal:
            raise Refused(refusal)
        spki = p256_spki(payload.get("public_key"))
        made = datetime.fromtimestamp(payload["timestamp"] / 1000, timezone.utc)
    except Refused as e:
        raise Refusal("document", str(e)) from e
    except Exception as e:
        raise Refusal("document", f"the document does not parse: {e!r}") from e
    if record["spki_sha256"] != spki:
        raise Refusal("spki", f"the record's spki_sha256 is {record['spki_sha256']!r}, and the document attests SPKI {spki}")
    if logged.body.digest != record_digest(spki):
        raise Refusal("digest", f"the entry's digest is not H for SPKI {spki}, which the document attests")
    if payload.get("nonce") != origin_nonce(spki, born, sender, floor):
        raise Refusal("nonce", "the document's nonce is not the origin statement of its SPKI and the record's origin, so the enclave did not attest this origin")
    return Verified(logged.origin, logged.index, key_id, spki, born, sender, floor, made)


def verify_entry(raw, shards, policy, environment, history):
    return verify_record(rekor.verify_logged(raw, shards, policy), environment, history)


def entry_json(shard, checkpoint, index, body, proof):
    return json.dumps({
        "logIndex": str(index), "logId": {"keyId": rekor.b64_string(shard.log_id)}, "kindVersion": {"kind": "hashedrekord", "version": "0.0.2"},
        "inclusionProof": {"logIndex": str(index), "rootHash": rekor.b64_string(checkpoint.root), "treeSize": str(checkpoint.size),
                           "hashes": [rekor.b64_string(h) for h in proof], "checkpoint": {"envelope": checkpoint.note}},
        "canonicalizedBody": rekor.b64_string(body),
    }).encode()


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
    """The shard's newest checkpoint, if it verifies under policy and extends the one an earlier run accepted, and why not.
    The newest checkpoint is returned either way, when its log signature verifies, so check 8 can read its cosigners.
    A retired shard an earlier run tracked keeps its accepted checkpoint, with a Note, when its newest cannot be shown."""
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
    """A pointer's entry: from this watcher's cache, else from the shard's tiles against the accepted checkpoint,
    else from the leaf archive in morse-records. Each is checked in full, the way verify_logged checks any entry."""
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
            raw = entry_json(shard, accepted, pointer.index, tiles.entry(pointer.index), tiles.inclusion(pointer.index))
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


@dataclass
class Evidence:
    name: str
    environment: str
    certificates: list
    ct_counts: dict
    pointers: list
    verified: list
    notes: list
    shard_failures: list
    caa_history: list
    caa_accounts: set
    live: list
    tips: dict
    rewound: dict
    witnesses: dict
    trust: object
    records_visibility: str | None
    policy: rekor.Policy
    boots: dict = field(default_factory=dict)
    last_run: datetime | None = None
    now: datetime = field(default_factory=lambda: utcnow())
    revocations: dict = field(default_factory=dict)
    ct_unread: dict = field(default_factory=dict)
    signer: list = field(default_factory=list)
    signer_state: object = None

    def recorded(self):
        return {v.spki_sha256 for v in self.verified}

    def born(self):
        born = {}
        for v in self.verified:
            t = rekor.rfc3339(v.born, "origin.born")[0]
            born[v.spki_sha256] = min(born.get(v.spki_sha256, t), t)
        return born

    def pairs(self):
        pairs = {}
        for v in self.verified:
            pairs.setdefault(v.pair, []).append(v)
        return pairs


def unattested(c, recorded, born, now):
    if c.spki_sha256 not in recorded:
        if now - c.logged < POINTER_LATE:
            return Note(f"{c.source} names {', '.join(c.names)} with SPKI {c.spki_sha256}, which no verified record attests yet. CT made it public at {c.logged.isoformat(timespec='seconds')}, and it fails once {POINTER_LATE // timedelta(minutes=1)} minutes have passed without a pointer")
        return f"{c.source} names {', '.join(c.names)} with SPKI {c.spki_sha256}, which no verified record attests, and CT made it public at {c.logged.isoformat(timespec='seconds')}"
    if c.not_before > born[c.spki_sha256] + MAX_KEY_AGE:
        return f"{c.source} names {', '.join(c.names)} with SPKI {c.spki_sha256} from {c.not_before.isoformat(timespec='seconds')}, after the key, born at {born[c.spki_sha256].isoformat(timespec='seconds')}, was {MAX_KEY_AGE.days} days old"
    return None


def findings(ev):
    recorded, born = ev.recorded(), ev.born()
    return [(c, why) for c in ev.certificates if (why := unattested(c, recorded, born, ev.now))]


def failing(ev):
    return [c for c, why in findings(ev) if not isinstance(why, Note)]


def check_certificates(ev):
    recorded = ev.recorded()
    failures = [Note(f"{source} could not be read, so this run judges check 1 from {', '.join(ev.ct_counts)} alone: {e!r}") for source, e in ev.ct_unread.items()]
    for source, count in ev.ct_counts.items():
        others = {other: n for other, n in ev.ct_counts.items() if n}
        if count == 0 and (others or recorded):
            failures.append(f"{source} returned no certificate covering {ev.name}, though " + (", ".join(f"{o} returned {n}" for o, n in others.items()) if others else f"{len(recorded)} SPKIs have verified records"))
    for c, why in findings(ev):
        if isinstance(why, Note):
            failures.append(why)
            continue
        answer = ev.revocations.get(c.der, Revocation(None, "this run did not ask its CA"))
        if answer.revoked:
            failures.append(Note(f"revoked, skipped: {why}. Its CA revoked it, {answer.how}"))
        elif answer.revoked is False:
            failures.append(f"{why}. Its CA has not revoked it, {answer.how}")
        else:
            failures.append(f"{why}. Whether its CA revoked it is unknown, so it counts: {answer.how}")
    return failures


def check_records(ev):
    failures = list(ev.notes)
    for repo, (seen, tip) in sorted(ev.rewound.items()):
        failures.append(f"{repo} at {tip} does not descend from {seen}, which an earlier run saw, so its history was rewritten")
    return failures


def label(pair):
    return f"boot {pair[0]} with SPKI {pair[1]}"


def check_custody(ev):
    pairs, failures = ev.pairs(), []
    for pair, entries in sorted(pairs.items()):
        origins = sorted({v.origin for v in entries}, key=repr)
        if len(origins) > 1:
            failures.append(f"{label(pair)} has entries with {len(origins)} origins ({', '.join(v.name() for v in entries)}), and a boot fixes one origin per key")
            continue
        link, seen = pair, set()
        while True:
            _, sender, floor = pairs[link][0].origin
            if sender is None:
                break
            source = (sender, pair[1])
            if source not in pairs:
                failures.append(f"{label(pair)}: {label(link)} names sender {sender}, which has no verified record of that SPKI")
                break
            if pairs[source][0].floor > floor:
                failures.append(f"{label(pair)}: the floor falls from {pairs[source][0].floor} at {label(source)} to {floor} at {label(link)}")
                break
            if source in seen or source == pair:
                failures.append(f"{label(pair)}: custody loops at {label(source)}")
                break
            seen.add(link)
            link = source
    return failures


def check_logs(ev):
    return list(ev.shard_failures)


def caa_refusal(entry, accounts):
    match = re.fullmatch(r'\s*\d+\s+(\S+)\s+"(.*)"\s*', entry)
    if not match:
        return f"{entry!r} does not parse"
    tag, value = match.group(1).lower(), match.group(2)
    if tag == "iodef" or (tag in ("issue", "issuewild") and value.strip() == ";"):
        return None
    if tag not in ("issue", "issuewild"):
        return f"{entry} is a {tag} property this check does not allow"
    ca, *params = [p.strip() for p in value.split(";")]
    params = dict(p.split("=", 1) for p in params if "=" in p)
    if params.keys() != {"accounturi", "validationmethods"} or params["validationmethods"] != "dns-01" or (ca, params["accounturi"]) not in accounts:
        return f"{entry} is not one of Morse's ACME accounts with dns-01 only"
    return None


def check_caa(ev):
    if not ev.caa_history:
        return ["the CAA history has no samples"]
    failures = []
    for sample in ev.caa_history:
        if not any(re.match(r"\s*\d+\s+issue\s", e, re.I) for e in sample["caa"]):
            failures.append(f"at {sample['time']} no CAA issue property restricted who may issue")
        failures += [f"at {sample['time']}: {r}" for r in (caa_refusal(e, ev.caa_accounts) for e in sample["caa"]) if r]
    return failures


def live_boot(document, environment, history, now):
    payload = verified(document)
    try:
        made = datetime.fromtimestamp(payload["timestamp"] / 1000, timezone.utc)
        if now - made > MAX_AGE:
            raise Refused(f"AWS Nitro signed the document at {made.isoformat(timespec='seconds')}, {(now - made) // timedelta(minutes=1)} minutes before this run, and the relay refreshes each live document every 10 minutes and lists a peer's only while it is under 25 minutes old, so one older than {MAX_AGE // timedelta(minutes=1)} minutes is not live")
        if made - now > MAX_AHEAD:
            raise Refused(f"AWS Nitro signed the document at {made.isoformat(timespec='seconds')}, more than {MAX_AHEAD // timedelta(minutes=1)} minutes after this run's clock reads {now.isoformat(timespec='seconds')}, so this watcher's clock is behind")
        return Live(p256_spki(payload.get("public_key")), hpke_key_id(payload, environment), image_refusal(payload, environment, history))
    except Refused:
        raise
    except Exception as e:
        raise Refused(f"the document does not parse: {e!r}") from e


def check_live(ev):
    pairs, failures, held = ev.pairs(), [], set()
    if ev.last_run is not None and ev.now < ev.last_run - MAX_AHEAD:
        failures.append(f"this run's clock reads {ev.now.isoformat(timespec='seconds')}, before {ev.last_run.isoformat(timespec='seconds')}, when the last run wrote --sequence-state, and a clock that goes backwards stretches a boot's 2 hours")
    for n, seen in enumerate(ev.live, 1):
        if not isinstance(seen, Live):
            failures.append(f"live document {n}: {seen}")
            continue
        held.add((seen.key_id, seen.spki_sha256))
        if seen.unpinned:
            failures.append(f"live document {n} is from an image no record can admit: {seen.unpinned}")
        elif (seen.key_id, seen.spki_sha256) not in pairs and not ev.boots[seen.key_id].young(ev.now):
            failures.append(f"live document {n}: the boot with HPKE key {seen.key_id} holds SPKI {seen.spki_sha256}, which no verified record of that boot attests, and {ev.boots[seen.key_id].seen()}")
    for key_id, boot in sorted(ev.boots.items()):
        if boot.young(ev.now):
            continue
        for spki in boot.spkis:
            if (key_id, spki) not in held and (key_id, spki) not in pairs:
                failures.append(f"the boot with HPKE key {key_id} has no verified record of SPKI {spki}, which it held live, and {boot.seen()}")
    if ev.last_run is None:
        return failures + [UNENFORCED]
    if ev.now - ev.last_run > RUN_GAP:
        return failures + [Unenforced(f"check 6 not enforced on this run: the last run was at {ev.last_run.isoformat(timespec='seconds')}, more than {RUN_GAP.seconds // 60} minutes before this one, so a boot that served only in between cannot show, and a state file restored from an older copy shows this way too")]
    return failures


def parse_trust(source):
    """The witness list and k that an image's internal/door/trust.go compiles in."""
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


def check_witnesses(ev):
    failures = []
    if isinstance(ev.trust, Exception):
        failures.append(f"the newest pinned image's trust.go could not be read: {ev.trust}")
        trust_names = set()
    else:
        tag, k, listed = ev.trust
        trust_names = {w.name for w in listed}
        if k < ev.policy.k:
            failures.append(f"trust.go in {tag} needs {k} cosignatures, fewer than this watcher's {ev.policy.k}")
        mine = {(w.name, w.key): w.operator for w in ev.policy.witnesses}
        for w in listed:
            if (w.name, w.key) not in mine:
                failures.append(f"trust.go in {tag} lists the witness key {w.name}+{w.hash.hex()}, which this watcher's policy does not")
            elif mine[(w.name, w.key)] != w.operator:
                failures.append(f"trust.go in {tag} lists {w.name} under {w.operator}, and this watcher under {mine[(w.name, w.key)]}")
    for origin, (lines, last_seen) in sorted(ev.witnesses.items()):
        for name in sorted(set(lines) - ev.policy.names() - trust_names - {origin}):
            failures.append(f"{origin}'s newest checkpoint carries a cosignature by {name}, which neither this watcher's policy nor the image's trust.go names")
        for name in sorted(ev.policy.names()):
            if ev.now - last_seen[name] > WITNESS_LAPSE:
                failures.append(f"{name} has not cosigned a checkpoint of {origin} that this watcher read since {last_seen[name].isoformat(timespec='seconds')}, and with k = {ev.policy.k} of {len(ev.policy.names())} a missing witness leaves no margin")
    return failures


def check_records_public(ev):
    if ev.records_visibility == "public":
        return []
    return [f"{RECORDS_REPO_URL}, read with no token, {ev.records_visibility}, so an outside watcher cannot read the pointers or the leaf archive"]



CHECKS = [
    ("Every certificate in CT for the door's name holds a key a verified record attests (check 1)", check_certificates),
    ("Every pointer's entry verifies, and morse-pins and morse-records keep their history (check 2)", check_records),
    ("Every record's custody ends at a born record, with one origin per key and a floor that never falls (check 3)", check_custody),
    ("Each Rekor shard's checkpoint verifies and extends the last one this watcher accepted (check 4)", check_logs),
    ("CAA names only Morse's ACME accounts and dns-01 (check 5)", check_caa),
    ("The door's live attestation names only boots with verified records (check 6)", check_live),
    ("Only the publisher pushes data to morse-pins main, the signer's code is on the allowlist, every statement verifies, and no sign.yml run is missing (check 7)", signer_watch.check),
    ("The shard's witnesses match this watcher's policy and the newest pinned image's (check 8)", check_witnesses),
    ("morse-records is public (check 9)", check_records_public),
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
        visibility = json.loads(fetch(RECORDS_REPO_URL)).get("visibility")
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

    seen, certificates, ct_counts, ct_unread = set(), [], {}, {}
    for source in args.ct or ["crt.sh", "certspotter"]:
        try:
            read = read_ct(source, args.name)
        except (OSError, http.client.HTTPException, json.JSONDecodeError) as e:
            ct_unread[source] = e
            continue
        ct_counts[source] = 0
        for der, cert in [(der, parse_certificate(label_, der, logged)) for label_, der, logged in read]:
            if not any(covers(n, args.name) for n in cert.names):
                continue
            ct_counts[source] += 1
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
            v = verify_record(prove(p, shard, accepted, cache / "leaves", records_dir, shards, policy), args.environment, history)
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
            live.append(live_boot(base64.b64decode(instance), args.environment, history, now))
        except Refused as e:
            live.append(e)
    accounts = {tuple(a.split("=", 1)) for a in args.caa_account}
    boots = {key: boot if boot.first_seen is None or boot.first_seen <= now + MAX_AHEAD else Boot(None, boot.spkis) for key, boot in boots.items()}
    dated = last_run if last_run is not None and last_run <= now + MAX_AHEAD else None
    for seen_ in live:
        if isinstance(seen_, Live):
            boot = boots.get(seen_.key_id, Boot(dated, ()))
            boots[seen_.key_id] = Boot(boot.first_seen, tuple(sorted({*boot.spkis, seen_.spki_sha256})))
    ev = Evidence(args.name, args.environment, certificates, ct_counts, pointers, list(verified_.values()), notes, shard_failures, caa_history, accounts,
                  live, tips, rewound, witnesses, trust, records_visibility(), policy, boots, last_run, now, ct_unread=ct_unread)
    ev.checkpoints = checkpoints
    ev.revocations = {c.der: revocation.revocation(c.der, fetch) for c in failing(ev)}

    ev.signer, ev.signer_state = signer_watch.watch(pins_dir, args, saved["signer"], now, trusted_root, shards, policy)
    return ev


def read_state(state):
    saved = json.loads(state.read_text()) if state.exists() else {}
    last_run = None if saved.get("last_run") is None else datetime.fromisoformat(saved["last_run"])
    kept = signer_watch.SignerState.read(saved)
    # A state file from before a boot kept every SPKI it was seen live with held one in "spki_sha256".
    boots = {key: Boot(None if b["first_seen"] is None else datetime.fromisoformat(b["first_seen"]), tuple(sorted(set(b["spkis"] if "spkis" in b else [b["spki_sha256"]]))))
             for key, b in saved.get("boots", {}).items()}
    if any(t is not None and t.tzinfo is None for t in [last_run, kept.unlisted_since, kept.runs_read_at, *(b.first_seen for b in boots.values())]):
        raise ValueError(f"{state} holds a time with no zone")
    # A state file from before the watcher read Rekor kept the morse-pins tip it saw in "tip".
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
    args = parser.parse_args(argv)

    try:
        ev = gather(args)
    except Exception as e:
        print(f"FAIL: could not read the evidence: {e!r}")
        sys.exit(1)
    print(f"{len(ev.certificates)} certificates in CT cover {ev.name}. morse-records has {len(ev.pointers)} {ev.environment} pointers, and {len(ev.verified)} of their entries verify.\n")

    failed, unenforced = False, False
    for title, check in CHECKS:
        print(title)
        try:
            failures = check(ev)
        except Exception as e:
            failures = [f"the check could not run: {e!r}"]
        for failure in failures:
            print(f"  {'NOT ENFORCED' if isinstance(failure, Unenforced) else 'NOTE' if isinstance(failure, Note) else 'FAIL'}: {failure}")
        if not [f for f in failures if not isinstance(f, Note)]:
            print("  OK")
        print()
        failed = failed or any(not isinstance(f, (Unenforced, Note)) for f in failures)
        unenforced = unenforced or any(isinstance(f, Unenforced) for f in failures)
    write_state(Path(args.sequence_state), ev)
    sys.exit(1 if failed else 2 if unenforced else 0)


if __name__ == "__main__":
    main()

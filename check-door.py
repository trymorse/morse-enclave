# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2==6.1.5", "cryptography==50.0.2"]
# ///
"""Checks that every certificate for Morse's inference door holds a key that a pinned prod enclave attests.

Usage: uv run check-door.py --pins <morse-pins checkout> --caa-history caa.jsonl --sequence-state sequence.json --caa-account <ca>=<account uri> ...

It reads Certificate Transparency for inference.trymorse.ai and every wildcard that covers it, the boot records
in morse-pins, the CAA record, and the door's live attestation, and runs the six checks in the README.
It exits 1 if any check fails, and 2 if none fails but check 6 is not enforced.
"""

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import types
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

NAME = "inference.trymorse.ai"
CRTSH_URL = "https://crt.sh/?q=%25.{}&output=json"
CRTSH_CERT_URL = "https://crt.sh/?d={}"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={}&match_wildcards=true&expand=dns_names&expand=cert_der"
ATTESTATION_URL = "https://inference.trymorse.ai/v1/attestation"
DOH_URL = "https://dns.google/resolve?name={}&type=CAA"
STATEMENT_TYPE = "morse-door-records-v1"
ORIGIN_TYPE = "morse-door-origin-v1"
LIVE_GRACE = timedelta(hours=2)
RUN_GAP = timedelta(minutes=7)
MAX_AHEAD = timedelta(minutes=2)
MAX_AGE = timedelta(seconds=nitro.MAX_AGE_SECONDS)


@dataclass(frozen=True)
class Certificate:
    source: str
    names: list
    spki_sha256: str
    not_after: datetime


@dataclass(frozen=True)
class Record:
    path: Path
    document: str | None
    born: str | None
    sender: str | None
    floor: int | None


@dataclass(frozen=True)
class Attested:
    spki_sha256: str
    key_id: str


@dataclass(frozen=True)
class Live:
    spki_sha256: str
    key_id: str
    unpinned: str | None


@dataclass(frozen=True)
class Boot:
    first_seen: datetime | None
    spki_sha256: str

    def young(self, now):
        return self.first_seen is not None and now - self.first_seen < LIVE_GRACE

    def seen(self):
        if self.first_seen is None:
            return "this watcher cannot date when it first saw it live, so how long it served is unknown"
        return f"this watcher first saw it live at {self.first_seen.isoformat(timespec='seconds')}"


class Unenforced(str):
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


def parse_certificate(source, der):
    cert = x509.load_der_x509_certificate(der)
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    names += [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    return Certificate(source, list(dict.fromkeys(names)), spki_sha256(cert.public_key()), cert.not_valid_after_utc)


def read_ct(source, name):
    if source == "crt.sh":
        rows = json.loads(fetch(CRTSH_URL.format(name.split(".", 1)[1])))
        ids = sorted({r["id"] for r in rows if any(covers(n, name) for n in r["name_value"].split("\n"))})
        return [(f"crt.sh {i}", x509.load_pem_x509_certificate(fetch(CRTSH_CERT_URL.format(i))).public_bytes(serialization.Encoding.DER)) for i in ids]
    if source == "certspotter":
        entries, after = [], None
        while True:
            page = json.loads(fetch(CERTSPOTTER_URL.format(name) + (f"&after={after}" if after else "")))
            if not page:
                return entries
            entries += [(f"certspotter {i['id']}", base64.b64decode(i["cert_der"])) for i in page]
            after = page[-1]["id"]
    with open(source) as f:
        return [(f"{source} {i['id']}", base64.b64decode(i["cert_der"])) for i in json.load(f)]


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
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)", born, re.ASCII)
    if not match:
        raise Refused(f"origin.born {born!r} is not an RFC 3339 time")
    try:
        utc = datetime.fromisoformat(match[1] + ("+00:00" if match[3] == "Z" else match[3])).astimezone(timezone.utc)
    except (ValueError, OverflowError) as e:
        raise Refused(f"origin.born {born!r} is not a time UTC can hold: {e}") from e
    fraction = (match[2] or "").rstrip("0")
    return utc.strftime("%Y-%m-%dT%H:%M:%S") + (f".{fraction}" if fraction else "") + "Z"


def origin_nonce(spki_sha256, born, sender, floor):
    statement = {"origin": {"born": canonical_time(born), "floor": floor, "from": sender and sender.lower()}, "spki_sha256": spki_sha256, "type": ORIGIN_TYPE}
    return hashlib.sha256(json.dumps(statement, separators=(",", ":"), sort_keys=True).encode()).digest()


def image_refusal(payload, environment, history):
    pcrs = [payload["pcrs"][i].hex() for i in range(3)]
    made = datetime.fromtimestamp(payload["timestamp"] / 1000, timezone.utc)
    if any(p["environment"] == environment and not p["revoked"] and [p["pcr0"], p["pcr1"], p["pcr2"]] == pcrs for p in pins_at(history, made)):
        return None
    return f"morse-pins lists no unrevoked {environment} image with the document's PCRs at {made.isoformat(timespec='seconds')}, when the document was made"


def attest(record, environment, history):
    if record.document is None:
        raise Refused("the record is not a JSON object with a document and an origin of born, from and an integer floor")
    try:
        payload = verified(base64.b64decode(record.document, validate=True))
        key_id = hpke_key_id(payload, environment)
        refusal = image_refusal(payload, environment, history)
        if refusal:
            raise Refused(refusal)
        spki = p256_spki(payload.get("public_key"))
        if payload.get("nonce") != origin_nonce(spki, record.born, record.sender, record.floor):
            raise Refused("the document's nonce is not the origin statement of its SPKI and the record's origin, so the enclave did not attest this origin")
    except Refused:
        raise
    except Exception as e:
        raise Refused(f"the record does not parse: {e!r}") from e
    return Attested(spki, key_id)


def read_record(path):
    try:
        record = json.loads(path.read_bytes())
        document, origin = record["document"], record["origin"]
        born, sender, floor = origin["born"], origin["from"], origin["floor"]
    except (ValueError, KeyError, TypeError):
        return Record(path, None, None, None, None)
    if not isinstance(document, str) or not isinstance(born, str) or not isinstance(sender, (str, type(None))) or type(floor) is not int:
        return Record(path, None, None, None, None)
    return Record(path, document, born, sender, floor)


@dataclass
class Evidence:
    name: str
    environment: str
    records_dir: Path
    certificates: list
    records: list
    attested: dict
    caa_history: list
    caa_accounts: set
    live: list
    seen_sequence: int
    ct_counts: dict
    tip: str
    seen_tip: str | None
    rewound: bool
    boots: dict = field(default_factory=dict)
    last_run: datetime | None = None
    now: datetime = field(default_factory=lambda: utcnow())

    def recorded(self):
        return {a.spki_sha256 for a in self.attested.values() if isinstance(a, Attested)}

    def carried(self):
        return {a.key_id for a in self.attested.values() if isinstance(a, Attested)}

    def pending(self):
        live = {seen.spki_sha256 for seen in self.live if isinstance(seen, Live) and seen.unpinned is None}
        young = {}
        for boot in self.boots.values():
            young[boot.spki_sha256] = young.get(boot.spki_sha256, True) and boot.young(self.now)
        return {spki for spki in live if young.get(spki)}


def check_certificates(ev):
    recorded = ev.recorded() | ev.pending()
    empty = [
        f"{source} returned no certificate covering {ev.name}, though morse-pins has {len(ev.records)} records"
        for source, count in ev.ct_counts.items()
        if count == 0 and ev.records
    ]
    return empty + [
        f"{c.source} names {', '.join(c.names)} with SPKI {c.spki_sha256}, which no record's document attests"
        for c in ev.certificates
        if c.spki_sha256 not in recorded
    ]


def check_custody(ev):
    by_key, failures = {}, []
    for r, a in ev.attested.items():
        if not isinstance(a, Attested):
            continue
        if a.key_id in by_key:
            failures.append(f"{by_key[a.key_id].path.name} and {r.path.name} carry the same HPKE key {a.key_id}, and each boot has one record")
        by_key.setdefault(a.key_id, r)
    for record in ev.records:
        link, seen = record, set()
        while True:
            a = ev.attested[link]
            if not isinstance(a, Attested):
                failures.append(f"{record.path.name}: custody link {link.path.name} does not verify: {a}")
                break
            if link.sender is None:
                break
            sender = by_key.get(link.sender)
            if sender is None:
                failures.append(f"{record.path.name}: {link.path.name} names sender {link.sender}, whose HPKE key no record that verifies carries")
                break
            if link.floor < sender.floor:
                failures.append(f"{record.path.name}: the floor falls from {sender.floor} in {sender.path.name} to {link.floor} in {link.path.name}")
                break
            if sender in seen:
                failures.append(f"{record.path.name}: custody loops at {sender.path.name}")
                break
            seen.add(link)
            link = sender
    return failures


def read_statements(records_dir):
    return sorted(((int(p.stem), json.loads(p.read_bytes())) for p in (records_dir / "statements").glob("*.json")), key=lambda s: s[0])


def check_statements(ev):
    statements = read_statements(ev.records_dir)
    failures, listed = [], {}
    latest = statements[-1][0] if statements else 0
    if latest < ev.seen_sequence:
        failures.append(f"the latest statement is sequence {latest}, and an earlier run saw sequence {ev.seen_sequence}")
    if ev.rewound:
        failures.append(f"morse-pins at {ev.tip} does not descend from {ev.seen_tip}, which an earlier run saw, so its history was rewritten")
    for expected, (sequence, statement) in enumerate(statements, 1):
        if sequence != expected:
            return failures + [f"the statements skip sequence {expected}"]
        if statement.get("type") != STATEMENT_TYPE or statement.get("environment") != ev.environment or statement.get("sequence") != sequence:
            failures.append(f"statement {sequence} is not a {ev.environment} {STATEMENT_TYPE} statement at sequence {sequence}")
        failures += [f"statement {sequence} drops or changes {path}, which statement {sequence - 1} lists" for path, digest in listed.items() if statement["records"].get(path) != digest]
        listed = statement["records"]
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in ev.records_dir.glob("*.json")}
    failures += [f"{path} is not in the latest statement as it is" for path, digest in files.items() if listed.get(path) != digest]
    failures += [f"the latest statement lists {path}, which the repository does not have" for path in listed if path not in files]
    return failures


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
    recorded, carried = ev.recorded(), ev.carried()
    failures = []
    if ev.last_run is not None and ev.now < ev.last_run - MAX_AHEAD:
        failures.append(f"this run's clock reads {ev.now.isoformat(timespec='seconds')}, before {ev.last_run.isoformat(timespec='seconds')}, when the last run wrote --sequence-state, and a clock that goes backwards stretches a boot's 2 hours")
    for n, seen in enumerate(ev.live, 1):
        if not isinstance(seen, Live):
            failures.append(f"live document {n}: {seen}")
        elif seen.unpinned:
            failures.append(f"live document {n} is from an image no record can admit: {seen.unpinned}")
        elif seen.spki_sha256 not in recorded:
            failures.append(f"live document {n} attests SPKI {seen.spki_sha256}, which no record attests")
    for key_id, boot in sorted(ev.boots.items()):
        if key_id in carried:
            continue
        if boot.spki_sha256 not in recorded:
            failures.append(f"the boot with HPKE key {key_id} has no record, and its SPKI {boot.spki_sha256} is in no record either; {boot.seen()}")
        elif not boot.young(ev.now):
            failures.append(f"the boot with HPKE key {key_id} has no record, and {boot.seen()}")
    if ev.last_run is None:
        return failures + [UNENFORCED]
    if ev.now - ev.last_run > RUN_GAP:
        return failures + [Unenforced(f"check 6 not enforced on this run: the last run was at {ev.last_run.isoformat(timespec='seconds')}, more than {RUN_GAP.seconds // 60} minutes before this one, so a boot that served only in between cannot show, and a state file restored from an older copy shows this way too")]
    return failures


CHECKS = [
    ("Every certificate in CT for the door's name holds a key a record attests (checks 1 and 2)", check_certificates),
    ("Every record's custody ends at a born record, and the floor never falls (check 3)", check_custody),
    ("The records statements have no gaps and list every record (check 4)", check_statements),
    ("CAA names only Morse's ACME accounts and dns-01 (check 5)", check_caa),
    ("The door's live attestation names only recorded keys and boots (check 6)", check_live),
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


def gather(args):
    attestation = fetch(args.attestation) if args.attestation.startswith("https://") else Path(args.attestation).read_bytes()
    now = utcnow()
    pins_dir = Path(args.pins)
    history = read_pins_history(pins_dir)
    records_dir = pins_dir / "records" / args.environment
    records = [read_record(p) for p in sorted(records_dir.glob("*.json"))]
    attested = {}
    for record in records:
        try:
            attested[record] = attest(record, args.environment, history)
        except Refused as e:
            attested[record] = e

    seen, certificates, ct_counts = set(), [], {}
    for source in args.ct or ["crt.sh", "certspotter"]:
        ct_counts[source] = 0
        for label, der in read_ct(source, args.name):
            cert = parse_certificate(label, der)
            if not any(covers(n, args.name) for n in cert.names):
                continue
            ct_counts[source] += 1
            if hashlib.sha256(der).digest() in seen:
                continue
            seen.add(hashlib.sha256(der).digest())
            if args.since is None or cert.not_after >= args.since:
                certificates.append(cert)

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
    saved, last_run, boots = read_state(Path(args.sequence_state))
    boots = {key: boot if boot.first_seen is None or boot.first_seen <= now + MAX_AHEAD else Boot(None, boot.spki_sha256) for key, boot in boots.items()}
    dated = last_run if last_run is not None and last_run <= now + MAX_AHEAD else None
    for seen in live:
        if isinstance(seen, Live):
            boots.setdefault(seen.key_id, Boot(dated, seen.spki_sha256))
    tip = git(pins_dir, "rev-parse", "HEAD").strip()
    seen_tip = saved.get("tip")
    rewound = seen_tip is not None and subprocess.run(["git", "-C", str(pins_dir), "merge-base", "--is-ancestor", seen_tip, "HEAD"], capture_output=True).returncode != 0
    return Evidence(args.name, args.environment, records_dir, certificates, records, attested, caa_history, accounts, live, saved.get("sequence", 0), ct_counts, tip, seen_tip, rewound, boots, last_run, now)


def read_state(state):
    if not state.exists():
        return {}, None, {}
    saved = json.loads(state.read_text())
    last_run = None if saved.get("last_run") is None else datetime.fromisoformat(saved["last_run"])
    boots = {key: Boot(None if b["first_seen"] is None else datetime.fromisoformat(b["first_seen"]), b["spki_sha256"]) for key, b in saved.get("boots", {}).items()}
    if any(t is not None and t.tzinfo is None for t in [last_run, *(b.first_seen for b in boots.values())]):
        raise ValueError(f"{state} holds a time with no zone")
    return saved, last_run, boots


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pins", required=True, help="a full-history checkout of morse-pins, with enclave_pins.json and records/")
    parser.add_argument("--caa-history", required=True, help="a JSON lines file of CAA samples; each run appends one")
    parser.add_argument("--caa-account", action="append", default=[], metavar="CA=URI", help="an ACME account CAA may name, such as letsencrypt.org=https://acme-v02.api.letsencrypt.org/acme/acct/1")
    parser.add_argument("--sequence-state", required=True, help="a JSON file holding the highest records statement sequence any run has seen and the morse-pins commit it saw, which each run raises, when this watcher last ran, and every boot it has seen live with when it first saw it")
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
    print(f"{len(ev.certificates)} certificates in CT cover {ev.name}. morse-pins has {len(ev.records)} {ev.environment} records.\n")

    failed, unenforced = False, False
    for title, check in CHECKS:
        print(title)
        try:
            failures = check(ev)
        except Exception as e:
            failures = [f"the check could not run: {e!r}"]
        for failure in failures:
            print(f"  {'NOT ENFORCED' if isinstance(failure, Unenforced) else 'FAIL'}: {failure}")
        if not failures:
            print("  OK")
        print()
        failed = failed or any(not isinstance(f, Unenforced) for f in failures)
        unenforced = unenforced or any(isinstance(f, Unenforced) for f in failures)
    latest = max([s for s, _ in read_statements(ev.records_dir)], default=0)
    boots = {key: {"first_seen": b.first_seen and b.first_seen.isoformat(), "spki_sha256": b.spki_sha256} for key, b in sorted(ev.boots.items())}
    Path(args.sequence_state).write_text(json.dumps({"sequence": max(latest, ev.seen_sequence), "tip": ev.seen_tip if ev.rewound else ev.tip, "last_run": ev.now.isoformat(), "boots": boots}))
    sys.exit(1 if failed else 2 if unenforced else 0)


if __name__ == "__main__":
    main()

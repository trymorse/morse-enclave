import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

Refused = nitro.Refused
Refusal = rekor.Refusal

ORIGIN_TYPE = "morse-door-origin-v1"
RECORD_TYPE = "morse-door-boot-v1"
RECORD_OID = "1.3.6.1.4.1.67561.1"
MAX_AHEAD = timedelta(minutes=2)
MAX_AGE = timedelta(seconds=nitro.MAX_AGE_SECONDS)


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


def spki_sha256(key):
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def p256_spki(public_key):
    try:
        key = serialization.load_der_public_key(public_key or b"")
    except ValueError as e:
        raise Refused("the document's public_key is not a SubjectPublicKeyInfo") from e
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise Refused("the document's public_key is not a P-256 key")
    return spki_sha256(key)


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

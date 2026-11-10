"""Rekor v2 entries, verified offline, for check-door.py, which reads this file. It is not a script.

It checks the logs of Sigstore's trusted_root.json, signed notes and their cosignature/v1 cosignatures, RFC 9162
inclusion and consistency proofs, C2SP tlog-tiles, and the strict hashedrekord v0.0.2 body. The door's enclave runs
the same checks before it serves.
"""

import base64
import binascii
import hashlib
import json
import re
import urllib.error
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

LOG_SIGNATURE_ALG = 0x01
COSIGNATURE_ALG = 0x04
MAX_NOTE_SIGNATURES = 100
TILE_HEIGHT = 8
TILE_WIDTH = 1 << TILE_HEIGHT
HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", re.ASCII)


class Refusal(Exception):
    """Why an entry does not prove a boot record. The reasons up to not_this_record are Rekor v2's own."""

    def __init__(self, reason, detail):
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail = reason, detail


def rfc3339(value, what):
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)", value, re.ASCII) if isinstance(value, str) else None
    if not match:
        raise ValueError(f"{what} {value!r} is not an RFC 3339 time")
    try:
        utc = datetime.fromisoformat(match[1] + ("+00:00" if match[3] == "Z" else match[3])).astimezone(timezone.utc)
    except (ValueError, OverflowError) as e:
        raise ValueError(f"{what} {value!r} is not a time UTC can hold: {e}") from e
    return utc, (match[2] or "").rstrip("0")


def strict_json(raw):
    def unique(pairs):
        keys = [k for k, _ in pairs]
        if len(set(keys)) != len(keys):
            raise ValueError("a JSON object repeats a key")
        return dict(pairs)

    def constant(name):
        raise ValueError(f"{name} is not JSON")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=constant)


def only(obj, *allowed, required=()):
    if not isinstance(obj, dict):
        raise ValueError(f"{json.dumps(obj)[:40]} is not a JSON object")
    for key in obj:
        if key not in allowed:
            raise ValueError(f"unknown field {key!r}")
    for key in required:
        if obj.get(key) is None:
            raise ValueError(f"no {key}")
    return obj


def b64(value, what):
    if not isinstance(value, str):
        raise ValueError(f"{what} is not a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"{what} is not base64") from e


def b64_string(raw):
    return base64.b64encode(raw).decode()


def proto_uint(value, what):
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value, re.ASCII):
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 64:
        raise ValueError(f"{what} is not an unsigned integer")
    return value


def key_hash(name, alg, key):
    return hashlib.sha256(name.encode() + b"\n" + bytes([alg]) + key).digest()[:4]


def ed25519_verifies(key, signature, message):
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def valid_name(name):
    return name != "" and not any(c in name for c in " +\n\t")


@dataclass(frozen=True)
class Witness:
    name: str
    operator: str
    key: bytes

    @property
    def hash(self):
        return key_hash(self.name, COSIGNATURE_ALG, self.key)


def parse_witness(vkey, operator):
    name, _, rest = vkey.partition("+")
    hash_hex, _, key_b64 = rest.partition("+")
    try:
        raw = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError):
        raw = b""
    if not valid_name(name) or not operator or len(raw) != 33 or raw[0] != COSIGNATURE_ALG:
        raise ValueError(f"{vkey!r} is not a cosignature/v1 Ed25519 verifier key with an operator")
    w = Witness(name, operator, raw[1:])
    if w.hash.hex() != hash_hex:
        raise ValueError(f"the key hash of {name} is not its key's")
    return w


@dataclass(frozen=True)
class Cosigner:
    name: str
    operator: str
    time: datetime


@dataclass(frozen=True)
class Policy:
    k: int
    witnesses: tuple

    def names(self):
        return {w.name for w in self.witnesses}

    def count(self, text, signatures):
        earliest = {}
        for name, hash_, sig in signatures:
            for w in self.witnesses:
                if w.name != name or w.hash != hash_ or len(sig) != 8 + 64:
                    continue
                seconds = int.from_bytes(sig[:8], "big")
                # 253402300799 is the last second of year 9999, as far as a Python datetime goes.
                if seconds > 253402300799 or not ed25519_verifies(w.key, sig[8:], b"cosignature/v1\ntime %d\n" % seconds + text):
                    continue
                t = datetime.fromtimestamp(seconds, timezone.utc)
                if w.operator not in earliest or t < earliest[w.operator].time:
                    earliest[w.operator] = Cosigner(w.name, w.operator, t)
        return sorted(earliest.values(), key=lambda c: (c.time, c.operator))


def make_policy(k, listed):
    witnesses = [parse_witness(vkey, operator) for vkey, operator in listed]
    operator_of = {}
    for i, w in enumerate(witnesses):
        if operator_of.setdefault(w.name, w.operator) != w.operator:
            raise ValueError(f"{w.name} is listed under {operator_of[w.name]} and {w.operator}")
        if any(v.key == w.key for v in witnesses[:i]):
            raise ValueError(f"a key of {w.name} is listed twice")
    if k < 1 or k > len(set(operator_of.values())):
        raise ValueError(f"k is {k} and {len(set(operator_of.values()))} operators are listed")
    return Policy(k, tuple(witnesses))


@dataclass(frozen=True)
class Shard:
    origin: str
    base_url: str
    key: bytes
    start: datetime
    end: datetime | None

    @property
    def log_id(self):
        return hashlib.sha256(self.origin.encode() + b"\n\x01" + self.key).digest()

    def valid_at(self, t):
        return t >= self.start and (self.end is None or t <= self.end)


def origin_of(base_url):
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme != "https" or not HOST.fullmatch(parts.netloc) or parts.path not in ("", "/") or "?" in base_url or "#" in base_url:
        raise ValueError(f"baseUrl {base_url!r} is not https and a host name alone")
    return parts.netloc


def read_shards(trusted_root):
    """The Ed25519 logs of a trusted_root.json, by log id. A log with another key, Rekor v1's among them, is left out."""
    shards, skipped = {}, []
    for i, tlog in enumerate(strict_json(trusted_root).get("tlogs") or []):
        try:
            public = tlog["publicKey"]
            if public.get("keyDetails") != "PKIX_ED25519":
                continue
            origin = origin_of(tlog["baseUrl"])
            key = serialization.load_der_public_key(b64(public["rawBytes"], "rawBytes"))
            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise ValueError("the key is not Ed25519")
            if tlog.get("hashAlgorithm") != "SHA2_256" or not (public.get("validFor") or {}).get("start"):
                raise ValueError("another hash or no validity start")
            valid = public["validFor"]
            shard = Shard(origin, tlog["baseUrl"].rstrip("/"), key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                          rfc3339(valid["start"], "validFor.start")[0], rfc3339(valid["end"], "validFor.end")[0] if valid.get("end") else None)
            if b64(tlog["logId"]["keyId"], "keyId") != shard.log_id:
                raise ValueError("the log id is not the note key hash")
        except (KeyError, TypeError, ValueError) as e:
            skipped.append(f"Sigstore's trusted root lists tlog {i} in a form this watcher cannot read: {e}")
            continue
        if shard.log_id in shards:
            raise ValueError(f"Sigstore's trusted root lists two logs with the id of {shard.origin}")
        shards[shard.log_id] = shard
    if not shards:
        raise ValueError(f"Sigstore's trusted root lists no Ed25519 log this watcher can read: {skipped}")
    return shards, skipped


def parse_note(note):
    if "\r" in note or "\x00" in note:
        raise ValueError("the note is not plain text")
    split = note.rfind("\n\n")
    if split < 0 or not note.endswith("\n"):
        raise ValueError("the note has no signature block")
    lines = note[split + 2:-1].split("\n")
    if len(lines) > MAX_NOTE_SIGNATURES:
        raise ValueError(f"the note has {len(lines)} signature lines")
    signatures = []
    for line in lines:
        name, sep, encoded = line.removeprefix("— ").partition(" ")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raw = b""
        if not line.startswith("— ") or not sep or not valid_name(name) or len(raw) < 5:
            raise ValueError(f"the signature line {line!r} is malformed")
        signatures.append((name, raw[:4], raw[4:]))
    return note[:split + 1].encode(), signatures


def parse_checkpoint_text(text):
    lines = text.decode().removesuffix("\n").split("\n")
    if len(lines) < 3 or lines[0] == "":
        raise ValueError("the checkpoint has fewer than three lines")
    if not re.fullmatch(r"0|[1-9][0-9]{0,19}", lines[1], re.ASCII) or int(lines[1]) >= 1 << 64:
        raise ValueError(f"the checkpoint's size {lines[1]!r} is not a decimal number")
    try:
        root = base64.b64decode(lines[2], validate=True)
    except (binascii.Error, ValueError):
        root = b""
    if len(root) != 32:
        raise ValueError("the checkpoint's root hash is not 32 bytes of base64")
    if "" in lines[3:]:
        raise ValueError("the checkpoint has an empty extension line")
    return lines[0], int(lines[1]), root


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root: bytes
    note: str
    cosigners: tuple
    lines: tuple


def verify_note(note, shard, policy, size=None, root=None):
    """A checkpoint the shard signed and at least k of policy's witnesses cosigned, while the shard was valid."""
    try:
        text, signatures = parse_note(note)
        origin, note_size, note_root = parse_checkpoint_text(text)
    except (ValueError, UnicodeDecodeError) as e:
        raise Refusal("checkpoint", str(e)) from e
    if origin != shard.origin:
        raise Refusal("checkpoint", f"the checkpoint's origin {origin!r} is not {shard.origin!r}")
    if size is not None and note_size != size:
        raise Refusal("checkpoint", f"the checkpoint's size {note_size} is not the proof's {size}")
    if root is not None and note_root != root:
        raise Refusal("checkpoint", "the checkpoint's root hash is not the proof's")
    log_hash = key_hash(shard.origin, LOG_SIGNATURE_ALG, shard.key)
    if not any(name == shard.origin and h == log_hash and len(sig) == 64 and ed25519_verifies(shard.key, sig, text) for name, h, sig in signatures):
        raise Refusal("log_signature", f"no signature line by {shard.origin} verifies under its key")
    counted = policy.count(text, signatures)
    if len(counted) < policy.k:
        raise Refusal("witnesses", f"{len(counted)} of the {policy.k} cosignatures needed")
    when = counted[policy.k - 1].time
    if not shard.valid_at(when):
        raise Refusal("log_not_valid_now", f"{shard.origin} is not valid at {when.isoformat()}")
    return Checkpoint(origin, note_size, note_root, note, tuple(counted), tuple(name for name, _, _ in signatures))


def leaf_hash(body):
    return hashlib.sha256(b"\x00" + body).digest()


def node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def root_from_inclusion(index, size, leaf, proof):
    """The RFC 9162 Section 2.1.3.2 inclusion check, folded from the leaf at index to the root of a tree of size."""
    if index >= size:
        raise ValueError(f"leaf index {index} is outside a tree of size {size}")
    inner = (index ^ (size - 1)).bit_length()
    border = bin(index >> inner).count("1")
    if len(proof) != inner + border:
        raise ValueError(f"the inclusion proof has {len(proof)} hashes, not {inner + border}")
    h = leaf
    for i, p in enumerate(proof[:inner]):
        h = node_hash(h, p) if (index >> i) & 1 == 0 else node_hash(p, h)
    for p in proof[inner:]:
        h = node_hash(p, h)
    return h


def consistent(size1, size2, root1, root2, proof):
    """The RFC 9162 Section 2.1.4.2 consistency check: the tree of size2 extends the tree of size1."""
    if size1 > size2:
        return False
    if size1 == size2:
        return not proof and root1 == root2
    if size1 == 0:
        return not proof
    if not proof:
        return False
    if size1 & (size1 - 1) == 0:
        proof = [root1, *proof]
    fn, sn = size1 - 1, size2 - 1
    while fn & 1:
        fn, sn = fn >> 1, sn >> 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            while fn & 1 == 0 and fn != 0:
                fn, sn = fn >> 1, sn >> 1
        else:
            sr = node_hash(sr, c)
        fn, sn = fn >> 1, sn >> 1
    return sn == 0 and fr == root1 and sr == root2


def tile_index(n):
    digits = f"{n:03d}"
    digits = "0" * (-len(digits) % 3) + digits
    groups = [digits[i:i + 3] for i in range(0, len(digits), 3)]
    return "/".join([f"x{g}" for g in groups[:-1]] + groups[-1:])


class Tiles:
    """A shard's C2SP tlog-tiles, read for a tree of size. Nothing read here is trusted: every proof built from it
    is checked against a verified checkpoint's root hash before it counts."""

    def __init__(self, shard, size, fetch):
        self.base, self.size, self.get, self.read = f"{shard.base_url}/api/v2/", size, fetch, {}

    def fetch(self, path, width, unit):
        if path not in self.read:
            data = None
            try:
                data = self.get(self.base + path + (f".p/{width}" if width < TILE_WIDTH else ""))
            except urllib.error.HTTPError:
                if width == TILE_WIDTH:
                    raise
                data = self.get(self.base + path)
            self.read[path] = data
        return self.read[path]

    def tile(self, level, n):
        width = min(TILE_WIDTH, (self.size >> (TILE_HEIGHT * level)) - n * TILE_WIDTH)
        if width < 1:
            raise ValueError(f"a tree of size {self.size} has no tile {level}/{n}")
        data = self.fetch(f"tile/{level}/{tile_index(n)}", width, 32)
        if len(data) < width * 32 or (width < TILE_WIDTH and len(data) not in (width * 32, TILE_WIDTH * 32)):
            raise ValueError(f"tile {level}/{n} is {len(data)} bytes, not {width} hashes")
        return data

    def hash(self, level, index):
        """The stored hash of the complete subtree of 2**level leaves at index, from one tile."""
        tile_level, rise = divmod(level, TILE_HEIGHT)
        n, at = divmod(index << rise, TILE_WIDTH)
        data = self.tile(tile_level, n)
        hashes = [data[(at + i) * 32:(at + i + 1) * 32] for i in range(1 << rise)]
        if len(hashes[-1]) != 32:
            raise ValueError(f"tile {tile_level}/{n} holds no hash at {at + len(hashes) - 1}")
        while len(hashes) > 1:
            hashes = [node_hash(hashes[i], hashes[i + 1]) for i in range(0, len(hashes), 2)]
        return hashes[0]

    def subtree(self, start, size):
        if size & (size - 1) == 0 and start % size == 0:
            return self.hash(size.bit_length() - 1, start // size)
        k = 1 << ((size - 1).bit_length() - 1)
        return node_hash(self.subtree(start, k), self.subtree(start + k, size - k))

    def inclusion(self, index):
        def path(m, start, n):
            if n == 1:
                return []
            k = 1 << ((n - 1).bit_length() - 1)
            if m < k:
                return path(m, start, k) + [self.subtree(start + k, n - k)]
            return path(m - k, start + k, n - k) + [self.subtree(start, k)]
        return path(index, 0, self.size)

    def consistency(self, older):
        def subproof(m, start, n, whole):
            if m == n:
                return [] if whole else [self.subtree(start, m)]
            k = 1 << ((n - 1).bit_length() - 1)
            if m <= k:
                return subproof(m, start, k, whole) + [self.subtree(start + k, n - k)]
            return subproof(m - k, start + k, n - k, False) + [self.subtree(start, k)]
        return [] if older in (0, self.size) else subproof(older, 0, self.size, True)

    def entry(self, index):
        n, at = divmod(index, TILE_WIDTH)
        width = min(TILE_WIDTH, self.size - n * TILE_WIDTH)
        data, entries = self.fetch(f"tile/entries/{tile_index(n)}", width, None), []
        while data:
            if len(data) < 2 or len(data) < 2 + int.from_bytes(data[:2], "big"):
                raise ValueError(f"entry bundle {n} is truncated")
            length = int.from_bytes(data[:2], "big")
            entries.append(data[2:2 + length])
            data = data[2 + length:]
        if len(entries) < width or (width < TILE_WIDTH and len(entries) not in (width, TILE_WIDTH)):
            raise ValueError(f"entry bundle {n} holds {len(entries)} entries, not {width}")
        return entries[at]


ENTRY_KEYS = {
    "": ("logIndex", "logId", "kindVersion", "integratedTime", "inclusionPromise", "inclusionProof", "canonicalizedBody"),
    "logId": ("keyId",),
    "kindVersion": ("kind", "version"),
    "inclusionProof": ("logIndex", "rootHash", "treeSize", "hashes", "checkpoint"),
    "inclusionProof.checkpoint": ("envelope",),
}


def parse_entry(raw):
    entry = strict_json(raw)

    def exact(obj, path):
        only(obj, *ENTRY_KEYS[path])
        for key, value in obj.items():
            child = f"{path}.{key}" if path else key
            if child in ENTRY_KEYS:
                exact(value, child)

    exact(entry, "")
    proof = entry.get("inclusionProof", {})
    hashes = proof.get("hashes") if proof.get("hashes") is not None else []
    if not isinstance(hashes, list):
        raise ValueError("hashes is not a list")
    return {
        "index": proto_uint(entry.get("logIndex", 0), "logIndex"),
        "log_id": b64(entry.get("logId", {}).get("keyId", ""), "keyId"),
        "kind": entry.get("kindVersion", {}).get("kind", ""),
        "version": entry.get("kindVersion", {}).get("version", ""),
        "proof_index": proto_uint(proof.get("logIndex", 0), "inclusionProof.logIndex"),
        "root": b64(proof.get("rootHash", ""), "rootHash"),
        "size": proto_uint(proof.get("treeSize", 0), "treeSize"),
        "hashes": [b64(h, "a proof hash") for h in hashes],
        "envelope": proof.get("checkpoint", {}).get("envelope", ""),
        "body": b64(entry.get("canonicalizedBody", ""), "canonicalizedBody"),
    }


@dataclass(frozen=True)
class HashedRekord:
    digest: bytes
    signature: bytes
    certificate: bytes


def parse_hashed_rekord(raw):
    def exact(obj, *keys):
        return only(obj, *keys, required=keys)

    def string(value, want, what):
        if value != want:
            raise ValueError(f"{what} is {json.dumps(value)}, not {want!r}")

    top = exact(strict_json(raw), "apiVersion", "kind", "spec")
    string(top["apiVersion"], "0.0.2", "apiVersion")
    string(top["kind"], "hashedrekord", "kind")
    v002 = exact(exact(top["spec"], "hashedRekordV002")["hashedRekordV002"], "data", "signature")
    data = exact(v002["data"], "algorithm", "digest")
    string(data["algorithm"], "SHA2_256", "algorithm")
    digest = b64(data["digest"], "the digest")
    if len(digest) != 32:
        raise ValueError("the digest is not 32 bytes")
    signature = exact(v002["signature"], "content", "verifier")
    content = b64(signature["content"], "the signature")
    verifier = exact(signature["verifier"], "keyDetails", "x509Certificate")
    string(verifier["keyDetails"], "PKIX_ECDSA_P256_SHA_256", "keyDetails")
    der = b64(exact(verifier["x509Certificate"], "rawBytes")["rawBytes"], "the certificate")
    if not content or not der:
        raise ValueError("the signature or the certificate is empty")
    return HashedRekord(digest, content, der)


@dataclass(frozen=True)
class Logged:
    origin: str
    index: int
    body: HashedRekord
    checkpoint: Checkpoint


def verify_logged(raw, shards, policy):
    """Checks a Rekor v2 TransparencyLogEntry in the order of the door's PUT /door/record, steps 2 to 8, with the
    shard's validity read at the k-th earliest counted cosignature, and returns the first failure as a Refusal."""
    try:
        e = parse_entry(raw)
    except (ValueError, TypeError, AttributeError) as err:
        raise Refusal("not_v2", f"the entry is not a TransparencyLogEntry: {err}") from err
    if (e["kind"], e["version"]) != ("hashedrekord", "0.0.2"):
        raise Refusal("not_v2", f"the entry is {e['kind']} {e['version']}")
    shard = shards.get(e["log_id"])
    if shard is None:
        raise Refusal("unknown_log", "the trusted root lists no Ed25519 log with this id")
    if e["proof_index"] != e["index"]:
        raise Refusal("inclusion", "the proof is for another index")
    if any(len(h) != 32 for h in e["hashes"]):
        raise Refusal("inclusion", "a proof hash is not 32 bytes")
    try:
        root = root_from_inclusion(e["index"], e["size"], leaf_hash(e["body"]), e["hashes"])
    except ValueError as err:
        raise Refusal("inclusion", str(err)) from err
    if len(e["root"]) != 32 or root != e["root"]:
        raise Refusal("inclusion", "the proof does not reach its root hash")
    checkpoint = verify_note(e["envelope"] if isinstance(e["envelope"], str) else "", shard, policy, e["size"], root)
    try:
        body = parse_hashed_rekord(e["body"])
    except (ValueError, TypeError, UnicodeDecodeError) as err:
        raise Refusal("not_this_record", f"the body is not a strict hashedrekord v0.0.2: {err}") from err
    return Logged(shard.origin, e["index"], body, checkpoint)

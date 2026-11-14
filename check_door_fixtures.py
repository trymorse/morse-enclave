"""Fixtures for test_check_door.py, test_rekor.py and test_signer.py: AWS Nitro documents under a test root, a fake Rekor v2 shard
with its tiles and witnesses, a fake TUF repository, a CA with an OCSP responder and a CRL, local morse-pins, morse-records
and morse-enclave repositories, and for check 7 a statements branch, GitHub's activity and runs listings, and a fake bundle
verifier. It loads check-door.py, which loads rekor.py, door_records.py, door_checks.py, signer.py and signer_watch.py, and refuses the network to every test that imports it.
"""

import base64
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import check_door  # noqa: E402
import check_enclave as nitro  # noqa: E402
import rekor  # noqa: E402,F401
import signer  # noqa: E402

NOW = datetime.now(timezone.utc)
BORN = (NOW - timedelta(days=20)).replace(microsecond=0)
BORN_TEXT = BORN.strftime("%Y-%m-%dT%H:%M:%SZ")
PUSHED = (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
LE = ("letsencrypt.org", "https://acme-v02.api.letsencrypt.org/acme/acct/1")
GTS = ("pki.goog", "https://dv.acme-v02.api.pki.goog/account/2")
CAA = [f'0 issue "{ca}; accounturi={uri}; validationmethods=dns-01"' for ca, uri in (LE, GTS)] + ['0 issuewild ";"', '0 iodef "mailto:security@trymorse.ai"']
SOURCE = next(p for p in (HERE, HERE.parents[2]) if (p / "go.mod").exists())
REAL_DOCUMENT = SOURCE / "internal/nitro/verify/testdata/nitro_document.b64"
TWIN = SOURCE / "internal/door/watch/testdata/twin.json" if SOURCE != HERE else None
WATCHER_TRUST = SOURCE / "internal/door/testdata/watcher_trust.json" if SOURCE != HERE else None
ORIGIN = "log.test.example"
DER = serialization.Encoding.DER
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


def refuse_network(*args, **kwargs):
    raise AssertionError("the tests must not reach the network")


urllib.request.urlopen = refuse_network


def b64(raw):
    return base64.b64encode(raw).decode()


def certificate(subject_key, issuer_key, cn, names=(), issuer_cn=None, ca=False, not_before=None):
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - timedelta(days=10))
        .not_valid_after((not_before or NOW) + timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    return builder.sign(issuer_key, hashes.SHA384() if isinstance(issuer_key.curve, ec.SECP384R1) else hashes.SHA256())


ROOT_KEY = ec.generate_private_key(ec.SECP384R1())
ROOT = certificate(ROOT_KEY, ROOT_KEY, "test nitro root", ca=True)
SIGNER_KEY = ec.generate_private_key(ec.SECP384R1())
SIGNER = certificate(SIGNER_KEY, ROOT_KEY, "test nitro signer", issuer_cn="test nitro root")
PROD_PCRS = [bytes([n]) * 48 for n in (1, 2, 3)]
DEV_PCRS = [bytes([n]) * 48 for n in (4, 5, 6)]
REVOKED_PCRS = [bytes([n]) * 48 for n in (7, 8, 9)]
UNDATED = int((NOW - timedelta(days=1)).timestamp() * 1000)


def spki(key):
    return key.public_key().public_bytes(DER, SPKI)


def spki_hex(key):
    return hashlib.sha256(spki(key)).hexdigest()


class CA:
    ISSUER, OCSP, CRL = "http://ca.test/issuer.der", "http://ocsp.ca.test", "http://ca.test/1.crl"

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cert = certificate(self.key, self.key, "test revoking ca", ca=True)
        self.issued, self.revoked, self.down, self.broken, self.asked = {}, {}, set(), {}, []
        self.served_issuer = self.cert
        self.ocsp_signer = (self.key, self.cert, [])
        self.crl_key = self.key

    def issue(self, names, ocsp=True, crl=True, key=None, not_before=None):
        access = [x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(self.ISSUER))]
        if ocsp:
            access.append(x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(self.OCSP)))
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(self.cert.subject)
            .public_key((key or ec.generate_private_key(ec.SECP256R1())).public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before or NOW - timedelta(days=10))
            .not_valid_after((not_before or NOW) + timedelta(days=10))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.AuthorityInformationAccess(access), critical=False)
        )
        if crl:
            point = x509.DistributionPoint([x509.UniformResourceIdentifier(self.CRL)], None, None, None)
            builder = builder.add_extension(x509.CRLDistributionPoints([point]), critical=False)
        cert = builder.sign(self.key, hashes.SHA256())
        self.issued[cert.serial_number] = cert
        return cert

    def revoke(self, cert, reason=x509.ReasonFlags.key_compromise):
        self.revoked[cert.serial_number] = reason

    def delegate_ocsp(self, eku=ExtendedKeyUsageOID.OCSP_SIGNING):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test ocsp responder")]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=10))
            .not_valid_after(NOW + timedelta(days=10))
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        self.ocsp_signer = (key, cert, [cert])

    def serve(self, url):
        if not url.startswith(("http://ca.test/", "http://ocsp.ca.test/")):
            return None
        self.asked.append(url)
        if url.split("/")[2] in self.down or url in self.down:
            raise urllib.error.URLError("connection refused")
        if url.split("/")[2] in self.broken:
            raise self.broken[url.split("/")[2]]
        if url == self.ISSUER:
            return self.served_issuer.public_bytes(DER)
        if url == self.CRL:
            builder = x509.CertificateRevocationListBuilder().issuer_name(self.cert.subject).last_update(NOW).next_update(NOW + timedelta(days=1))
            for serial, reason in self.revoked.items():
                entry = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(NOW).add_extension(x509.CRLReason(reason), critical=False)
                builder = builder.add_revoked_certificate(entry.build())
            return builder.sign(self.crl_key, hashes.SHA256()).public_bytes(DER)
        asked = ocsp.load_der_ocsp_request(base64.b64decode(urllib.parse.unquote(url.removeprefix(self.OCSP + "/"))))
        cert = self.issued[asked.serial_number]
        key, signer, included = self.ocsp_signer
        if cert.serial_number in self.revoked:
            status, when, reason = ocsp.OCSPCertStatus.REVOKED, NOW, self.revoked[cert.serial_number]
        else:
            status, when, reason = ocsp.OCSPCertStatus.GOOD, None, None
        builder = ocsp.OCSPResponseBuilder().add_response(cert, self.cert, hashes.SHA1(), status, NOW, NOW + timedelta(days=1), when, reason)
        builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, signer)
        if included:
            builder = builder.certificates(included)
        return builder.sign(key, hashes.SHA256()).public_bytes(DER)


SIGNERS = {}


def sign(payload, key):
    protected = cbor2.dumps({1: -35})
    r, s = decode_dss_signature(key.sign(cbor2.dumps(["Signature1", protected, b"", payload]), ec.ECDSA(hashes.SHA384())))
    return cbor2.dumps([protected, {}, payload, r.to_bytes(48, "big") + s.to_bytes(48, "big")])


def payload_of(doc):
    return cbor2.loads(cbor2.loads(doc)[2])


def sealed(doc, born, sender, floor):
    payload = payload_of(doc)
    key = SIGNERS.get(payload["certificate"])
    if key is None:
        return doc
    payload["nonce"] = check_door.records.origin_nonce(hashlib.sha256(payload["public_key"]).hexdigest(), born, sender, floor)
    return sign(cbor2.dumps(payload), key)


def document(hpke, tls, environment="prod", pcrs=PROD_PCRS, signer=(SIGNER_KEY, SIGNER), public_key=None, made=None):
    key, cert = signer
    SIGNERS[cert.public_bytes(DER)] = key
    payload = cbor2.dumps({
        "module_id": "i-test", "digest": "SHA384", "timestamp": UNDATED if made is None else int(made.timestamp() * 1000),
        "pcrs": dict(enumerate(pcrs)), "certificate": cert.public_bytes(DER),
        "cabundle": [ROOT.public_bytes(DER)],
        "public_key": public_key if public_key is not None else spki(tls),
        "user_data": f"morse-proxy-hpke-v1|{environment}|".encode() + hpke, "nonce": None,
    })
    return sign(payload, key)


def relayed(doc, when):
    payload = payload_of(doc)
    if payload["timestamp"] != UNDATED:
        return doc
    payload["timestamp"] = int(when.timestamp() * 1000)
    return sign(cbor2.dumps(payload), SIGNERS[payload["certificate"]])


def key_id(hpke):
    return hashlib.sha256(hpke).hexdigest()[:16]




def leaf(body):
    return hashlib.sha256(b"\x00" + body).digest()


def node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def split(n):
    return 1 << ((n - 1).bit_length() - 1)


def mth(leaves):
    if len(leaves) == 1:
        return leaves[0]
    k = split(len(leaves))
    return node(mth(leaves[:k]), mth(leaves[k:]))


def audit_path(m, leaves):
    if len(leaves) == 1:
        return []
    k = split(len(leaves))
    if m < k:
        return audit_path(m, leaves[:k]) + [mth(leaves[k:])]
    return audit_path(m - k, leaves[k:]) + [mth(leaves[:k])]


def key_hash(name, alg, key):
    return hashlib.sha256(name.encode() + b"\n" + bytes([alg]) + key).digest()[:4]


def raw_public(private):
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class Witness:
    def __init__(self, name, operator):
        self.name, self.operator, self.key = name, operator, ed25519.Ed25519PrivateKey.generate()

    @property
    def vkey(self):
        public = raw_public(self.key)
        return f"{self.name}+{key_hash(self.name, 4, public).hex()}+{b64(bytes([4]) + public)}"

    def cosign(self, text, when):
        seconds = int(when.timestamp())
        signature = self.key.sign(b"cosignature/v1\ntime %d\n" % seconds + text)
        return f"— {self.name} {b64(key_hash(self.name, 4, raw_public(self.key)) + seconds.to_bytes(8, 'big') + signature)}\n"


WITNESSES = [Witness("w1.test.example/a", "Operator A"), Witness("w2.test.example", "Operator B"),
             Witness("w3.test.example", "Operator C"), Witness("w4.test.example", "Operator D")]


def not_found(url):
    return urllib.error.HTTPError(url, 404, "Not Found", {}, None)


class Log:
    def __init__(self, origin=ORIGIN, key=None):
        self.origin, self.key = origin, key or ed25519.Ed25519PrivateKey.generate()
        self.bodies, self.note, self.gone, self.reads = [], None, set(), []
        self.witnesses, self.cosigned = list(WITNESSES), NOW - timedelta(minutes=1)
        self.valid = {"start": "2020-01-01T00:00:00Z"}

    @property
    def log_id(self):
        return hashlib.sha256(self.origin.encode() + b"\n\x01" + raw_public(self.key)).digest()

    def add(self, body):
        self.bodies.append(body)
        return len(self.bodies) - 1

    def leaves(self, size=None):
        return [leaf(b) for b in self.bodies[:len(self.bodies) if size is None else size]]

    def checkpoint(self, size=None, witnesses=None, when=None, signer=None, origin=None):
        size = len(self.bodies) if size is None else size
        text = f"{origin or self.origin}\n{size}\n{b64(mth(self.leaves(size)))}\n".encode()
        signer = signer or self.key
        lines = f"— {origin or self.origin} {b64(key_hash(origin or self.origin, 1, raw_public(signer)) + signer.sign(text))}\n"
        for w in self.witnesses if witnesses is None else witnesses:
            lines += w.cosign(text, when or self.cosigned)
        return text.decode() + "\n" + lines

    def entry(self, index, size=None, note=None, kind=("hashedrekord", "0.0.2"), hashes=None, **extra):
        size = len(self.bodies) if size is None else size
        leaves = self.leaves(size)
        entry = {
            "logIndex": str(index), "logId": {"keyId": b64(self.log_id)}, "kindVersion": {"kind": kind[0], "version": kind[1]},
            "integratedTime": "0",
            "inclusionProof": {"logIndex": str(index), "rootHash": b64(mth(leaves)), "treeSize": str(size),
                               "hashes": [b64(h) for h in (audit_path(index, leaves) if hashes is None else hashes)],
                               "checkpoint": {"envelope": note or self.checkpoint(size)}},
            "canonicalizedBody": b64(self.bodies[index]),
        }
        return json.dumps({**entry, **extra}).encode()

    def tlog(self):
        return {"baseUrl": f"https://{self.origin}", "hashAlgorithm": "SHA2_256",
                "publicKey": {"rawBytes": b64(self.key.public_key().public_bytes(DER, SPKI)), "keyDetails": "PKIX_ED25519", "validFor": self.valid},
                "logId": {"keyId": b64(self.log_id)}}

    def serve(self, path, url):
        self.reads.append(path)
        if path in self.gone:
            raise not_found(url)
        if path == "checkpoint":
            return (self.note or self.checkpoint()).encode()
        tile, _, width = path.partition(".p/")
        parts = tile.split("/")
        entries = parts[1] == "entries"
        n = int("".join(p.removeprefix("x") for p in parts[2 if entries else 2:]))
        count = int(width) if width else 256
        if entries:
            if n * 256 + count > len(self.bodies):
                raise not_found(url)
            return b"".join(len(b).to_bytes(2, "big") + b for b in self.bodies[n * 256:n * 256 + count])
        level = int(parts[1])
        span = 1 << (8 * level)
        if (len(self.bodies) >> (8 * level)) < n * 256 + count:
            raise not_found(url)
        leaves = self.leaves()
        return b"".join(mth(leaves[(n * 256 + i) * span:(n * 256 + i + 1) * span]) for i in range(count))


def hashed_rekord(digest, certificate_der, version="0.0.2", **extra):
    body = {"apiVersion": version, "kind": "hashedrekord", "spec": {"hashedRekordV002": {
        "data": {"algorithm": "SHA2_256", "digest": b64(digest)},
        "signature": {"content": b64(b"0\x06\x02\x01\x01\x02\x01\x01"), "verifier": {"keyDetails": "PKIX_ECDSA_P256_SHA_256", "x509Certificate": {"rawBytes": b64(certificate_der)}}}}}}
    return json.dumps({**body, **extra}, separators=(",", ":")).encode()


def der_octet(raw):
    n = len(raw)
    length = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x04" + length + raw


def record_certificate(record, oid=check_door.records.RECORD_OID):
    key = ec.generate_private_key(ec.SECP256R1())
    raw = record if isinstance(record, bytes) else json.dumps(record, separators=(",", ":")).encode()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "morse door record")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "morse door record")]))
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=1))
        .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), der_octet(raw)), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(DER)


def trust_go(witnesses, k):
    listed = "".join(f'\t{{"{w.vkey}", "{w.operator}"}},\n' for w in witnesses)
    return f"package door\n\nconst witnessK = {k}\n\n// All four are test tier.\nvar witnesses = []struct{{ vkey, operator string }}{{\n{listed}}}\n"


def git(directory, *args, committed=None, authored=None):
    env = {**os.environ}
    if committed:
        env["GIT_COMMITTER_DATE"] = committed.isoformat()
        env["GIT_AUTHOR_DATE"] = (authored or committed).isoformat()
    return subprocess.run(["git", "-C", str(directory), "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "tag.gpgSign=false", "-c", "commit.gpgSign=false", *args],
                          check=True, capture_output=True, env=env, text=True).stdout


TEMPLATES = tempfile.TemporaryDirectory()
ENCLAVES = {}

SIGN_YML = "name: sign\n"


def signer_tree(sign_yml=SIGN_YML):
    repo = Path(tempfile.mkdtemp(dir=TEMPLATES.name))
    git(repo, "init", "-q")
    (repo / ".github/workflows").mkdir(parents=True)
    (repo / ".github/workflows/sign.yml").write_text(sign_yml)
    git(repo, "add", "-A")
    return git(repo, "rev-parse", f"{git(repo, 'write-tree').strip()}:.github").strip()


SIGNER_TREE = signer_tree()
RUN = "https://github.com/trymorse/morse-pins/actions/runs/{}/attempts/1"


def fake_bundle(commit, run=RUN.format(1), unsigned=None):
    return json.dumps({"unsigned": unsigned} if unsigned else {"commit": commit, "run": run}).encode()


def fake_verify(statement, bundle_json, shards, authorities, policy, rekor_module):
    b = json.loads(bundle_json)
    if "unsigned" in b:
        raise signer.Unsigned(b["unsigned"])
    return signer.Signed(b["commit"], b["run"])


def push(before, after, actor="morse-pins-publisher[bot]", kind="push"):
    return {"id": int(hashlib.sha256(f"{before} {after} {kind}".encode()).hexdigest()[:12], 16), "activity_type": kind, "before": before, "after": after, "actor": {"login": actor}, "timestamp": PUSHED}


def run_of(number, sha, event="push", conclusion="success", branch="main", created=None, status="completed"):
    return {"id": 9000 + number, "run_number": number, "event": event, "status": status, "conclusion": conclusion, "head_branch": branch, "head_sha": sha,
            "created_at": (created or NOW - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")}


class Door:
    def __init__(self, root):
        self.root = Path(root)
        self.tls = ec.generate_private_key(ec.SECP256R1())
        self.hpke = [bytes([n]) * 32 for n in (11, 12, 13)]
        self.pins = [
            {"environment": "prod", "pcr0": PROD_PCRS[0].hex(), "pcr1": PROD_PCRS[1].hex(), "pcr2": PROD_PCRS[2].hex(), "revoked": False, "tag": "v1"},
            {"environment": "dev", "pcr0": DEV_PCRS[0].hex(), "pcr1": DEV_PCRS[1].hex(), "pcr2": DEV_PCRS[2].hex(), "revoked": False, "tag": "v1"},
            {"environment": "prod", "pcr0": REVOKED_PCRS[0].hex(), "pcr1": REVOKED_PCRS[1].hex(), "pcr2": REVOKED_PCRS[2].hex(), "revoked": True, "tag": "v0"},
        ]
        self.revocations, self.authored = {}, {}
        self.base_time = datetime(2000, 1, 1, tzinfo=timezone.utc)
        self.history = None
        self.log = Log()
        self.logs = [self.log]
        self.extra_tlogs = []
        self.pointers, self.archive = [], {}
        self.visibility = "public"
        self.doh = None
        self.tuf = None
        self.crtsh = None
        self.revoking = CA()
        self.tags = {"v0": trust_go(WITNESSES, 3), "v1": trust_go(WITNESSES, 3)}
        self.built, self.committed, self.pinned = None, None, None
        self.statements, self.deleted, self.changed, self.signed = [], [], {}, None
        self.runs, self.activity_edit, self.page_size = [], None, 100
        self.github_reads, self.activity_reads = [], 0
        self.ca = ec.generate_private_key(ec.SECP256R1())
        self.born = self.add(self.record(document(self.hpke[0], self.tls), None, 7))
        self.handed = self.add(self.record(document(self.hpke[1], self.tls), key_id(self.hpke[0]), 8))
        self.ct = [
            certificate(self.tls, self.ca, "inference.trymorse.ai", ["inference.trymorse.ai", "0123456789abcdef.k.inference.trymorse.ai"], issuer_cn="test ca"),
            certificate(ec.generate_private_key(ec.SECP256R1()), self.ca, "admin.trymorse.ai", ["admin.trymorse.ai", "*.inference.trymorse.ai"], issuer_cn="test ca"),
        ]
        self.caa = [CAA]
        self.live = [document(self.hpke[1], self.tls)]
        (self.root / "sequence.json").write_text(json.dumps({"last_run": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(), "boots": {}}))

    def record(self, doc, sender, floor, label=None, born=BORN_TEXT, environment="prod", type_="morse-door-boot-v1"):
        doc = sealed(doc, born, sender, floor)
        return {"type": type_, "environment": environment, "document": b64(doc),
                "spki_sha256": label or hashlib.sha256(payload_of(doc)["public_key"] or b"").hexdigest(), "origin": {"born": born, "from": sender, "floor": floor}}

    def add(self, record, digest=None, point=True, log=None, certificate_der=None, pointer=None):
        log = log or self.log
        try:
            payload = payload_of(base64.b64decode(record["document"]))
            spki_sha256, boot = hashlib.sha256(payload["public_key"]).hexdigest(), key_id(payload["user_data"][-32:])
        except Exception:
            spki_sha256, boot = "0" * 64, "0" * 16
        index = log.add(hashed_rekord(digest or check_door.records.record_digest(spki_sha256), certificate_der or record_certificate(record)))
        if point:
            self.pointers.append(pointer or {"log": log.origin, "index": index, "spki_sha256": spki_sha256, "boot": boot})
        return index

    def needed(self, tls, **kwargs):
        """A certificate in CT for tls, so check 1 fails unless an entry for tls verifies."""
        self.ct.append(certificate(tls, self.ca, "inference.trymorse.ai", ["inference.trymorse.ai"], issuer_cn="test ca", **kwargs))
        return tls

    def seen(self, hpke, tls, ago):
        state = self.root / "sequence.json"
        saved = json.loads(state.read_text())
        saved["boots"][key_id(hpke)] = {"first_seen": (datetime.now(timezone.utc) - ago).isoformat(), "spkis": [spki_hex(tls)]}
        state.write_text(json.dumps(saved))

    def ran(self, when):
        saved = self.state()
        saved["last_run"] = when.isoformat()
        (self.root / "sequence.json").write_text(json.dumps(saved))

    def state(self):
        return json.loads((self.root / "sequence.json").read_text())

    def edit_state(self, change):
        saved = self.state()
        change(saved)
        (self.root / "sequence.json").write_text(json.dumps(saved))

    def rogue(self, names):
        rogue = ec.generate_private_key(ec.SECP256R1())
        self.ct.append(certificate(rogue, self.ca, names[0], names, issuer_cn="test ca"))
        return rogue

    def commit_pins(self, pins, when, authored=None):
        pinned = self.root / "pins"
        if not (pinned / ".git").exists():
            pinned.mkdir(parents=True, exist_ok=True)
            git(pinned, "init", "-q", "-b", "main")
            (pinned / ".github/workflows").mkdir(parents=True)
            (pinned / ".github/workflows/sign.yml").write_text(SIGN_YML)
            git(pinned, "add", ".github")
        (pinned / "enclave_pins.json").write_text(json.dumps(pins))
        git(pinned, "add", "enclave_pins.json")
        git(pinned, "commit", "-q", "-m", "pins", committed=when, authored=authored)

    def git(self, *args, committed=None):
        git(self.root / "pins", *args, committed=committed)

    def revoked(self, tag):
        return [{**p, "revoked": p["revoked"] or p["tag"] == tag} for p in self.pins]

    def unrevoked(self, tag):
        return [{**p, "revoked": False} if p["tag"] == tag else p for p in self.pins]

    def head(self):
        self.build_pins()
        return git(self.root / "pins", "rev-parse", "HEAD").strip()

    def sign(self, environment="prod", commit=None, path=None, signed=None, **changes):
        """Adds a statement for environment at commit, HEAD if None, as sign.yml writes it, with changes on top."""
        commit = commit or self.head()
        pins = json.loads(git(self.root / "pins", "show", f"{commit}:enclave_pins.json"))
        sequence = int(git(self.root / "pins", "rev-list", "--count", commit))
        images = sorted(({"pcr0": p["pcr0"], "pcr1": p["pcr1"], "pcr2": p["pcr2"], "revoked": p["revoked"]} for p in pins if p["environment"] == environment), key=lambda i: i["pcr0"])
        statement = {"type": "morse-enclave-pins-v1", "environment": environment, "sequence": sequence, "pins_commit": commit, "time": "2026-11-11T00:00:00Z", "images": images}
        path = path or f"{environment}/{sequence}-{len(self.statements):08d}T000000Z.statement.json"
        raw = json.dumps({**statement, **changes}, sort_keys=True, separators=(",", ":")).encode()
        self.statements.append((path, raw, signed if signed is not None else fake_bundle(commit)))
        return path

    def commit_statements(self):
        statements = self.root / "statements"
        key = (list(self.statements), list(self.deleted), dict(self.changed))
        if key != self.signed:
            self.signed = key
            shutil.rmtree(statements, ignore_errors=True)
            statements.mkdir()
            git(statements, "init", "-q", "-b", "main")
            for path, raw, signed in self.statements:
                (statements / path).parent.mkdir(parents=True, exist_ok=True)
                (statements / path).write_bytes(raw)
                (statements / path.replace(".statement.json", ".sigstore.json")).write_bytes(signed)
            git(statements, "add", "-A")
            git(statements, "commit", "-q", "--allow-empty", "-m", "sign")
            if self.deleted:
                git(statements, "rm", "-q", *self.deleted)
                git(statements, "commit", "-q", "-m", "prune")
            if self.changed:
                for path, raw in self.changed.items():
                    (statements / path).write_bytes(raw)
                git(statements, "commit", "-q", "-am", "rewrite")
        git(self.root / "pins", "fetch", "-q", str(statements), "+main:refs/remotes/origin/statements/images")

    def activity(self):
        commits = git(self.root / "pins", "rev-list", "--first-parent", "--reverse", "HEAD").split()
        events = [push("0" * 40, commits[0], kind="branch_creation")] + [push(a, b) for a, b in zip(commits, commits[1:])]
        self.activity_reads += 1
        return self.activity_edit(events) if self.activity_edit else events

    def fetch_github(self, url):
        self.github_reads.append(url)
        if url.startswith(check_door.signer_watch.RUNS_URL):
            created = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get("created", [">="])[0].removeprefix(">=")
            runs = [r for r in self.runs if r["created_at"] >= created]
            return json.dumps({"total_count": len(runs), "workflow_runs": runs}).encode(), None
        if url.startswith(check_door.signer_watch.RUN_URL):
            run = next((r for r in self.runs if f"{check_door.signer_watch.RUN_URL}{r['id']}" == url), None)
            if run is None:
                raise not_found(url)
            return json.dumps(run).encode(), None
        base, _, cursor = url.partition("&after=")
        if base != check_door.signer_watch.PUSHES_URL:
            raise AssertionError(f"the test reaches {url}")
        events, page = self.activity()[::-1], int(cursor.removeprefix("c") or 0)
        more = (page + 1) * self.page_size < len(events)
        return json.dumps(events[page * self.page_size:(page + 1) * self.page_size]).encode(), more and f"{base}&after=c{page + 1}"

    def commit_records(self):
        records = self.root / "records"
        pointers = "".join(p if isinstance(p, str) else json.dumps(p) + "\n" for p in self.pointers)
        if (records / ".git").exists() and self.committed == (pointers, dict(self.archive), git(records, "rev-parse", "HEAD")):
            return
        if not (records / ".git").exists():
            records.mkdir(parents=True)
            git(records, "init", "-q", "-b", "main")
        (records / "prod.jsonl").write_text(pointers)
        shutil.rmtree(records / "leaves", ignore_errors=True)
        for (log, index), raw in self.archive.items():
            (records / "leaves" / log).mkdir(parents=True, exist_ok=True)
            (records / "leaves" / log / f"{index}.json").write_bytes(raw)
        git(records, "add", "-A")
        if git(records, "status", "--porcelain"):
            git(records, "commit", "-q", "-m", "pointers")
        self.committed = (pointers, dict(self.archive), git(records, "rev-parse", "HEAD"))

    def build_enclave(self):
        enclave = self.root / "enclave"
        if self.built == self.tags:
            return
        self.built = dict(self.tags)
        shutil.rmtree(enclave, ignore_errors=True)
        key = tuple(self.tags.items())
        if key not in ENCLAVES:
            built = Path(tempfile.mkdtemp(dir=TEMPLATES.name))
            (built / "internal/door").mkdir(parents=True)
            git(built, "init", "-q", "-b", "main")
            for n, (tag, trust) in enumerate(self.tags.items()):
                (built / "internal/door/trust.go").write_text(trust)
                git(built, "add", "-A")
                git(built, "commit", "-q", "--allow-empty", "-m", tag, committed=datetime(2000, 1, 1, tzinfo=timezone.utc) + timedelta(days=n))
                git(built, "tag", tag)
            ENCLAVES[key] = built
        shutil.copytree(ENCLAVES[key], enclave, symlinks=True)

    def trusted_root(self):
        return json.dumps({"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1", "tlogs": [log.tlog() for log in self.logs] + self.extra_tlogs}).encode()

    def read_github(self, url, headers):
        if url != check_door.checks.RECORDS_REPO_URL or "Authorization" in headers:
            raise AssertionError(f"the test reaches {url} with {headers}")
        if self.visibility == "rate limited":
            raise urllib.error.HTTPError(url, 403, "rate limit exceeded", {"x-ratelimit-remaining": "0"}, None)
        if isinstance(self.visibility, int):
            raise urllib.error.HTTPError(url, self.visibility, "status", {}, None)
        return json.dumps({"visibility": self.visibility, "private": self.visibility != "public"}).encode(), {}

    def fetch(self, url):
        for log in self.logs:
            if url.startswith(f"https://{log.origin}/api/v2/"):
                return log.serve(url.removeprefix(f"https://{log.origin}/api/v2/"), url)
        if self.doh and url.startswith("https://dns.google/"):
            return self.doh(url)
        if self.tuf is not None and url.startswith(check_door.TUF_URL):
            if url not in self.tuf:
                raise not_found(url)
            return self.tuf[url]
        if self.crtsh is not None and url in self.crtsh:
            if isinstance(self.crtsh[url], Exception):
                raise self.crtsh[url]
            return self.crtsh[url]
        served = self.revoking.serve(url)
        if served is not None:
            return served
        raise AssertionError(f"the test reaches {url}")

    def build_pins(self):
        pinned = (json.dumps(self.pins), dict(self.revocations), dict(self.authored), self.base_time, self.history)
        if pinned != self.pinned:
            self.pinned, self.signed = pinned, None
            shutil.rmtree(self.root / "pins", ignore_errors=True)
            if self.history:
                self.history(self)
            else:
                self.commit_pins(self.pins, self.base_time)
                for tag, when in self.revocations.items():
                    self.commit_pins(self.revoked(tag), when, self.authored.get(tag))

    def run(self, *extra, sample=False, trusted_root=True):
        self.build_pins()
        self.commit_statements()
        self.commit_records()
        self.build_enclave()
        (self.root / "ct.json").write_text(json.dumps([{"id": str(n), "cert_der": b64(c.public_bytes(DER))} for n, c in enumerate(self.ct)]))
        (self.root / "caa.jsonl").write_text("".join(json.dumps({"time": f"2026-11-0{n + 1}T00:00:00Z", "caa": s}) + "\n" for n, s in enumerate(self.caa)))
        (self.root / "attestation.json").write_text(json.dumps({"instances": [b64(relayed(d, check_door.utcnow() - timedelta(minutes=1))) for d in self.live]}))
        argv = ["--pins", str(self.root / "pins"), "--records", str(self.root / "records"), "--enclave", str(self.root / "enclave"),
                "--attestation", str(self.root / "attestation.json"), "--caa-history", str(self.root / "caa.jsonl"),
                "--sequence-state", str(self.root / "sequence.json"), *extra]
        if not any(a == "--ct" for a in extra):
            argv += ["--ct", str(self.root / "ct.json")]
        if not sample:
            argv.append("--no-caa-sample")
        argv += [a for ca, uri in (LE, GTS) for a in ("--caa-account", f"{ca}={uri}")]
        out = io.StringIO()
        root = unittest.mock.patch.object(check_door, "read_trusted_root", lambda cache: self.trusted_root()) if trusted_root else contextlib.nullcontext()
        github = [unittest.mock.patch.object(check_door.signer_watch, "fetch_github", self.fetch_github), unittest.mock.patch.object(check_door.signer_watch, "ACTIVITY_LAG", 0)]
        with contextlib.redirect_stdout(out), unittest.mock.patch.object(check_door, "fetch", self.fetch), unittest.mock.patch.object(check_door, "read_github", self.read_github), root, github[0], github[1]:
            try:
                check_door.main(argv)
            except SystemExit as e:
                return e.code, out.getvalue()
        raise AssertionError("check-door did not exit")


class Fixture(unittest.TestCase):
    def setUp(self):
        self.real_root = nitro.AWS_NITRO_ROOT
        nitro.AWS_NITRO_ROOT = ROOT
        policy = [unittest.mock.patch.object(check_door, "WITNESSES", [(w.vkey, w.operator) for w in WITNESSES]), unittest.mock.patch.object(check_door, "WITNESS_K", 3),
                  unittest.mock.patch.object(check_door.signer_watch, "SIGNER_TREES", {SIGNER_TREE}), unittest.mock.patch.object(signer, "verify_statement", fake_verify),
                  unittest.mock.patch.object(signer, "read_authorities", lambda root, rfc3339: [])]
        for p in policy:
            p.start()
            self.addCleanup(p.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.door = Door(self.tmp.name)

    def tearDown(self):
        nitro.AWS_NITRO_ROOT = self.real_root
        self.tmp.cleanup()

    def passes(self, *messages):
        code, out = self.door.run()
        self.assertEqual(code, 0, out)
        for message in messages:
            self.assertIn(message, out)
        return out

    def fails(self, *messages):
        code, out = self.door.run()
        self.assertEqual(code, 1, out)
        for message in messages:
            self.assertIn(message, out)
        return out

    def section(self, out, check):
        return out.split(f"({check})\n", 1)[1].split("\n\n", 1)[0]

    def at(self, when):
        with unittest.mock.patch.object(check_door, "utcnow", lambda: when):
            return self.door.run()

    def unrecorded(self, tls):
        return f"with SPKI {spki_hex(tls)}, which no verified record attests"

    def ignored(self, index, reason):
        return f"the entry at {ORIGIN}/{index} does not verify, so this run ignores it: {reason}"

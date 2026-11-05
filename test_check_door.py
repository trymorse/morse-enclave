# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2==6.1.5", "cryptography==50.0.2"]
# ///
"""Tests check-door.py against fixtures. It reads nothing from the network.

Usage: uv run test_check_door.py
"""

import base64
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import types
import unittest
import unittest.mock
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

HERE = Path(__file__).parent
check_door = types.ModuleType("check_door")
check_door.__file__ = str(HERE / "check-door.py")
exec(compile((HERE / "check-door.py").read_text(), check_door.__file__, "exec"), check_door.__dict__)

NOW = datetime.now(timezone.utc)
LE = ("letsencrypt.org", "https://acme-v02.api.letsencrypt.org/acme/acct/1")
GTS = ("pki.goog", "https://dv.acme-v02.api.pki.goog/account/2")
CAA = [f'0 issue "{ca}; accounturi={uri}; validationmethods=dns-01"' for ca, uri in (LE, GTS)] + ['0 issuewild ";"', '0 iodef "mailto:security@trymorse.ai"']
REAL_DOCUMENT = next(p for p in (HERE, HERE.parents[2]) if (p / "go.mod").exists()) / "internal/nitro/verify/testdata/nitro_document.b64"


def refuse_network(*args, **kwargs):
    raise AssertionError("the tests must not reach the network")


def setUpModule():
    urllib.request.urlopen = refuse_network


def certificate(subject_key, issuer_key, cn, names=(), issuer_cn=None, ca=False):
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=10))
        .not_valid_after(NOW + timedelta(days=10))
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
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


SIGNERS = {}


def sign(payload, key):
    protected = cbor2.dumps({1: -35})
    r, s = decode_dss_signature(key.sign(cbor2.dumps(["Signature1", protected, b"", payload]), ec.ECDSA(hashes.SHA384())))
    return cbor2.dumps([protected, {}, payload, r.to_bytes(48, "big") + s.to_bytes(48, "big")])


def sealed(doc, born, sender, floor):
    payload = cbor2.loads(cbor2.loads(doc)[2])
    key = SIGNERS.get(payload["certificate"])
    if key is None:
        return doc
    payload["nonce"] = check_door.origin_nonce(hashlib.sha256(payload["public_key"]).hexdigest(), born, sender, floor)
    return sign(cbor2.dumps(payload), key)


def document(hpke, tls, environment="prod", pcrs=PROD_PCRS, signer=(SIGNER_KEY, SIGNER), public_key=None, made=None):
    key, cert = signer
    SIGNERS[cert.public_bytes(serialization.Encoding.DER)] = key
    payload = cbor2.dumps({
        "module_id": "i-test", "digest": "SHA384", "timestamp": UNDATED if made is None else int(made.timestamp() * 1000),
        "pcrs": dict(enumerate(pcrs)), "certificate": cert.public_bytes(serialization.Encoding.DER),
        "cabundle": [ROOT.public_bytes(serialization.Encoding.DER)],
        "public_key": public_key if public_key is not None else spki(tls),
        "user_data": f"morse-proxy-hpke-v1|{environment}|".encode() + hpke, "nonce": None,
    })
    return sign(payload, key)


def relayed(doc, when):
    payload = cbor2.loads(cbor2.loads(doc)[2])
    if payload["timestamp"] != UNDATED:
        return doc
    payload["timestamp"] = int(when.timestamp() * 1000)
    return sign(cbor2.dumps(payload), SIGNERS[payload["certificate"]])


def key_id(hpke):
    return hashlib.sha256(hpke).hexdigest()[:16]


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
        self.revocations = {}
        self.authored = {}
        self.base_time = datetime(2000, 1, 1, tzinfo=timezone.utc)
        self.history = None
        self.records = {
            "2026-11-04T09:12:03Z-born.json": self.record(document(self.hpke[0], self.tls), None, 7),
            "2026-11-05T10:00:00Z-handed.json": self.record(document(self.hpke[1], self.tls), key_id(self.hpke[0]), 8),
        }
        self.statements = {1: ["2026-11-04T09:12:03Z-born.json"], 2: ["2026-11-04T09:12:03Z-born.json", "2026-11-05T10:00:00Z-handed.json"]}
        self.ca = ec.generate_private_key(ec.SECP256R1())
        self.ct = [
            certificate(self.tls, self.ca, "inference.trymorse.ai", ["inference.trymorse.ai", "0123456789abcdef.k.inference.trymorse.ai"], issuer_cn="test ca"),
            certificate(ec.generate_private_key(ec.SECP256R1()), self.ca, "admin.trymorse.ai", ["admin.trymorse.ai", "*.inference.trymorse.ai"], issuer_cn="test ca"),
        ]
        self.caa = [CAA]
        self.live = [document(self.hpke[1], self.tls)]
        (self.root / "sequence.json").write_text(json.dumps({"sequence": 0, "last_run": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(), "boots": {}}))

    def record(self, doc, sender, floor, label=None, born="2026-11-04T09:12:03Z"):
        return {"type": "morse-door-boot-v1", "environment": "prod", "document": base64.b64encode(sealed(doc, born, sender, floor)).decode(),
                "spki_sha256": label or "unused", "origin": {"born": born, "from": sender, "floor": floor}}

    def seen(self, hpke, tls, ago):
        state = self.root / "sequence.json"
        saved = json.loads(state.read_text())
        saved["boots"][key_id(hpke)] = {"first_seen": (datetime.now(timezone.utc) - ago).isoformat(), "spki_sha256": hashlib.sha256(spki(tls)).hexdigest()}
        state.write_text(json.dumps(saved))

    def ran(self, when):
        saved = self.state()
        saved["last_run"] = when.isoformat()
        (self.root / "sequence.json").write_text(json.dumps(saved))

    def state(self):
        return json.loads((self.root / "sequence.json").read_text())

    def add_record(self, name, record):
        self.records[name] = record
        self.statements[len(self.statements) + 1] = self.statements[len(self.statements)] + [name]

    def rogue(self, names):
        rogue = ec.generate_private_key(ec.SECP256R1())
        self.ct.append(certificate(rogue, self.ca, names[0], names, issuer_cn="test ca"))
        return rogue

    def git(self, *args, committed=None, authored=None):
        env = {**os.environ}
        if committed:
            env["GIT_COMMITTER_DATE"] = committed.isoformat()
            env["GIT_AUTHOR_DATE"] = (authored or committed).isoformat()
        subprocess.run(["git", "-C", str(self.root / "pins"), "-c", "user.name=t", "-c", "user.email=t@example.com", *args], check=True, capture_output=True, env=env)

    def commit_pins(self, pins, when, authored=None):
        pinned = self.root / "pins"
        if not (pinned / ".git").exists():
            self.git("init", "-q", "-b", "main")
        (pinned / "enclave_pins.json").write_text(json.dumps(pins))
        self.git("add", "enclave_pins.json")
        self.git("commit", "-q", "-m", "pins", committed=when, authored=authored)

    def revoked(self, tag):
        return [{**p, "revoked": p["revoked"] or p["tag"] == tag} for p in self.pins]

    def unrevoked(self, tag):
        return [{**p, "revoked": False} if p["tag"] == tag else p for p in self.pins]

    def run(self, *extra, sample=False):
        shutil.rmtree(self.root / "pins", ignore_errors=True)
        records = self.root / "pins/records/prod"
        (records / "statements").mkdir(parents=True)
        if self.history:
            self.history(self)
        else:
            self.commit_pins(self.pins, self.base_time)
            for tag, when in self.revocations.items():
                self.commit_pins(self.revoked(tag), when, self.authored.get(tag))
        digests = {}
        for name, record in self.records.items():
            (records / name).write_text(json.dumps(record))
            digests[name] = hashlib.sha256((records / name).read_bytes()).hexdigest()
        for sequence, names in self.statements.items():
            statement = {"type": "morse-door-records-v1", "environment": "prod", "sequence": sequence, "time": "2026-11-05T10:00:00Z",
                         "records": {n: digests[n] for n in names}}
            (records / "statements" / f"{sequence}.json").write_text(json.dumps(statement))
        (self.root / "ct.json").write_text(json.dumps([{"id": str(n), "cert_der": base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()} for n, c in enumerate(self.ct)]))
        (self.root / "caa.jsonl").write_text("".join(json.dumps({"time": f"2026-11-0{n + 1}T00:00:00Z", "caa": s}) + "\n" for n, s in enumerate(self.caa)))
        (self.root / "attestation.json").write_text(json.dumps({"instances": [base64.b64encode(relayed(d, check_door.utcnow() - timedelta(minutes=1))).decode() for d in self.live]}))
        argv = ["--pins", str(self.root / "pins"), "--ct", str(self.root / "ct.json"), "--attestation", str(self.root / "attestation.json"),
                "--caa-history", str(self.root / "caa.jsonl"), "--sequence-state", str(self.root / "sequence.json"), *extra]
        if not sample:
            argv.append("--no-caa-sample")
        argv += [a for ca, uri in (LE, GTS) for a in ("--caa-account", f"{ca}={uri}")]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            try:
                check_door.main(argv)
            except SystemExit as e:
                return e.code, out.getvalue()
        raise AssertionError("check-door did not exit")


class CheckDoorTest(unittest.TestCase):
    def setUp(self):
        self.real_root = check_door.nitro.AWS_NITRO_ROOT
        check_door.nitro.AWS_NITRO_ROOT = ROOT
        self.tmp = tempfile.TemporaryDirectory()
        self.door = Door(self.tmp.name)

    def tearDown(self):
        check_door.nitro.AWS_NITRO_ROOT = self.real_root
        self.tmp.cleanup()

    def fails(self, *messages):
        code, out = self.door.run()
        self.assertEqual(code, 1, out)
        for message in messages:
            self.assertIn(message, out)
        return out

    def section(self, out, check):
        return out.split(f"({check})\n", 1)[1].split("\n\n", 1)[0]

    def test_a_clean_set_passes(self):
        code, out = self.door.run()
        self.assertEqual(code, 0, out)
        self.assertIn("1 certificates in CT cover inference.trymorse.ai. morse-pins has 2 prod records.", out)

    def test_a_rogue_certificate_with_no_record_fails(self):
        rogue = self.door.rogue(["inference.trymorse.ai"])
        self.fails(f"names inference.trymorse.ai with SPKI {hashlib.sha256(spki(rogue)).hexdigest()}, which no record's document attests")

    def test_a_rogue_wildcard_certificate_fails(self):
        rogue = self.door.rogue(["*.TRYMORSE.ai"])
        self.fails(f"names *.TRYMORSE.ai with SPKI {hashlib.sha256(spki(rogue)).hexdigest()}, which no record's document attests")

    def test_a_ct_source_with_no_certificates_fails(self):
        self.door.ct = []
        self.fails(f"{self.door.root / 'ct.json'} returned no certificate covering inference.trymorse.ai, though morse-pins has 2 records")

    def test_a_ct_source_with_only_other_names_fails(self):
        self.door.ct = [certificate(ec.generate_private_key(ec.SECP256R1()), self.door.ca, "admin.trymorse.ai", ["admin.trymorse.ai"], issuer_cn="test ca")]
        self.fails("returned no certificate covering inference.trymorse.ai")

    def test_since_does_not_make_a_ct_source_look_empty(self):
        code, out = self.door.run("--since", "2100-01-01")
        self.assertEqual(code, 0, out)
        self.assertIn("0 certificates in CT cover", out)

    def test_a_label_naming_a_rogue_key_beside_a_genuine_document_fails(self):
        rogue = self.door.rogue(["inference.trymorse.ai"])
        label = hashlib.sha256(spki(rogue)).hexdigest()
        self.door.add_record("2026-11-06T00:00:00Z-forged.json", self.door.record(document(self.door.hpke[2], ec.generate_private_key(ec.SECP256R1())), None, 8, label))
        self.fails(f"with SPKI {label}, which no record's document attests")

    def test_a_junk_public_key_fails(self):
        self.door.add_record("2026-11-06T00:00:00Z-junk.json", self.door.record(document(self.door.hpke[2], None, public_key=b"\x01\x02\x03"), None, 8))
        self.fails("custody link 2026-11-06T00:00:00Z-junk.json does not verify: the document's public_key is not a SubjectPublicKeyInfo")

    def test_a_rsa_public_key_fails(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.door.add_record("2026-11-06T00:00:00Z-rsa.json", self.door.record(document(self.door.hpke[2], key), None, 8))
        self.fails("custody link 2026-11-06T00:00:00Z-rsa.json does not verify: the document's public_key is not a P-256 key")

    def test_a_dev_document_fails(self):
        self.door.add_record("2026-11-06T00:00:00Z-dev.json", self.door.record(document(self.door.hpke[2], self.door.tls, environment="dev"), None, 8))
        self.fails("custody link 2026-11-06T00:00:00Z-dev.json does not verify: the document's user_data does not name a prod HPKE key")

    def test_a_revoked_image_fails(self):
        self.door.add_record("2026-11-06T00:00:00Z-revoked.json", self.door.record(document(self.door.hpke[2], self.door.tls, pcrs=REVOKED_PCRS), None, 8))
        self.fails("does not verify: morse-pins lists no unrevoked prod image with the document's PCRs")

    def test_a_record_made_before_its_image_was_revoked_passes(self):
        self.door.pins.append({"environment": "prod", "pcr0": REVOKED_PCRS[0].hex(), "pcr1": REVOKED_PCRS[1].hex(), "pcr2": REVOKED_PCRS[2].hex(), "revoked": False, "tag": "v2"})
        self.door.add_record("2026-11-06T00:00:00Z-old.json", self.door.record(document(self.door.hpke[2], self.door.tls, pcrs=REVOKED_PCRS, made=NOW - timedelta(days=3)), None, 8))
        self.door.revocations["v2"] = NOW - timedelta(days=2)
        code, out = self.door.run()
        self.assertEqual(code, 0, out)

    def test_a_record_made_after_its_image_was_revoked_fails(self):
        self.door.pins.append({"environment": "prod", "pcr0": REVOKED_PCRS[0].hex(), "pcr1": REVOKED_PCRS[1].hex(), "pcr2": REVOKED_PCRS[2].hex(), "revoked": False, "tag": "v2"})
        self.door.add_record("2026-11-06T00:00:00Z-late.json", self.door.record(document(self.door.hpke[2], self.door.tls, pcrs=REVOKED_PCRS, made=NOW - timedelta(days=1)), None, 8))
        self.door.revocations["v2"] = NOW - timedelta(days=2)
        self.fails("2026-11-06T00:00:00Z-late.json does not verify: morse-pins lists no unrevoked prod image with the document's PCRs at")

    def late_record(self, made):
        self.door.pins.append({"environment": "prod", "pcr0": REVOKED_PCRS[0].hex(), "pcr1": REVOKED_PCRS[1].hex(), "pcr2": REVOKED_PCRS[2].hex(), "revoked": False, "tag": "v2"})
        self.door.add_record("2026-11-06T00:00:00Z-late.json", self.door.record(document(self.door.hpke[2], self.door.tls, pcrs=REVOKED_PCRS, made=made), None, 8))

    def test_the_committer_date_governs_a_revocation_authored_long_ago(self):
        self.late_record(NOW - timedelta(days=1))
        self.door.revocations["v2"] = NOW - timedelta(hours=1)
        self.door.authored["v2"] = NOW - timedelta(days=5)
        code, out = self.door.run()
        self.assertEqual(code, 0, out)

    def test_the_committer_date_governs_a_revocation_authored_later(self):
        self.late_record(NOW - timedelta(days=1))
        self.door.revocations["v2"] = NOW - timedelta(days=2)
        self.door.authored["v2"] = NOW
        self.fails("2026-11-06T00:00:00Z-late.json does not verify: morse-pins lists no unrevoked prod image")

    def test_an_approval_and_a_revocation_in_one_second_leave_the_image_revoked(self):
        self.late_record(NOW - timedelta(days=1))
        self.door.base_time = NOW - timedelta(days=2)
        self.door.revocations["v2"] = NOW - timedelta(days=2)
        self.fails("2026-11-06T00:00:00Z-late.json does not verify: morse-pins lists no unrevoked prod image")

    def test_a_commit_dated_before_the_one_below_it_fails_the_run(self):
        def history(door):
            door.commit_pins(door.pins, NOW - timedelta(days=4))
            door.commit_pins(door.revoked("v1"), NOW - timedelta(days=2))
            door.commit_pins(door.pins, NOW - timedelta(days=3))
        self.door.history = history
        self.fails("FAIL: could not read the evidence", "are not in order")

    def test_a_revocation_undone_inside_a_back_dated_window_fails_the_run(self):
        self.late_record(NOW - timedelta(days=2) + timedelta(minutes=90))
        def history(door):
            door.commit_pins(door.unrevoked("v2"), door.base_time)
            door.commit_pins(door.revoked("v2"), NOW - timedelta(days=2))
            door.commit_pins(door.unrevoked("v2"), NOW - timedelta(days=2) + timedelta(hours=1))
            door.commit_pins(door.revoked("v2"), NOW - timedelta(days=2) + timedelta(hours=2))
        self.door.history = history
        self.fails("FAIL: could not read the evidence", "was revoked and is listed unrevoked again")

    def test_a_revocation_landed_by_a_merge_counts_from_the_merge(self):
        self.late_record(NOW - timedelta(days=4))
        def history(door):
            door.commit_pins(door.unrevoked("v2"), door.base_time)
            door.git("checkout", "-q", "-b", "revoke")
            door.commit_pins(door.revoked("v2"), NOW - timedelta(days=7))
            door.git("checkout", "-q", "main")
            (door.root / "pins/README").write_text("x")
            door.git("add", "README")
            door.git("commit", "-q", "-m", "unrelated", committed=NOW - timedelta(days=5))
            door.git("merge", "-q", "--no-ff", "-m", "merge revoke", "revoke", committed=NOW - timedelta(days=3))
        self.door.history = history
        code, out = self.door.run()
        self.assertEqual(code, 0, out)

        self.door.records["2026-11-06T00:00:00Z-late.json"] = self.door.record(document(self.door.hpke[2], self.door.tls, pcrs=REVOKED_PCRS, made=NOW - timedelta(days=2)), None, 8)
        self.fails("2026-11-06T00:00:00Z-late.json does not verify: morse-pins lists no unrevoked prod image")

    def test_a_pins_history_that_no_longer_holds_the_last_run_s_commit_fails(self):
        self.door.pins.append({"environment": "prod", "pcr0": REVOKED_PCRS[0].hex(), "pcr1": REVOKED_PCRS[1].hex(), "pcr2": REVOKED_PCRS[2].hex(), "revoked": False, "tag": "v2"})
        self.door.revocations["v2"] = NOW - timedelta(days=2)
        self.assertEqual(self.door.run()[0], 0)
        tip = self.door.state()["tip"]
        self.door.revocations["v2"] = NOW - timedelta(days=2) + timedelta(seconds=1)
        self.fails("does not descend from", "which an earlier run saw, so its history was rewritten")
        self.assertEqual(self.door.state()["tip"], tip)

    def test_a_pins_history_that_grew_since_the_last_run_passes(self):
        self.door.pins.append({"environment": "prod", "pcr0": REVOKED_PCRS[0].hex(), "pcr1": REVOKED_PCRS[1].hex(), "pcr2": REVOKED_PCRS[2].hex(), "revoked": False, "tag": "v2"})
        self.assertEqual(self.door.run()[0], 0)
        self.door.revocations["v2"] = NOW - timedelta(days=2)
        code, out = self.door.run()
        self.assertEqual(code, 0, out)

    def test_a_dev_image_with_prod_user_data_fails(self):
        self.door.add_record("2026-11-06T00:00:00Z-devimage.json", self.door.record(document(self.door.hpke[2], self.door.tls, pcrs=DEV_PCRS), None, 8))
        self.fails("does not verify: morse-pins lists no unrevoked prod image with the document's PCRs")

    def test_a_document_not_signed_under_the_nitro_root_fails(self):
        other = ec.generate_private_key(ec.SECP384R1())
        signer = (other, certificate(other, other, "test nitro signer", issuer_cn="test nitro root"))
        self.door.add_record("2026-11-06T00:00:00Z-unsigned.json", self.door.record(document(self.door.hpke[2], self.door.tls, signer=signer), None, 8))
        self.fails("does not verify: CN=test nitro signer is not signed by CN=test nitro root")

    def handed(self, sender, floor):
        self.door.records["2026-11-05T10:00:00Z-handed.json"] = self.door.record(document(self.door.hpke[1], self.door.tls), sender, floor)

    def test_a_broken_custody_link_fails(self):
        self.handed(key_id(b"\x00" * 32), 8)
        self.fails(f"2026-11-05T10:00:00Z-handed.json names sender {key_id(b'\x00' * 32)}, whose HPKE key no record that verifies carries")

    def test_a_falling_floor_fails(self):
        self.handed(key_id(self.door.hpke[0]), 6)
        self.fails("the floor falls from 7 in 2026-11-04T09:12:03Z-born.json to 6 in 2026-11-05T10:00:00Z-handed.json")

    def test_the_same_document_published_under_another_name_fails(self):
        born = base64.b64decode(self.door.records["2026-11-04T09:12:03Z-born.json"]["document"])
        self.door.add_record("2026-11-04T09:12:03Z-born_dup.json", self.door.record(born, None, 1))
        self.handed(key_id(self.door.hpke[0]), 2)
        self.fails(f"2026-11-04T09:12:03Z-born.json and 2026-11-04T09:12:03Z-born_dup.json carry the same HPKE key {key_id(self.door.hpke[0])}")

    def test_two_documents_carrying_one_hpke_key_fail(self):
        self.door.add_record("2026-11-06T00:00:00Z-again.json", self.door.record(document(self.door.hpke[0], self.door.tls), None, 8))
        self.fails(f"2026-11-04T09:12:03Z-born.json and 2026-11-06T00:00:00Z-again.json carry the same HPKE key {key_id(self.door.hpke[0])}")

    def test_a_statement_gap_fails(self):
        self.door.statements[3] = self.door.statements.pop(2)
        self.fails("the statements skip sequence 2")

    def test_a_record_dropped_from_a_later_statement_fails(self):
        self.door.statements[3] = ["2026-11-05T10:00:00Z-handed.json"]
        self.fails("statement 3 drops or changes 2026-11-04T09:12:03Z-born.json, which statement 2 lists")

    def test_a_checkout_rolled_back_to_an_earlier_statement_fails(self):
        code, out = self.door.run()
        self.assertEqual(code, 0, out)
        del self.door.records["2026-11-05T10:00:00Z-handed.json"]
        del self.door.statements[2]
        self.door.live = [document(self.door.hpke[0], self.door.tls)]
        self.fails("the latest statement is sequence 1, and an earlier run saw sequence 2")
        self.fails("the latest statement is sequence 1, and an earlier run saw sequence 2")

    def test_a_second_run_at_the_same_sequence_passes(self):
        self.assertEqual(self.door.run()[0], 0)
        code, out = self.door.run()
        self.assertEqual(code, 0, out)
        state = json.loads((self.door.root / "sequence.json").read_text())
        self.assertEqual(state["sequence"], 2)
        self.assertEqual(state["tip"], subprocess.run(["git", "-C", str(self.door.root / "pins"), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip())

    def test_a_record_no_statement_lists_fails(self):
        self.door.records["2026-11-06T00:00:00Z-unlisted.json"] = self.door.record(document(self.door.hpke[2], self.door.tls), None, 8)
        self.fails("2026-11-06T00:00:00Z-unlisted.json is not in the latest statement as it is")

    def test_a_caa_sample_naming_another_account_fails(self):
        self.door.caa.append(CAA + ['0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/9; validationmethods=dns-01"'])
        self.fails("at 2026-11-02T00:00:00Z: 0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/9; validationmethods=dns-01\" is not one of Morse's ACME accounts")

    def test_a_caa_sample_allowing_http_validation_fails(self):
        self.door.caa.append([f'0 issue "{LE[0]}; accounturi={LE[1]}; validationmethods=dns-01,http-01"'])
        self.fails("is not one of Morse's ACME accounts with dns-01 only")

    def test_a_caa_sample_with_no_record_fails(self):
        self.door.caa.append([])
        self.fails("at 2026-11-02T00:00:00Z no CAA issue property restricted who may issue")

    def sample_with(self, *answers):
        urls = []

        def doh(url):
            urls.append(url)
            return json.dumps(answers[min(len(urls), len(answers)) - 1]).encode()

        with unittest.mock.patch.object(check_door, "fetch", doh):
            code, out = self.door.run(sample=True)
        return code, out, urls

    def samples(self):
        return (self.door.root / "caa.jsonl").read_text().splitlines()

    def test_a_caa_answer_with_a_failing_dns_status_writes_no_sample(self):
        for status in (1, 2, 4, 5):
            with self.subTest(status=status):
                code, out, urls = self.sample_with({"Status": status})
                self.assertEqual(code, 1, out)
                self.assertIn(f"FAIL: could not read the evidence: Refused('the DoH answer for inference.trymorse.ai has Status {status}')", out)
                self.assertEqual(len(urls), 1)
                self.assertEqual(len(self.samples()), 1)

    def test_a_caa_answer_with_no_status_writes_no_sample(self):
        code, out, _ = self.sample_with({"Answer": [{"type": 257, "data": CAA[0]}]})
        self.assertEqual(code, 1, out)
        self.assertEqual(len(self.samples()), 1)

    def test_a_name_that_does_not_exist_falls_through_to_its_parent(self):
        code, out, urls = self.sample_with({"Status": 3}, {"Status": 0, "Answer": [{"type": 257, "data": e} for e in CAA]})
        self.assertEqual(code, 0, out)
        self.assertEqual(len(urls), 2)
        self.assertEqual(len(self.samples()), 2)

    def test_a_live_document_with_an_unrecorded_key_fails_at_once(self):
        rogue = ec.generate_private_key(ec.SECP256R1())
        self.door.live.append(document(self.door.hpke[2], rogue))
        digest = hashlib.sha256(spki(rogue)).hexdigest()
        self.fails(f"live document 2 attests SPKI {digest}, which no record attests",
                   f"the boot with HPKE key {key_id(self.door.hpke[2])} has no record, and its SPKI {digest} is in no record either")

    def test_a_live_boot_with_no_record_behind_a_recorded_spki_fails_once_past_the_grace(self):
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.door.seen(self.door.hpke[2], self.door.tls, check_door.LIVE_GRACE + timedelta(seconds=1))
        self.fails(f"the boot with HPKE key {key_id(self.door.hpke[2])} has no record, and this watcher first saw it live at")

    def test_a_handed_off_boot_passes_until_the_grace_ends_and_then_fails(self):
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        last_run = self.door.state()["last_run"]
        code, out = self.door.run()
        self.assertEqual(code, 0, out)
        first = datetime.fromisoformat(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])
        self.assertEqual(first.isoformat(), last_run)
        later = first + check_door.LIVE_GRACE - timedelta(seconds=1)
        self.door.ran(later - timedelta(minutes=5))
        with unittest.mock.patch.object(check_door, "utcnow", lambda: later):
            code, out = self.door.run()
        self.assertEqual(code, 0, out)
        with unittest.mock.patch.object(check_door, "utcnow", lambda: first + check_door.LIVE_GRACE):
            code, out = self.door.run()
        self.assertEqual(code, 1, out)
        self.assertIn(f"the boot with HPKE key {key_id(self.door.hpke[2])} has no record, and this watcher first saw it live at {first.isoformat(timespec='seconds')}", out)

    def test_a_boot_replaced_inside_its_grace_still_fails_when_the_grace_ends(self):
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.assertEqual(self.door.run()[0], 0)
        first = datetime.fromisoformat(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])
        self.door.live.pop()
        with unittest.mock.patch.object(check_door, "utcnow", lambda: first + check_door.LIVE_GRACE):
            code, out = self.door.run()
        self.assertEqual(code, 1, out)
        self.assertIn(f"the boot with HPKE key {key_id(self.door.hpke[2])} has no record, and this watcher first saw it live at", out)
        self.assertIn(key_id(self.door.hpke[2]), self.door.state()["boots"])

    def test_a_boot_whose_record_lands_late_passes(self):
        self.door.seen(self.door.hpke[2], self.door.tls, check_door.LIVE_GRACE + timedelta(hours=5))
        self.door.add_record("2026-11-06T00:00:00Z-late.json", self.door.record(document(self.door.hpke[2], self.door.tls), key_id(self.door.hpke[1]), 8))
        code, out = self.door.run()
        self.assertEqual(code, 0, out)

    def test_a_recorded_boot_whose_live_spki_no_record_attests_fails_at_once(self):
        rogue = ec.generate_private_key(ec.SECP256R1())
        self.door.live.append(document(self.door.hpke[1], rogue))
        self.fails(f"live document 2 attests SPKI {hashlib.sha256(spki(rogue)).hexdigest()}, which no record attests")

    def test_a_watcher_with_no_state_does_not_report_check_6_ok_and_starts_its_history(self):
        (self.door.root / "sequence.json").unlink()
        code, out = self.door.run()
        self.assertEqual(code, 2, out)
        self.assertIn("NOT ENFORCED: check 6 not enforced: needs --sequence-state", out)
        self.assertNotIn("FAIL", out)
        self.assertEqual(self.door.state()["boots"], {key_id(self.door.hpke[1]): {"first_seen": None, "spki_sha256": hashlib.sha256(spki(self.door.tls)).hexdigest()}})
        code, out = self.door.run()
        self.assertEqual(code, 0, out)

    def test_a_watcher_with_no_state_gives_a_recordless_boot_no_grace_on_any_later_run(self):
        (self.door.root / "sequence.json").unlink()
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        message = f"the boot with HPKE key {key_id(self.door.hpke[2])} has no record, and this watcher cannot date when it first saw it live"
        self.fails(message, "NOT ENFORCED: check 6 not enforced")
        out = self.fails(message)
        self.assertNotIn("NOT ENFORCED", out)
        self.door.live.append(document(bytes([14]) * 32, self.door.tls))
        out = self.fails(message)
        self.assertNotIn(key_id(bytes([14]) * 32), self.section(out, "check 6"))

    def test_a_watcher_with_no_state_fails_an_unrecorded_live_spki_at_once(self):
        (self.door.root / "sequence.json").unlink()
        rogue = ec.generate_private_key(ec.SECP256R1())
        self.door.live.append(document(self.door.hpke[2], rogue))
        self.fails(f"live document 2 attests SPKI {hashlib.sha256(spki(rogue)).hexdigest()}, which no record attests", "NOT ENFORCED: check 6 not enforced")

    def test_an_unreadable_state_fails_and_is_kept(self):
        (self.door.root / "sequence.json").write_text("{not json")
        self.fails("FAIL: could not read the evidence")
        self.assertEqual((self.door.root / "sequence.json").read_text(), "{not json")

    def test_a_state_with_a_first_seen_time_with_no_zone_fails_and_is_kept(self):
        state = json.dumps({"sequence": 0, "boots": {key_id(self.door.hpke[1]): {"first_seen": "2026-11-04T09:12:03", "spki_sha256": hashlib.sha256(spki(self.door.tls)).hexdigest()}}})
        (self.door.root / "sequence.json").write_text(state)
        self.fails("FAIL: could not read the evidence", "with no zone")
        self.assertEqual((self.door.root / "sequence.json").read_text(), state)

    def test_a_watcher_state_from_before_the_boot_history_reads_its_sequence_and_does_not_enforce_check_6_once(self):
        (self.door.root / "sequence.json").write_text(json.dumps({"sequence": 2}))
        code, out = self.door.run()
        self.assertEqual(code, 2, out)
        self.assertIn("NOT ENFORCED: check 6 not enforced", out)
        self.assertEqual(self.door.state()["sequence"], 2)
        self.assertEqual(self.door.run()[0], 0)

    def at(self, when):
        with unittest.mock.patch.object(check_door, "utcnow", lambda: when):
            return self.door.run()

    def test_a_boot_is_dated_to_the_run_before_the_one_that_first_saw_it_so_a_state_restored_from_before_it_cannot_restart_its_grace(self):
        start = datetime.now(timezone.utc)
        self.door.ran(start - timedelta(minutes=5))
        before = (self.door.root / "sequence.json").read_text()
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.assertEqual(self.at(start)[0], 0)
        (self.door.root / "sequence.json").write_text(before)
        self.assertEqual(self.at(start + timedelta(minutes=1))[0], 0)
        self.door.ran(start + timedelta(minutes=110))
        code, out = self.at(start - timedelta(minutes=5) + check_door.LIVE_GRACE)
        self.assertEqual(code, 1, out)
        self.assertIn(f"the boot with HPKE key {key_id(self.door.hpke[2])} has no record, and this watcher first saw it live at {(start - timedelta(minutes=5)).isoformat(timespec='seconds')}", out)

    def test_a_state_restored_from_a_copy_older_than_the_run_gap_is_not_enforced_and_fails_a_recordless_boot(self):
        start = datetime.now(timezone.utc)
        self.door.ran(start - timedelta(minutes=5))
        before = (self.door.root / "sequence.json").read_text()
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.assertEqual(self.at(start)[0], 0)
        (self.door.root / "sequence.json").write_text(before)
        code, out = self.at(start + timedelta(minutes=115))
        self.assertEqual(code, 1, out)
        self.assertIn(f"NOT ENFORCED: check 6 not enforced on this run: the last run was at {(start - timedelta(minutes=5)).isoformat(timespec='seconds')}, more than 7 minutes before this one", out)
        self.assertIn(f"the boot with HPKE key {key_id(self.door.hpke[2])} has no record, and this watcher first saw it live at", out)

    def test_a_run_more_than_7_minutes_after_the_last_is_not_enforced_and_one_inside_is(self):
        now = NOW.replace(microsecond=0)
        self.door.ran(now - timedelta(minutes=7, seconds=1))
        code, out = self.at(now)
        self.assertEqual(code, 2, out)
        self.assertIn("check 6 not enforced on this run", out)
        self.door.ran(now - timedelta(minutes=7))
        code, out = self.at(now)
        self.assertEqual(code, 0, out)

    def live_at(self, made, now):
        self.door.live = [document(self.door.hpke[1], self.door.tls, made=made)]
        self.door.ran(now - timedelta(minutes=5))
        return self.at(now)

    def test_a_live_document_older_than_30_minutes_fails_and_one_30_minutes_old_passes(self):
        now = NOW.replace(microsecond=0)
        self.assertEqual(self.live_at(now - timedelta(minutes=30), now)[0], 0)
        code, out = self.live_at(now - timedelta(minutes=30, seconds=1), now)
        self.assertEqual(code, 1, out)
        self.assertIn(f"live document 1: AWS Nitro signed the document at {(now - timedelta(minutes=30, seconds=1)).isoformat(timespec='seconds')}, 30 minutes before this run, and the relay refreshes each live document every 10 minutes and lists a peer's only while it is under 25 minutes old, so one older than 30 minutes is not live", out)

    def test_a_stale_live_document_gets_no_boot_and_its_key_no_time_under_check_1(self):
        now = NOW.replace(microsecond=0)
        tls = ec.generate_private_key(ec.SECP256R1())
        self.door.ct.append(certificate(tls, self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai"], issuer_cn="test ca"))
        self.door.live = [document(self.door.hpke[1], self.door.tls, made=now - timedelta(minutes=1)), document(self.door.hpke[2], tls, made=now - timedelta(hours=1))]
        self.door.ran(now - timedelta(minutes=5))
        code, out = self.at(now)
        self.assertEqual(code, 1, out)
        self.assertIn("live document 2: AWS Nitro signed the document at", self.section(out, "check 6"))
        self.assertIn(f"with SPKI {hashlib.sha256(spki(tls)).hexdigest()}, which no record's document attests", self.section(out, "checks 1 and 2"))
        self.assertNotIn(key_id(self.door.hpke[2]), self.door.state()["boots"])

    def test_a_live_document_from_an_image_revoked_after_it_was_made_fails_once_it_is_stale(self):
        now = NOW.replace(microsecond=0)
        self.door.pins[2]["revoked"] = False
        self.door.revocations["v0"] = now - timedelta(days=1)
        code, out = self.live_at(now - timedelta(days=3), now)
        self.assertEqual(code, 1, out)
        self.assertIn("live document 1: AWS Nitro signed the document at", out)

    def test_a_live_document_ahead_of_the_clock_by_more_than_the_skew_fails(self):
        now = NOW.replace(microsecond=0)
        self.assertEqual(self.live_at(now + check_door.MAX_AHEAD, now)[0], 0)
        code, out = self.live_at(now + check_door.MAX_AHEAD + timedelta(seconds=1), now)
        self.assertEqual(code, 1, out)
        self.assertIn(f"live document 1: AWS Nitro signed the document at {(now + check_door.MAX_AHEAD + timedelta(seconds=1)).isoformat(timespec='seconds')}, more than 2 minutes after this run's clock reads {now.isoformat(timespec='seconds')}, so this watcher's clock is behind", out)

    def test_a_frozen_watcher_clock_fails_once_the_relay_refreshes_its_document(self):
        frozen = NOW.replace(microsecond=0)
        self.assertEqual(self.live_at(frozen, frozen)[0], 0)
        code, out = self.live_at(frozen + timedelta(minutes=10), frozen)
        self.assertEqual(code, 1, out)
        self.assertIn("so this watcher's clock is behind", out)

    def test_a_run_reads_its_clock_and_the_attestation_before_ct_so_a_slow_ct_read_moves_neither(self):
        start = NOW.replace(microsecond=0)
        clock = [start]
        read_ct, read_bytes = check_door.read_ct, Path.read_bytes
        order = []

        def slow_ct(source, name):
            order.append("ct")
            clock[0] += timedelta(minutes=3)
            return read_ct(source, name)

        def watched(path):
            if path.name == "attestation.json":
                order.append("attestation")
            return read_bytes(path)

        self.door.live = [document(self.door.hpke[1], self.door.tls, made=start - timedelta(minutes=29, seconds=30))]
        self.door.ran(start - timedelta(minutes=6))
        with unittest.mock.patch.object(check_door, "utcnow", lambda: clock[0]), unittest.mock.patch.object(check_door, "read_ct", slow_ct), \
                unittest.mock.patch.object(check_door.Path, "read_bytes", watched):
            code, out = self.door.run()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.door.state()["last_run"], start.isoformat())
        self.assertEqual(order, ["attestation", "ct"])

    def test_each_run_writes_its_own_time_as_the_last_run(self):
        when = datetime.now(timezone.utc) + timedelta(minutes=3)
        self.at(when)
        self.assertEqual(self.door.state()["last_run"], when.isoformat())

    def test_a_state_with_boots_and_no_last_run_is_not_enforced_and_gives_a_live_boot_no_grace(self):
        (self.door.root / "sequence.json").write_text(json.dumps({"boots": {}}))
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.fails(f"the boot with HPKE key {key_id(self.door.hpke[2])} has no record, and this watcher cannot date when it first saw it live", "NOT ENFORCED: check 6 not enforced: needs --sequence-state")

    def test_a_last_run_time_with_no_zone_fails_and_is_kept(self):
        state = json.dumps({"sequence": 0, "last_run": "2026-11-04T09:12:03", "boots": {}})
        (self.door.root / "sequence.json").write_text(state)
        self.fails("FAIL: could not read the evidence", "with no zone")
        self.assertEqual((self.door.root / "sequence.json").read_text(), state)

    def test_a_clock_behind_the_last_run_fails_and_a_boot_it_first_sees_gets_no_grace(self):
        now = datetime.now(timezone.utc)
        self.door.ran(now + timedelta(days=1))
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.fails(f"this run's clock reads", f"before {(now + timedelta(days=1)).isoformat(timespec='seconds')}, when the last run wrote --sequence-state",
                   f"the boot with HPKE key {key_id(self.door.hpke[2])} has no record, and this watcher cannot date when it first saw it live")
        self.assertIsNone(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])

    def test_a_clock_behind_the_last_run_by_less_than_the_skew_passes(self):
        self.door.ran(datetime.now(timezone.utc) + check_door.MAX_AHEAD - timedelta(seconds=10))
        code, out = self.door.run()
        self.assertEqual(code, 0, out)

    def test_a_first_seen_time_ahead_of_the_clock_is_an_unknown_age(self):
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.door.seen(self.door.hpke[2], self.door.tls, -timedelta(days=1))
        self.fails(f"the boot with HPKE key {key_id(self.door.hpke[2])} has no record, and this watcher cannot date when it first saw it live")
        self.assertIsNone(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])

    def test_a_first_seen_time_ahead_of_the_clock_by_less_than_the_skew_keeps_its_grace(self):
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.door.seen(self.door.hpke[2], self.door.tls, -check_door.MAX_AHEAD + timedelta(seconds=10))
        code, out = self.door.run()
        self.assertEqual(code, 0, out)

    def test_a_live_document_from_an_unpinned_image_is_named_as_such_and_not_as_a_fresh_order(self):
        for pcrs in (REVOKED_PCRS, [bytes(48)] * 3):
            with self.subTest(pcrs=pcrs[0][:1].hex()):
                self.door = Door(tempfile.mkdtemp(dir=self.tmp.name))
                rogue = ec.generate_private_key(ec.SECP256R1())
                self.door.live.append(document(self.door.hpke[2], rogue, pcrs=pcrs))
                out = self.section(self.fails("live document 2 is from an image no record can admit: morse-pins lists no unrevoked prod image with the document's PCRs at"), "check 6")
                self.assertNotIn("live document 2 attests SPKI", out)

    def test_a_live_document_from_a_revoked_image_holding_a_recorded_key_fails_at_once(self):
        self.door.live.append(document(self.door.hpke[2], self.door.tls, pcrs=REVOKED_PCRS))
        self.fails("live document 2 is from an image no record can admit")

    def test_a_certificate_for_a_key_only_an_unpinned_live_image_holds_gets_no_grace(self):
        for pcrs in (REVOKED_PCRS, [bytes(48)] * 3):
            with self.subTest(pcrs=pcrs[0][:1].hex()):
                self.door = Door(tempfile.mkdtemp(dir=self.tmp.name))
                rogue = ec.generate_private_key(ec.SECP256R1())
                self.door.live.append(document(self.door.hpke[2], rogue, pcrs=pcrs))
                self.door.ct.append(certificate(rogue, self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai"], issuer_cn="test ca"))
                self.assertIn(f"with SPKI {hashlib.sha256(spki(rogue)).hexdigest()}, which no record's document attests", self.section(self.fails(), "checks 1 and 2"))

    def fresh_order(self):
        tls = ec.generate_private_key(ec.SECP256R1())
        self.door.live.append(document(self.door.hpke[2], tls))
        self.door.ct.append(certificate(tls, self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai"], issuer_cn="test ca"))
        return tls

    def test_a_fresh_order_certificate_passes_check_1_inside_its_live_boots_grace_and_fails_after(self):
        tls = self.fresh_order()
        out = self.fails(f"live document 2 attests SPKI {hashlib.sha256(spki(tls)).hexdigest()}, which no record attests")
        self.assertEqual(self.section(out, "checks 1 and 2"), "  OK")
        first = datetime.fromisoformat(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])
        with unittest.mock.patch.object(check_door, "utcnow", lambda: first + check_door.LIVE_GRACE):
            code, out = self.door.run()
        self.assertEqual(code, 1, out)
        self.assertIn(f"with SPKI {hashlib.sha256(spki(tls)).hexdigest()}, which no record's document attests", self.section(out, "checks 1 and 2"))

    def test_a_certificate_for_a_live_spki_first_seen_under_an_earlier_boot_gets_no_new_grace(self):
        tls = self.fresh_order()
        self.door.seen(self.door.hpke[0], tls, check_door.LIVE_GRACE + timedelta(seconds=1))
        out = self.fails()
        self.assertIn(f"with SPKI {hashlib.sha256(spki(tls)).hexdigest()}, which no record's document attests", self.section(out, "checks 1 and 2"))

    def test_a_certificate_for_a_spki_no_boot_showed_live_gets_no_grace(self):
        self.door.seen(self.door.hpke[2], self.door.rogue(["inference.trymorse.ai"]), timedelta(minutes=1))
        self.assertIn("which no record's document attests", self.section(self.fails(), "checks 1 and 2"))

    def test_a_fresh_order_certificate_gets_no_grace_from_a_watcher_with_no_state(self):
        (self.door.root / "sequence.json").unlink()
        self.fresh_order()
        self.assertIn("which no record's document attests", self.section(self.fails(), "checks 1 and 2"))

    def test_a_record_that_does_not_parse_is_refused_and_the_other_checks_run(self):
        record = self.door.record(document(self.door.hpke[2], self.door.tls), key_id(self.door.hpke[1]), 8)
        for born in ("2026-11-04T03:39:60Z", "2026-11-04T03:39:52+24:00", "0001-01-01T00:30:00+01:00", "\u0662\u0660\u0662\u0666-11-04T03:39:52Z", "2026-11-04T03:39:52.12345678\u0669Z"):
            with self.subTest(born=born):
                self.door.add_record("2026-11-06T00:00:00Z-bad.json", {**record, "origin": {**record["origin"], "born": born}})
                out = self.fails("custody link 2026-11-06T00:00:00Z-bad.json does not verify: origin.born")
                self.assertEqual(self.section(out, "check 4"), "  OK")
                self.assertEqual(self.section(out, "check 5"), "  OK")
                del self.door.records["2026-11-06T00:00:00Z-bad.json"]
                self.door.statements.popitem()
        for name, junk in (("floor", {**record, "origin": {**record["origin"], "floor": "8"}}), ("document", {**record, "document": "!!"}), ("list", [])):
            with self.subTest(junk=name):
                self.door.add_record("2026-11-06T00:00:00Z-junk.json", junk)
                out = self.fails(f"custody link 2026-11-06T00:00:00Z-junk.json does not verify: the record {'does not parse' if name == 'document' else 'is not a JSON object with a document'}")
                self.assertEqual(self.section(out, "check 5"), "  OK")
                del self.door.records["2026-11-06T00:00:00Z-junk.json"]
                self.door.statements.popitem()

    def test_an_origin_the_documents_nonce_does_not_attest_fails(self):
        record = self.door.records["2026-11-05T10:00:00Z-handed.json"]
        for change in ({"from": None}, {"floor": 9}, {"born": "2026-11-04T09:12:04Z"}):
            with self.subTest(change=change):
                self.door.records["2026-11-05T10:00:00Z-handed.json"] = {**record, "origin": {**record["origin"], **change}}
                self.fails("2026-11-05T10:00:00Z-handed.json does not verify: the document's nonce is not the origin statement of its SPKI and the record's origin")

    def test_a_document_with_no_nonce_fails(self):
        self.door.add_record("2026-11-06T00:00:00Z-nonce.json", {**self.door.record(document(self.door.hpke[2], self.door.tls), None, 8),
                                                                  "document": base64.b64encode(document(self.door.hpke[2], self.door.tls)).decode()})
        self.fails("custody link 2026-11-06T00:00:00Z-nonce.json does not verify: the document's nonce is not the origin statement")

    def test_the_origin_nonce_is_the_backends_golden_statement(self):
        sender = hashlib.sha256(b"sender").hexdigest()[:16]
        golden = '{"origin":{"born":"2026-11-04T17:12:03.12Z","floor":7,"from":"' + sender + '"},"spki_sha256":"9f3c","type":"morse-door-origin-v1"}'
        self.assertEqual(check_door.origin_nonce("9f3c", "2026-11-04T09:12:03.120-08:00", sender, 7), hashlib.sha256(golden.encode()).digest())
        born = '{"origin":{"born":"2026-11-04T17:12:03.12Z","floor":7,"from":null},"spki_sha256":"9f3c","type":"morse-door-origin-v1"}'
        self.assertEqual(check_door.origin_nonce("9f3c", "2026-11-04T17:12:03.120000000Z", None, 7), hashlib.sha256(born.encode()).digest())
        self.assertEqual(check_door.canonical_time("2026-11-04T17:12:03.000000000Z"), "2026-11-04T17:12:03Z")
        self.assertEqual(check_door.canonical_time("2026-11-04T23:12:03.123456789-08:00"), "2026-11-05T07:12:03.123456789Z")

    def test_a_live_document_for_another_environment_fails(self):
        self.door.live.append(document(self.door.hpke[1], self.door.tls, environment="dev"))
        self.fails("live document 2: the document's user_data does not name a prod HPKE key")

    def test_a_real_aws_document_verifies_at_its_own_time_and_its_dev_user_data_fails_for_prod(self):
        check_door.nitro.AWS_NITRO_ROOT = self.real_root
        real = base64.b64decode(REAL_DOCUMENT.read_text())
        self.door.pins.append({"environment": "prod", "revoked": False, "tag": "real",
                               "pcr0": "1dab5ad4c661f95a9e7e3f57bcd83efd9fced7f749ac21ea85a1853131bb5e43b41eb58615efef998d478ce485fcff53",
                               "pcr1": "3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03",
                               "pcr2": "f9d2c68436810c46556535a583870e2913ec1f05ecca361b4e78eaa00d0b365dee6570e7699c4f34165fbf635bf35c6a"})
        self.door.records = {"2026-10-17T16:48:24Z-real.json": self.door.record(real, None, 1)}
        self.door.statements = {1: ["2026-10-17T16:48:24Z-real.json"]}
        self.door.ct, self.door.live = [], []
        self.fails("custody link 2026-10-17T16:48:24Z-real.json does not verify: the document's user_data does not name a prod HPKE key")


if __name__ == "__main__":
    unittest.main()

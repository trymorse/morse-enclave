# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2==6.1.5", "cryptography==50.0.2", "tuf==7.0.1", "securesystemslib==1.6.0", "urllib3==2.8.0"]
# ///
"""Tests check-door.py's checks of certificates, pointers and records, custody, CAA, the live boots and morse-records'
visibility, against the fixtures in check_door_fixtures.py. It reads nothing from the network. test_rekor.py tests the
Rekor v2 reader, TUF, and the checks of the shards and their witnesses.

Usage: uv run test_check_door.py
"""

import base64
import hashlib
import http.client
import json
import sys
import tempfile
import unittest
import unittest.mock
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

sys.dont_write_bytecode = True
from check_door_fixtures import *  # noqa: E402,F403


class CertificatesTest(Fixture):
    def test_a_clean_set_passes(self):
        out = self.passes("1 certificates in CT cover inference.trymorse.ai. morse-records has 2 prod pointers, and 2 of their entries verify.")
        self.assertNotIn("NOTE", out)
        for check in ("check 1", "check 2", "check 3", "check 4", "check 5", "check 6", "check 7", "check 8", "check 9"):
            self.assertEqual(self.section(out, check), "  OK")

    def test_a_rogue_certificate_with_no_record_fails(self):
        rogue = self.door.rogue(["inference.trymorse.ai"])
        self.fails(f"names inference.trymorse.ai {self.unrecorded(rogue)}, and CT made it public at")

    def test_a_rogue_wildcard_certificate_fails(self):
        rogue = self.door.rogue(["*.TRYMORSE.ai"])
        self.fails(f"names *.TRYMORSE.ai {self.unrecorded(rogue)}")

    def test_a_ct_source_with_no_certificates_fails(self):
        self.door.ct = []
        self.fails(f"{self.door.root / 'ct.json'} returned no certificate covering inference.trymorse.ai, though 1 SPKIs have verified records")

    def test_a_ct_source_with_only_other_names_fails(self):
        self.door.ct = [certificate(ec.generate_private_key(ec.SECP256R1()), self.door.ca, "admin.trymorse.ai", ["admin.trymorse.ai"], issuer_cn="test ca")]
        self.fails("returned no certificate covering inference.trymorse.ai")

    def test_since_does_not_make_a_ct_source_look_empty(self):
        code, out = self.door.run("--since", "2100-01-01")
        self.assertEqual(code, 0, out)
        self.assertIn("0 certificates in CT cover", out)

    def test_a_certificate_has_20_minutes_from_its_ct_time_for_its_pointer(self):
        now = NOW.replace(microsecond=0)
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()), not_before=now - timedelta(minutes=19))
        self.door.ran(now - timedelta(minutes=5))
        code, out = self.at(now)
        self.assertEqual(code, 0, out)
        self.assertIn(f"NOTE: {self.door.root / 'ct.json'} 2 names inference.trymorse.ai {self.unrecorded(tls)} yet", out)
        self.door.ran(now + timedelta(minutes=1))
        code, out = self.at(now + timedelta(minutes=1, seconds=1))
        self.assertEqual(code, 1, out)
        self.assertIn(f"FAIL: {self.door.root / 'ct.json'} 2 names inference.trymorse.ai {self.unrecorded(tls)}, and CT made it public at", out)

    def test_crtsh_s_entry_time_starts_the_20_minutes_and_not_a_back_dated_not_before(self):
        now = NOW.replace(microsecond=0)
        tls = ec.generate_private_key(ec.SECP256R1())
        cert = certificate(tls, self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai"], issuer_cn="test ca", not_before=now - timedelta(days=3))
        genuine = self.door.ct[0]
        self.door.crtsh = {
            check_door.CRTSH_URL.format("trymorse.ai"): json.dumps([
                {"id": 1, "name_value": "inference.trymorse.ai", "entry_timestamp": (now - timedelta(days=3)).replace(tzinfo=None).isoformat()},
                {"id": 2, "name_value": "inference.trymorse.ai", "entry_timestamp": (now - timedelta(minutes=5)).replace(tzinfo=None).isoformat()},
                {"id": 3, "name_value": "admin.trymorse.ai", "entry_timestamp": None}]).encode(),
            check_door.CRTSH_CERT_URL.format(1): genuine.public_bytes(serialization.Encoding.PEM),
            check_door.CRTSH_CERT_URL.format(2): cert.public_bytes(serialization.Encoding.PEM),
        }
        self.door.ran(now - timedelta(minutes=5))
        with unittest.mock.patch.object(check_door, "utcnow", lambda: now):
            code, out = self.door.run("--ct", "crt.sh")
        self.assertEqual(code, 0, out)
        self.assertIn(f"NOTE: crt.sh 2 names inference.trymorse.ai {self.unrecorded(tls)} yet. CT made it public at {(now - timedelta(minutes=5)).isoformat(timespec='seconds')}", out)

    def crtsh_answers(self, *certs):
        rows = [{"id": n, "name_value": "inference.trymorse.ai", "entry_timestamp": None} for n in range(len(certs))]
        self.door.crtsh = {check_door.CRTSH_URL.format("trymorse.ai"): json.dumps(rows).encode()}
        self.door.crtsh |= {check_door.CRTSH_CERT_URL.format(n): c.public_bytes(serialization.Encoding.PEM) for n, c in enumerate(certs)}

    def crtsh_unreachable(self):
        self.door.crtsh = {check_door.CRTSH_URL.format("trymorse.ai"): urllib.error.URLError(OSError(101, "Network is unreachable"))}
        self.door.doh = lambda url: json.dumps({"Status": 0, "Answer": [{"type": 257, "data": e} for e in CAA]}).encode()
        return "URLError(OSError(101, 'Network is unreachable'))"

    def test_a_ct_source_that_cannot_be_read_is_a_note_and_check_1_is_judged_from_the_other(self):
        error = self.crtsh_unreachable()
        ct = self.door.root / "ct.json"
        code, out = self.door.run("--ct", "crt.sh", "--ct", str(ct), sample=True)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.section(out, "check 1"), f"  NOTE: crt.sh could not be read, so this run judges check 1 from {ct} alone: {error}\n  OK")
        self.assertEqual(len((self.door.root / "caa.jsonl").read_text().splitlines()), 2)
        rogue = self.door.rogue(["inference.trymorse.ai"])
        code, out = self.door.run("--ct", "crt.sh", "--ct", str(ct))
        self.assertEqual(code, 1, out)
        self.assertIn(f"FAIL: {ct} 2 names inference.trymorse.ai {self.unrecorded(rogue)}, and CT made it public at", out)

    def test_no_ct_source_that_can_be_read_leaves_the_evidence_unread(self):
        error = self.crtsh_unreachable()
        missing = self.door.root / "missing.json"
        code, out = self.door.run("--ct", "crt.sh", "--ct", str(missing), sample=True)
        self.assertEqual(code, 1, out)
        self.assertIn(f"FAIL: could not read the evidence: OSError(\"no CT source could be read: crt.sh: {error}; {missing}: FileNotFoundError(2, 'No such file or directory')\")", out)
        self.assertNotIn("  FAIL: ", out)
        self.assertEqual(len((self.door.root / "caa.jsonl").read_text().splitlines()), 1)

    def test_a_certificate_that_does_not_parse_leaves_the_evidence_unread_while_the_other_source_answers(self):
        self.crtsh_answers(self.door.ct[0])
        bad = self.door.root / "bad.json"
        bad.write_text(json.dumps([{"id": "0", "cert_der": base64.b64encode(b"not a certificate").decode()}]))
        code, out = self.door.run("--ct", "crt.sh", "--ct", str(bad))
        self.assertEqual(code, 1, out)
        self.assertIn("FAIL: could not read the evidence: ValueError(", out)
        self.assertNotIn("could not be read, so this run judges check 1", out)

    def test_a_crtsh_certificate_that_does_not_parse_leaves_the_evidence_unread_while_the_other_source_answers(self):
        self.crtsh_answers(self.door.ct[0])
        self.door.crtsh[check_door.CRTSH_CERT_URL.format(0)] = b"not a certificate"
        code, out = self.door.run("--ct", "crt.sh", "--ct", str(self.door.root / "ct.json"))
        self.assertEqual(code, 1, out)
        self.assertIn("FAIL: could not read the evidence: ValueError(", out)
        self.assertNotIn("could not be read, so this run judges check 1", out)

    def test_two_ct_sources_that_answer_leave_no_note(self):
        self.crtsh_answers(self.door.ct[0])
        out = self.door.run("--ct", "crt.sh", "--ct", str(self.door.root / "ct.json"))[1]
        self.assertEqual(self.section(out, "check 1"), "  OK")

    def crtsh_lags(self, *later):
        """crt.sh answers with no certificate until it has been read len(later) + 1 times, then with later's last."""
        self.crtsh_answers()
        delays = []

        def sleep(delay):
            delays.append(delay)
            if len(delays) == len(later):
                self.crtsh_answers(*later[-1])
        return unittest.mock.patch.object(check_door.time, "sleep", sleep), delays

    def test_crtsh_with_none_of_the_certificates_another_source_returns_is_read_again_then_taken_as_unread(self):
        ct = self.door.root / "ct.json"
        sleeping, delays = self.crtsh_lags()
        with sleeping:
            code, out = self.door.run("--ct", "crt.sh", "--ct", str(ct))
        self.assertEqual(code, 0, out)
        self.assertEqual(delays, list(check_door.CRTSH_RETRY_DELAYS))
        self.assertEqual(self.section(out, "check 1"), f"  NOTE: crt.sh could not be read, so this run judges check 1 from {ct} alone: "
                         f"LookupError('it returned no certificate covering inference.trymorse.ai in 3 reads, though {ct} returned 1')\n  OK")

    def test_crtsh_that_answers_on_a_later_read_is_judged_as_usual(self):
        ct = self.door.root / "ct.json"
        sleeping, delays = self.crtsh_lags([], [self.door.ct[0]])
        with sleeping:
            code, out = self.door.run("--ct", "crt.sh", "--ct", str(ct))
        self.assertEqual(code, 0, out)
        self.assertEqual(delays, list(check_door.CRTSH_RETRY_DELAYS))
        self.assertEqual(self.section(out, "check 1"), "  OK")

    def test_crtsh_that_answers_on_a_later_read_with_a_rogue_certificate_fails(self):
        rogue = certificate(ec.generate_private_key(ec.SECP256R1()), self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai"], issuer_cn="test ca")
        sleeping, _ = self.crtsh_lags([rogue])
        with sleeping:
            code, out = self.door.run("--ct", "crt.sh", "--ct", str(self.door.root / "ct.json"))
        self.assertEqual(code, 1, out)
        self.assertIn(f"FAIL: crt.sh 0 names inference.trymorse.ai {self.unrecorded(rogue)}, and CT made it public at", out)

    def test_a_rogue_certificate_only_the_other_source_returns_fails_while_crtsh_has_none(self):
        rogue = self.door.rogue(["inference.trymorse.ai"])
        ct = self.door.root / "ct.json"
        sleeping, _ = self.crtsh_lags()
        with sleeping:
            code, out = self.door.run("--ct", "crt.sh", "--ct", str(ct))
        self.assertEqual(code, 1, out)
        self.assertIn("NOTE: crt.sh could not be read, so this run judges check 1", out)
        self.assertIn(f"FAIL: {ct} 2 names inference.trymorse.ai {self.unrecorded(rogue)}, and CT made it public at", out)

    def test_a_rogue_certificate_only_crtsh_returns_fails(self):
        rogue = certificate(ec.generate_private_key(ec.SECP256R1()), self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai"], issuer_cn="test ca")
        self.crtsh_answers(self.door.ct[0], rogue)
        with unittest.mock.patch.object(check_door.time, "sleep", lambda delay: self.fail("crt.sh is read again")):
            code, out = self.door.run("--ct", "crt.sh", "--ct", str(self.door.root / "ct.json"))
        self.assertEqual(code, 1, out)
        self.assertIn(f"FAIL: crt.sh 1 names inference.trymorse.ai {self.unrecorded(rogue)}, and CT made it public at", out)

    def test_the_other_source_with_none_of_the_certificates_crtsh_returns_still_fails(self):
        self.crtsh_answers(self.door.ct[0])
        empty = self.door.root / "empty.json"
        empty.write_text("[]")
        code, out = self.door.run("--ct", "crt.sh", "--ct", str(empty))
        self.assertEqual(code, 1, out)
        self.assertIn(f"FAIL: {empty} returned no certificate covering inference.trymorse.ai, though crt.sh returned 1", out)

    def test_a_certificate_from_after_its_key_is_60_days_old_fails(self):
        self.door.needed(self.door.tls, not_before=BORN + timedelta(days=60))
        self.passes()
        self.door.ct[-1] = certificate(self.door.tls, self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai"], issuer_cn="test ca", not_before=BORN + timedelta(days=60, seconds=1))
        self.fails(f"with SPKI {spki_hex(self.door.tls)} from {(BORN + timedelta(days=60, seconds=1)).isoformat(timespec='seconds')}, after the key, born at {BORN.isoformat(timespec='seconds')}, was 60 days old")


class RevocationTest(Fixture):
    def setUp(self):
        super().setUp()
        self.ca = self.door.revoking

    def wildcard(self, revoked=False, **kwargs):
        cert = self.ca.issue(["trymorse.ai", "*.trymorse.ai"], **kwargs)
        if revoked:
            self.ca.revoke(cert)
        self.door.ct.append(cert)
        return f"{self.door.root / 'ct.json'} {len(self.door.ct) - 1} names trymorse.ai, *.trymorse.ai with SPKI {hashlib.sha256(spki(cert)).hexdigest()}, which no verified record attests"

    def skipped(self, label, how):
        out = self.passes(f"NOTE: revoked, skipped: {label}, and CT made it public at")
        self.assertIn(f"Its CA revoked it, by {how}\n", out)
        self.assertEqual(self.section(out, "check 1").splitlines()[-1], "  OK")
        return out

    def counted(self, label, why):
        out = self.fails(f"FAIL: {label}, and CT made it public at")
        self.assertIn(why, self.section(out, "check 1"))
        return out

    def test_a_certificate_its_ca_revoked_by_ocsp_is_skipped(self):
        self.skipped(self.wildcard(revoked=True), f"OCSP {CA.OCSP}")
        self.assertNotIn(CA.CRL, self.ca.asked)

    def test_a_certificate_its_ca_has_not_revoked_fails(self):
        self.counted(self.wildcard(), f"Its CA has not revoked it, by OCSP {CA.OCSP}")

    def test_a_certificate_on_a_crl_with_no_ocsp_responder_is_skipped(self):
        self.skipped(self.wildcard(revoked=True, ocsp=False), f"CRL {CA.CRL}")

    def test_a_certificate_missing_from_its_crl_fails(self):
        self.counted(self.wildcard(ocsp=False), f"Its CA has not revoked it, by CRL {CA.CRL}")

    def test_the_crl_answers_when_the_ocsp_responder_does_not(self):
        self.ca.down.add("ocsp.ca.test")
        self.skipped(self.wildcard(revoked=True), f"CRL {CA.CRL}")

    def test_a_certificate_whose_revocation_cannot_be_read_counts(self):
        self.ca.down.add("ocsp.ca.test")
        self.counted(self.wildcard(revoked=True, crl=False), f"Whether its CA revoked it is unknown, so it counts: the OCSP responder at {CA.OCSP} could not be read")
        self.ca.down.add(CA.CRL)
        self.counted(self.wildcard(revoked=True), f"; the CRL at {CA.CRL} could not be read")

    def test_a_reply_cut_off_partway_counts_the_certificate_and_the_run_goes_on(self):
        self.ca.broken["ocsp.ca.test"] = http.client.IncompleteRead(b"0", 100)
        out = self.counted(self.wildcard(revoked=True, crl=False), f"Whether its CA revoked it is unknown, so it counts: the OCSP answer from {CA.OCSP} could not be read: IncompleteRead(")
        self.assertIn("(check 9)", out)

    def test_a_certificate_that_names_no_responder_and_no_crl_counts(self):
        self.counted(self.wildcard(revoked=True, ocsp=False, crl=False), "Whether its CA revoked it is unknown, so it counts: it names neither an OCSP responder nor a CRL")

    def test_an_unreachable_issuer_counts_the_certificate(self):
        self.ca.down.add(CA.ISSUER)
        self.counted(self.wildcard(revoked=True), f"Whether its CA revoked it is unknown, so it counts: its issuer at {CA.ISSUER} could not be read")

    def test_an_issuer_that_did_not_sign_the_certificate_counts_it(self):
        self.ca.served_issuer = CA().cert
        self.counted(self.wildcard(revoked=True), f"Whether its CA revoked it is unknown, so it counts: {CA.ISSUER} holds no certificate that signed it")

    def test_an_ocsp_answer_its_issuer_did_not_sign_counts_the_certificate(self):
        impostor = ec.generate_private_key(ec.SECP256R1())
        named_alike = certificate(impostor, impostor, "test revoking ca", ca=True)
        self.ca.ocsp_signer = (impostor, named_alike, [named_alike])
        self.counted(self.wildcard(revoked=True, crl=False), f"the OCSP responder at {CA.OCSP} answered with a signature its issuer did not make or delegate")

    def test_a_delegated_responder_answers_only_with_the_ocsp_signing_usage(self):
        self.ca.delegate_ocsp()
        label = self.wildcard(revoked=True, crl=False)
        self.skipped(label, f"OCSP {CA.OCSP}")
        self.ca.delegate_ocsp(eku=ExtendedKeyUsageOID.SERVER_AUTH)
        self.counted(label, "answered with a signature its issuer did not make or delegate")

    def test_a_crl_its_issuer_did_not_sign_counts_the_certificate(self):
        self.ca.crl_key = ec.generate_private_key(ec.SECP256R1())
        self.counted(self.wildcard(revoked=True, ocsp=False), f"the CRL at {CA.CRL} is not signed by its issuer")

    def test_a_certificate_on_hold_counts(self):
        label = self.wildcard()
        self.ca.revoke(self.door.ct[-1], x509.ReasonFlags.certificate_hold)
        self.counted(label, f"Whether its CA revoked it is unknown, so it counts: its CA holds it, by OCSP {CA.OCSP}, and may release it")

    def test_a_certificate_with_a_verified_record_asks_no_ca(self):
        self.door.ct[0] = self.ca.issue(["inference.trymorse.ai"], key=self.door.tls)
        self.ca.down.update({"ocsp.ca.test", CA.CRL})
        self.passes()
        self.assertEqual(self.ca.asked, [])

    def test_a_certificate_inside_its_20_minutes_asks_no_ca(self):
        now = NOW.replace(microsecond=0)
        cert = self.ca.issue(["inference.trymorse.ai"], not_before=now - timedelta(minutes=5))
        self.ca.revoke(cert)
        self.door.ct.append(cert)
        self.door.ran(now - timedelta(minutes=5))
        code, out = self.at(now)
        self.assertEqual(code, 0, out)
        self.assertIn("which no verified record attests yet", out)
        self.assertNotIn("revoked, skipped", out)
        self.assertEqual(self.ca.asked, [])


class RecordsTest(Fixture):
    def test_a_label_naming_a_rogue_key_beside_a_genuine_document_fails(self):
        rogue = self.door.rogue(["inference.trymorse.ai"])
        record = self.door.record(document(self.door.hpke[2], ec.generate_private_key(ec.SECP256R1())), None, 8, spki_hex(rogue))
        index = self.door.add(record, digest=check_door.records.record_digest(spki_hex(rogue)))
        self.fails(self.ignored(index, "spki: the record's spki_sha256 is"), self.unrecorded(rogue))

    def test_a_digest_that_is_not_h_of_the_documents_spki_fails(self):
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        index = self.door.add(self.door.record(document(self.door.hpke[2], tls), None, 8), digest=check_door.records.record_digest(spki_hex(self.door.tls)))
        self.fails(self.ignored(index, f"digest: the entry's digest is not H for SPKI {spki_hex(tls)}"), self.unrecorded(tls))

    def test_a_junk_public_key_fails(self):
        index = self.door.add(self.door.record(document(self.door.hpke[2], None, public_key=b"\x01\x02\x03"), None, 8))
        out = self.door.run()[1]
        self.assertIn(self.ignored(index, "document: the document's public_key is not a SubjectPublicKeyInfo"), out)

    def test_a_rsa_public_key_fails(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        index = self.door.add(self.door.record(document(self.door.hpke[2], key), None, 8))
        self.assertIn(self.ignored(index, "document: the document's public_key is not a P-256 key"), self.door.run()[1])

    def test_a_dev_document_fails(self):
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        index = self.door.add(self.door.record(document(self.door.hpke[2], tls, environment="dev"), None, 8))
        self.fails(self.ignored(index, "document: the document's user_data does not name a prod HPKE key"), self.unrecorded(tls))

    def test_a_dev_record_fails(self):
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        index = self.door.add(self.door.record(document(self.door.hpke[2], tls, environment="dev"), None, 8, environment="dev"))
        self.fails(self.ignored(index, "record: the record is a dev morse-door-boot-v1, not a prod morse-door-boot-v1"), self.unrecorded(tls))

    def test_a_revoked_image_fails(self):
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        index = self.door.add(self.door.record(document(self.door.hpke[2], tls, pcrs=REVOKED_PCRS), None, 8))
        self.fails(self.ignored(index, "document: morse-pins lists no unrevoked prod image with the document's PCRs"), self.unrecorded(tls))

    def late_record(self, made):
        self.door.pins.append({"environment": "prod", "pcr0": REVOKED_PCRS[0].hex(), "pcr1": REVOKED_PCRS[1].hex(), "pcr2": REVOKED_PCRS[2].hex(), "revoked": False, "tag": "v2"})
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        return self.door.add(self.door.record(document(self.door.hpke[2], tls, pcrs=REVOKED_PCRS, made=made), None, 8)), tls

    def test_a_record_made_before_its_image_was_revoked_passes(self):
        self.late_record(NOW - timedelta(days=3))
        self.door.revocations["v2"] = NOW - timedelta(days=2)
        self.passes()

    def test_a_record_made_after_its_image_was_revoked_fails(self):
        index, tls = self.late_record(NOW - timedelta(days=1))
        self.door.revocations["v2"] = NOW - timedelta(days=2)
        self.fails(self.ignored(index, "document: morse-pins lists no unrevoked prod image with the document's PCRs at"), self.unrecorded(tls))

    def test_the_committer_date_governs_a_revocation_authored_long_ago(self):
        self.late_record(NOW - timedelta(days=1))
        self.door.revocations["v2"] = NOW - timedelta(hours=1)
        self.door.authored["v2"] = NOW - timedelta(days=5)
        self.passes()

    def test_the_committer_date_governs_a_revocation_authored_later(self):
        index, _ = self.late_record(NOW - timedelta(days=1))
        self.door.revocations["v2"] = NOW - timedelta(days=2)
        self.door.authored["v2"] = NOW
        self.fails(self.ignored(index, "document: morse-pins lists no unrevoked prod image"))

    def test_an_approval_and_a_revocation_in_one_second_leave_the_image_revoked(self):
        index, _ = self.late_record(NOW - timedelta(days=1))
        self.door.base_time = NOW - timedelta(days=2)
        self.door.revocations["v2"] = NOW - timedelta(days=2)
        self.fails(self.ignored(index, "document: morse-pins lists no unrevoked prod image"))

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
        self.passes()

        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        index = self.door.add(self.door.record(document(bytes([14]) * 32, tls, pcrs=REVOKED_PCRS, made=NOW - timedelta(days=2)), None, 8))
        self.fails(self.ignored(index, "document: morse-pins lists no unrevoked prod image"), self.unrecorded(tls))

    def test_a_pins_history_that_no_longer_holds_the_last_run_s_commit_fails(self):
        self.door.pins.append({"environment": "prod", "pcr0": REVOKED_PCRS[0].hex(), "pcr1": REVOKED_PCRS[1].hex(), "pcr2": REVOKED_PCRS[2].hex(), "revoked": False, "tag": "v2"})
        self.door.revocations["v2"] = NOW - timedelta(days=2)
        self.passes()
        tip = self.door.state()["tips"]["morse-pins"]
        self.door.revocations["v2"] = NOW - timedelta(days=2) + timedelta(seconds=1)
        self.fails(f"morse-pins at", f"does not descend from {tip}, which an earlier run saw, so its history was rewritten")
        self.assertEqual(self.door.state()["tips"]["morse-pins"], tip)

    def test_a_pins_history_that_grew_since_the_last_run_passes(self):
        self.door.pins.append({"environment": "prod", "pcr0": REVOKED_PCRS[0].hex(), "pcr1": REVOKED_PCRS[1].hex(), "pcr2": REVOKED_PCRS[2].hex(), "revoked": False, "tag": "v2"})
        self.passes()
        self.door.revocations["v2"] = NOW - timedelta(days=2)
        self.passes()

    def test_a_morse_records_history_that_dropped_a_pointer_fails(self):
        self.passes()
        tip = self.door.state()["tips"]["morse-records"]
        records = self.door.root / "records"
        git(records, "reset", "-q", "--hard", "HEAD")
        self.door.pointers.pop()
        (records / "prod.jsonl").write_text("".join(json.dumps(p) + "\n" for p in self.door.pointers))
        git(records, "commit", "-q", "--amend", "-a", "-m", "rewritten")
        self.fails(f"morse-records at {git(records, 'rev-parse', 'HEAD').strip()} does not descend from {tip}, which an earlier run saw, so its history was rewritten")
        self.assertEqual(self.door.state()["tips"]["morse-records"], tip)

    def test_a_morse_records_history_that_grew_passes(self):
        self.passes()
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        self.door.add(self.door.record(document(self.door.hpke[2], tls), None, 9))
        self.passes("morse-records has 3 prod pointers, and 3 of their entries verify")
        self.assertEqual(self.door.state()["tips"]["morse-records"], git(self.door.root / "records", "rev-parse", "HEAD").strip())

    def test_a_dev_image_with_prod_user_data_fails(self):
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        index = self.door.add(self.door.record(document(self.door.hpke[2], tls, pcrs=DEV_PCRS), None, 8))
        self.fails(self.ignored(index, "document: morse-pins lists no unrevoked prod image with the document's PCRs"))

    def test_a_document_not_signed_under_the_nitro_root_fails(self):
        other = ec.generate_private_key(ec.SECP384R1())
        signer = (other, certificate(other, other, "test nitro signer", issuer_cn="test nitro root"))
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        index = self.door.add(self.door.record(document(self.door.hpke[2], tls, signer=signer), None, 8))
        self.fails(self.ignored(index, "document: CN=test nitro signer is not signed by CN=test nitro root"), self.unrecorded(tls))

    def test_a_record_that_does_not_parse_is_refused_and_the_other_checks_run(self):
        record = self.door.record(document(self.door.hpke[2], self.door.tls), key_id(self.door.hpke[1]), 8)
        for born in ("2026-11-04T03:39:60Z", "2026-11-04T03:39:52+24:00", "0001-01-01T00:30:00+01:00", "٢٠٢٦-11-04T03:39:52Z", "2026-11-04T03:39:52.12345678٩Z"):
            with self.subTest(born=born):
                index = self.door.add({**record, "origin": {**record["origin"], "born": born}})
                out = self.door.run()[1]
                self.assertIn(self.ignored(index, "record: origin.born"), out)
                self.assertEqual(self.section(out, "check 5"), "  OK")
        for name, junk in (("floor", {**record, "origin": {**record["origin"], "floor": "8"}}), ("from", {**record, "origin": {**record["origin"], "from": "xyz"}}),
                           ("missing from", {**record, "origin": {"born": BORN_TEXT, "floor": 8}}), ("extra", {**record, "extra": 1}),
                           ("document", {**record, "document": "!!"}), ("list", []), ("duplicate", b'{"type":"a","type":"b"}')):
            with self.subTest(junk=name):
                index = self.door.add(junk, certificate_der=record_certificate(junk))
                out = self.door.run()[1]
                self.assertIn(self.ignored(index, "record: "), out)
                self.assertEqual(self.section(out, "check 5"), "  OK")

    def test_a_record_certificate_without_the_extension_or_with_a_bad_one_is_refused(self):
        record = self.door.record(document(self.door.hpke[2], self.door.tls), key_id(self.door.hpke[1]), 8)
        for name, der in (("no extension", record_certificate(record, oid="1.3.6.1.4.1.67561.2")), ("not a certificate", b"\x30\x03\x02\x01\x01")):
            with self.subTest(case=name):
                index = self.door.add(record, certificate_der=der)
                self.assertIn(self.ignored(index, "record: "), self.door.run()[1])

    def test_an_origin_the_documents_nonce_does_not_attest_fails(self):
        doc = document(self.door.hpke[2], self.door.tls)
        record = self.door.record(doc, key_id(self.door.hpke[1]), 8)
        for change in ({"from": None}, {"floor": 9}, {"born": (BORN + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}):
            with self.subTest(change=change):
                index = self.door.add({**record, "origin": {**record["origin"], **change}})
                self.assertIn(self.ignored(index, "nonce: the document's nonce is not the origin statement of its SPKI and the record's origin"), self.door.run()[1])

    def test_a_document_with_no_nonce_fails(self):
        doc = document(self.door.hpke[2], self.door.tls)
        index = self.door.add({**self.door.record(doc, None, 8), "document": b64(doc)})
        self.assertIn(self.ignored(index, "nonce: the document's nonce is not the origin statement"), self.door.run()[1])

    def test_the_origin_nonce_is_the_backends_golden_statement(self):
        sender = hashlib.sha256(b"sender").hexdigest()[:16]
        golden = '{"origin":{"born":"2026-11-04T17:12:03.12Z","floor":7,"from":"' + sender + '"},"spki_sha256":"9f3c","type":"morse-door-origin-v1"}'
        self.assertEqual(check_door.records.origin_nonce("9f3c", "2026-11-04T09:12:03.120-08:00", sender, 7), hashlib.sha256(golden.encode()).digest())
        born = '{"origin":{"born":"2026-11-04T17:12:03.12Z","floor":7,"from":null},"spki_sha256":"9f3c","type":"morse-door-origin-v1"}'
        self.assertEqual(check_door.records.origin_nonce("9f3c", "2026-11-04T17:12:03.120000000Z", None, 7), hashlib.sha256(born.encode()).digest())
        self.assertEqual(check_door.records.canonical_time("2026-11-04T17:12:03.000000000Z"), "2026-11-04T17:12:03Z")
        self.assertEqual(check_door.records.canonical_time("2026-11-04T23:12:03.123456789-08:00"), "2026-11-05T07:12:03.123456789Z")

    def test_the_record_digest_is_the_enclaves(self):
        self.assertEqual(check_door.records.record_digest("9f3c"), hashlib.sha256(b"morse-door-boot-v1\n9f3c\n").digest())

    def test_a_real_aws_document_verifies_at_its_own_time_and_its_dev_user_data_fails_for_prod(self):
        check_door.nitro.AWS_NITRO_ROOT = self.real_root
        real = base64.b64decode(REAL_DOCUMENT.read_text())
        self.door.pins.append({"environment": "prod", "revoked": False, "tag": "real",
                               "pcr0": "1dab5ad4c661f95a9e7e3f57bcd83efd9fced7f749ac21ea85a1853131bb5e43b41eb58615efef998d478ce485fcff53",
                               "pcr1": "3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03",
                               "pcr2": "f9d2c68436810c46556535a583870e2913ec1f05ecca361b4e78eaa00d0b365dee6570e7699c4f34165fbf635bf35c6a"})
        self.door.pointers = []
        index = self.door.add(self.door.record(real, None, 1))
        self.door.ct, self.door.live = [], []
        out = self.door.run()[1]
        self.assertIn(self.ignored(index, "document: the document's user_data does not name a prod HPKE key"), out)

    def test_a_pointer_whose_entry_is_not_in_the_log_fails_its_certificate(self):
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        self.door.pointers.append({"log": ORIGIN, "index": 99, "spki_sha256": spki_hex(tls), "boot": key_id(self.door.hpke[2])})
        self.fails(f"the entry at {ORIGIN}/99 does not verify, so this run ignores it: unread: the newest checkpoint this watcher accepted holds 2 entries, so not index 99 yet", self.unrecorded(tls))

    def test_a_pointer_to_a_log_the_trusted_root_does_not_list_is_a_note(self):
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        self.door.pointers.append({"log": "other.test.example", "index": 0, "spki_sha256": spki_hex(tls), "boot": key_id(self.door.hpke[2])})
        self.fails("the entry at other.test.example/0 does not verify, so this run ignores it: unread: this watcher has no checkpoint of other.test.example", self.unrecorded(tls))

    def test_a_pointer_line_that_is_not_a_pointer_is_a_note(self):
        for line in ("{not json}\n", '{"log": "../../etc", "index": 0, "spki_sha256": "' + "0" * 64 + '", "boot": "' + "0" * 16 + '"}\n',
                     '{"log": "' + ORIGIN + '", "index": -1, "spki_sha256": "' + "0" * 64 + '", "boot": "' + "0" * 16 + '"}\n',
                     '{"log": "' + ORIGIN + '", "index": 0, "spki_sha256": "' + "0" * 64 + '", "boot": "' + "0" * 16 + '", "extra": 1}\n'):
            with self.subTest(line=line):
                self.door.pointers.append(line)
                self.passes("NOTE: prod.jsonl line 3 is not a pointer")
                self.door.pointers.pop()

    def test_a_pointer_naming_another_pair_is_a_note_and_its_entry_still_counts(self):
        self.door.pointers[1] = {**self.door.pointers[1], "boot": key_id(self.door.hpke[2])}
        self.passes(f"NOTE: the pointer {ORIGIN}/1 names boot {key_id(self.door.hpke[2])} and SPKI {spki_hex(self.door.tls)}, and its entry attests boot {key_id(self.door.hpke[1])}")

    def test_an_entry_proven_once_is_read_from_the_cache_and_not_the_tiles_again(self):
        self.passes()
        self.assertTrue((self.door.root / f"sequence.json.cache/leaves/{ORIGIN}/0.json").exists())
        self.door.log.reads.clear()
        self.passes()
        self.assertEqual(self.door.log.reads, ["checkpoint"])

    def test_a_shard_that_stopped_serving_tiles_is_read_from_the_leaf_archive(self):
        self.door.archive = {(ORIGIN, i): self.door.log.entry(i) for i in range(2)}
        self.door.log.gone = {"tile/entries/000.p/2", "tile/entries/000"}
        self.passes()

    def test_an_archived_leaf_that_does_not_verify_is_a_note(self):
        forged = Log(key=ed25519.Ed25519PrivateKey.generate())
        forged.bodies = list(self.door.log.bodies)
        self.door.archive = {(ORIGIN, 1): forged.entry(1)}
        self.door.log.gone = {"tile/entries/000.p/2", "tile/entries/000"}
        self.fails(self.ignored(1, "unread: the shard's tiles:"), "the archived leaf: unknown_log: the trusted root lists no Ed25519 log with this id")

    def test_check_2_and_the_entry_counts_need_records_from_morse_records_alone(self):
        self.door.pointers = []
        self.fails("morse-records has 0 prod pointers, and 0 of their entries verify", self.unrecorded(self.door.tls))


class CustodyTest(Fixture):
    def handed(self, sender, floor):
        self.door.pointers.pop()
        return self.door.add(self.door.record(document(self.door.hpke[1], self.door.tls), sender, floor))

    def test_a_broken_custody_link_fails(self):
        self.handed(key_id(b"\x00" * 32), 8)
        self.fails(f"boot {key_id(self.door.hpke[1])} with SPKI {spki_hex(self.door.tls)}: boot {key_id(self.door.hpke[1])} with SPKI {spki_hex(self.door.tls)} names sender {key_id(bytes(32))}, which has no verified record of that SPKI")

    def test_a_falling_floor_fails(self):
        self.handed(key_id(self.door.hpke[0]), 6)
        self.fails(f"the floor falls from 7 at boot {key_id(self.door.hpke[0])} with SPKI {spki_hex(self.door.tls)} to 6 at boot {key_id(self.door.hpke[1])}")

    def test_a_sender_of_another_spki_does_not_carry_the_chain(self):
        other = ec.generate_private_key(ec.SECP256R1())
        self.handed(key_id(self.door.hpke[2]), 8)
        self.door.add(self.door.record(document(self.door.hpke[2], other), None, 1))
        self.fails(f"names sender {key_id(self.door.hpke[2])}, which has no verified record of that SPKI")

    def test_a_retry_of_one_record_is_one_record(self):
        record = self.door.record(document(self.door.hpke[1], self.door.tls), key_id(self.door.hpke[0]), 8)
        der = record_certificate(record)
        self.door.pointers.pop()
        self.door.add(record, certificate_der=der)
        self.door.add(record, certificate_der=der)
        self.passes()

    def test_two_origins_for_one_key_of_one_boot_fail(self):
        self.door.add(self.door.record(document(self.door.hpke[1], self.door.tls), key_id(self.door.hpke[0]), 9))
        self.fails(f"boot {key_id(self.door.hpke[1])} with SPKI {spki_hex(self.door.tls)} has entries with 2 origins ({ORIGIN}/1, {ORIGIN}/2), and a boot fixes one origin per key")

    def test_custody_that_loops_fails(self):
        self.door.pointers = []
        a, b = self.door.hpke[0], self.door.hpke[1]
        self.door.add(self.door.record(document(a, self.door.tls), key_id(b), 7))
        self.door.add(self.door.record(document(b, self.door.tls), key_id(a), 7))
        self.fails("custody loops at")

    def test_one_boot_may_hold_a_born_key_and_a_handed_one(self):
        other = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        self.door.add(self.door.record(document(self.door.hpke[1], other), None, 3))
        self.passes()


class CAATest(Fixture):
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

        self.door.doh = doh
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


class LiveTest(Fixture):
    def no_record(self, hpke, tls):
        return f"the boot with HPKE key {key_id(hpke)} holds SPKI {spki_hex(tls)}, which no verified record of that boot attests"

    def gone(self, hpke, tls):
        return f"the boot with HPKE key {key_id(hpke)} has no verified record of SPKI {spki_hex(tls)}, which it held live"

    def test_a_live_boot_with_an_unrecorded_key_passes_inside_its_grace_and_fails_after(self):
        rogue = ec.generate_private_key(ec.SECP256R1())
        self.door.live.append(document(self.door.hpke[2], rogue))
        self.passes()
        first = datetime.fromisoformat(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])
        self.door.ran(first + check_door.checks.LIVE_GRACE - timedelta(minutes=5))
        code, out = self.at(first + check_door.checks.LIVE_GRACE)
        self.assertEqual(code, 1, out)
        self.assertIn(f"live document 2: {self.no_record(self.door.hpke[2], rogue)}, and this watcher first saw it live at {first.isoformat(timespec='seconds')}", out)

    def test_a_live_boot_with_no_record_behind_a_recorded_spki_fails_once_past_the_grace(self):
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.door.seen(self.door.hpke[2], self.door.tls, check_door.checks.LIVE_GRACE + timedelta(seconds=1))
        self.fails(f"live document 2: {self.no_record(self.door.hpke[2], self.door.tls)}, and this watcher first saw it live at")

    def test_a_handed_off_boot_passes_until_the_grace_ends_and_then_fails(self):
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        last_run = self.door.state()["last_run"]
        self.passes()
        first = datetime.fromisoformat(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])
        self.assertEqual(first.isoformat(), last_run)
        later = first + check_door.checks.LIVE_GRACE - timedelta(seconds=1)
        self.door.ran(later - timedelta(minutes=5))
        code, out = self.at(later)
        self.assertEqual(code, 0, out)
        code, out = self.at(first + check_door.checks.LIVE_GRACE)
        self.assertEqual(code, 1, out)
        self.assertIn(f"{self.no_record(self.door.hpke[2], self.door.tls)}, and this watcher first saw it live at {first.isoformat(timespec='seconds')}", out)

    def test_a_boot_replaced_inside_its_grace_still_fails_when_the_grace_ends(self):
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.passes()
        first = datetime.fromisoformat(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])
        self.door.live.pop()
        code, out = self.at(first + check_door.checks.LIVE_GRACE)
        self.assertEqual(code, 1, out)
        self.assertIn(f"{self.gone(self.door.hpke[2], self.door.tls)}, and this watcher first saw it live at", out)
        self.assertIn(key_id(self.door.hpke[2]), self.door.state()["boots"])

    def test_a_boot_whose_record_lands_late_passes(self):
        self.door.seen(self.door.hpke[2], self.door.tls, check_door.checks.LIVE_GRACE + timedelta(hours=5))
        self.door.add(self.door.record(document(self.door.hpke[2], self.door.tls), key_id(self.door.hpke[1]), 8))
        self.passes()

    def test_a_boot_whose_spki_changes_keeps_the_grace_it_started_with(self):
        self.door.seen(self.door.hpke[1], self.door.tls, check_door.checks.LIVE_GRACE + timedelta(seconds=1))
        rogue = ec.generate_private_key(ec.SECP256R1())
        self.door.live = [document(self.door.hpke[1], rogue)]
        self.fails(f"live document 1: {self.no_record(self.door.hpke[1], rogue)}, and this watcher first saw it live at")

    def served_on_a_second_spki_inside_its_grace(self):
        self.door.add(self.door.record(document(self.door.hpke[2], self.door.tls), key_id(self.door.hpke[1]), 8))
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.passes()
        first = datetime.fromisoformat(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])
        second = ec.generate_private_key(ec.SECP256R1())
        self.door.live[-1] = document(self.door.hpke[2], second)
        self.door.ran(first + timedelta(minutes=25))
        code, out = self.at(first + timedelta(minutes=30))
        self.assertEqual(code, 0, out)
        self.assertEqual(self.door.state()["boots"][key_id(self.door.hpke[2])], {"first_seen": first.isoformat(), "spkis": sorted([spki_hex(self.door.tls), spki_hex(second)])})
        self.door.live.pop()
        self.door.ran(first + check_door.checks.LIVE_GRACE - timedelta(minutes=4))
        return first, second

    def test_a_gone_boot_that_served_on_a_second_spki_inside_its_grace_fails_for_that_spki_once_the_grace_ends(self):
        first, second = self.served_on_a_second_spki_inside_its_grace()
        code, out = self.at(first + check_door.checks.LIVE_GRACE + timedelta(minutes=1))
        self.assertEqual(code, 1, out)
        self.assertIn(f"{self.gone(self.door.hpke[2], second)}, and this watcher first saw it live at {first.isoformat(timespec='seconds')}", self.section(out, "check 6"))
        self.assertNotIn(self.gone(self.door.hpke[2], self.door.tls), out)

    def test_a_gone_boot_whose_second_spki_has_a_record_passes(self):
        first, second = self.served_on_a_second_spki_inside_its_grace()
        self.door.add(self.door.record(document(self.door.hpke[2], second), None, 9))
        code, out = self.at(first + check_door.checks.LIVE_GRACE + timedelta(minutes=1))
        self.assertEqual(code, 0, out)

    def test_a_state_with_one_spki_per_boot_is_read_and_rewritten_with_a_list(self):
        first = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self.door.edit_state(lambda s: s["boots"].update({key_id(self.door.hpke[1]): {"first_seen": first, "spki_sha256": spki_hex(self.door.tls)},
                                                           key_id(self.door.hpke[2]): {"first_seen": first, "spki_sha256": spki_hex(self.door.tls)}}))
        self.fails(f"{self.gone(self.door.hpke[2], self.door.tls)}, and this watcher first saw it live at")
        self.assertEqual(self.door.state()["boots"], {key_id(self.door.hpke[1]): {"first_seen": first, "spkis": [spki_hex(self.door.tls)]},
                                                      key_id(self.door.hpke[2]): {"first_seen": first, "spkis": [spki_hex(self.door.tls)]}})

    def test_a_watcher_with_no_state_does_not_report_check_6_ok_and_starts_its_history(self):
        (self.door.root / "sequence.json").unlink()
        code, out = self.door.run()
        self.assertEqual(code, 2, out)
        self.assertIn("NOT ENFORCED: check 6 not enforced: needs --sequence-state", out)
        self.assertNotIn("FAIL", out)
        self.assertEqual(self.door.state()["boots"], {key_id(self.door.hpke[1]): {"first_seen": None, "spkis": [spki_hex(self.door.tls)]}})
        self.passes()

    def test_a_watcher_with_no_state_gives_a_recordless_boot_no_grace_on_any_later_run(self):
        (self.door.root / "sequence.json").unlink()
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        message = f"{self.no_record(self.door.hpke[2], self.door.tls)}, and this watcher cannot date when it first saw it live"
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
        self.fails(f"live document 2: {self.no_record(self.door.hpke[2], rogue)}, and this watcher cannot date", "NOT ENFORCED: check 6 not enforced")

    def test_an_unreadable_state_fails_and_is_kept(self):
        (self.door.root / "sequence.json").write_text("{not json")
        self.fails("FAIL: could not read the evidence")
        self.assertEqual((self.door.root / "sequence.json").read_text(), "{not json")

    def test_a_state_with_a_first_seen_time_with_no_zone_fails_and_is_kept(self):
        state = json.dumps({"boots": {key_id(self.door.hpke[1]): {"first_seen": "2026-11-04T09:12:03", "spki_sha256": spki_hex(self.door.tls)}}})
        (self.door.root / "sequence.json").write_text(state)
        self.fails("FAIL: could not read the evidence", "with no zone")
        self.assertEqual((self.door.root / "sequence.json").read_text(), state)

    def test_a_watcher_state_from_before_rekor_keeps_its_pins_tip_and_drops_its_sequence(self):
        self.passes()
        tip = self.door.state()["tips"]["morse-pins"]
        (self.door.root / "sequence.json").write_text(json.dumps({"sequence": 2, "tip": tip, "last_run": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(), "boots": {}}))
        self.passes()
        self.assertEqual(self.door.state()["tips"]["morse-pins"], tip)
        self.assertNotIn("sequence", self.door.state())
        self.assertNotIn("tip", self.door.state())

    def test_a_watcher_state_from_before_the_boot_history_does_not_enforce_check_6_once(self):
        (self.door.root / "sequence.json").write_text(json.dumps({"sequence": 2}))
        code, out = self.door.run()
        self.assertEqual(code, 2, out)
        self.assertIn("NOT ENFORCED: check 6 not enforced", out)
        self.passes()

    def test_a_boot_is_dated_to_the_run_before_the_one_that_first_saw_it_so_a_state_restored_from_before_it_cannot_restart_its_grace(self):
        start = datetime.now(timezone.utc)
        self.door.ran(start - timedelta(minutes=5))
        before = (self.door.root / "sequence.json").read_text()
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.assertEqual(self.at(start)[0], 0)
        (self.door.root / "sequence.json").write_text(before)
        self.assertEqual(self.at(start + timedelta(minutes=1))[0], 0)
        self.door.ran(start + timedelta(minutes=110))
        code, out = self.at(start - timedelta(minutes=5) + check_door.checks.LIVE_GRACE)
        self.assertEqual(code, 1, out)
        self.assertIn(f"{self.no_record(self.door.hpke[2], self.door.tls)}, and this watcher first saw it live at {(start - timedelta(minutes=5)).isoformat(timespec='seconds')}", out)

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
        self.assertIn(f"{self.no_record(self.door.hpke[2], self.door.tls)}, and this watcher first saw it live at", out)

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

    def test_a_stale_live_document_gets_no_boot(self):
        now = NOW.replace(microsecond=0)
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        self.door.live = [document(self.door.hpke[1], self.door.tls, made=now - timedelta(minutes=1)), document(self.door.hpke[2], tls, made=now - timedelta(hours=1))]
        self.door.ran(now - timedelta(minutes=5))
        code, out = self.at(now)
        self.assertEqual(code, 1, out)
        self.assertIn("live document 2: AWS Nitro signed the document at", self.section(out, "check 6"))
        self.assertIn(self.unrecorded(tls), self.section(out, "check 1"))
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
        self.assertEqual(self.live_at(now + check_door.records.MAX_AHEAD, now)[0], 0)
        code, out = self.live_at(now + check_door.records.MAX_AHEAD + timedelta(seconds=1), now)
        self.assertEqual(code, 1, out)
        self.assertIn(f"live document 1: AWS Nitro signed the document at {(now + check_door.records.MAX_AHEAD + timedelta(seconds=1)).isoformat(timespec='seconds')}, more than 2 minutes after this run's clock reads {now.isoformat(timespec='seconds')}, so this watcher's clock is behind", out)

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
        self.fails(f"{self.no_record(self.door.hpke[2], self.door.tls)}, and this watcher cannot date when it first saw it live", "NOT ENFORCED: check 6 not enforced: needs --sequence-state")

    def test_a_last_run_time_with_no_zone_fails_and_is_kept(self):
        state = json.dumps({"last_run": "2026-11-04T09:12:03", "boots": {}})
        (self.door.root / "sequence.json").write_text(state)
        self.fails("FAIL: could not read the evidence", "with no zone")
        self.assertEqual((self.door.root / "sequence.json").read_text(), state)

    def test_a_clock_behind_the_last_run_fails_and_a_boot_it_first_sees_gets_no_grace(self):
        now = datetime.now(timezone.utc)
        self.door.ran(now + timedelta(days=1))
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.fails("this run's clock reads", f"before {(now + timedelta(days=1)).isoformat(timespec='seconds')}, when the last run wrote --sequence-state",
                   f"{self.no_record(self.door.hpke[2], self.door.tls)}, and this watcher cannot date when it first saw it live")
        self.assertIsNone(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])

    def test_a_clock_behind_the_last_run_by_less_than_the_skew_passes(self):
        self.door.ran(datetime.now(timezone.utc) + check_door.records.MAX_AHEAD - timedelta(seconds=10))
        self.passes()

    def test_a_first_seen_time_ahead_of_the_clock_is_an_unknown_age(self):
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.door.seen(self.door.hpke[2], self.door.tls, -timedelta(days=1))
        self.fails(f"{self.no_record(self.door.hpke[2], self.door.tls)}, and this watcher cannot date when it first saw it live")
        self.assertIsNone(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])

    def test_a_first_seen_time_ahead_of_the_clock_by_less_than_the_skew_keeps_its_grace(self):
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.door.seen(self.door.hpke[2], self.door.tls, -check_door.records.MAX_AHEAD + timedelta(seconds=10))
        self.passes()

    def test_a_live_document_from_an_unpinned_image_fails_at_once(self):
        for pcrs in (REVOKED_PCRS, [bytes(48)] * 3):
            with self.subTest(pcrs=pcrs[0][:1].hex()):
                self.door = Door(tempfile.mkdtemp(dir=self.tmp.name))
                rogue = ec.generate_private_key(ec.SECP256R1())
                self.door.live.append(document(self.door.hpke[2], rogue, pcrs=pcrs))
                out = self.section(self.fails("live document 2 is from an image no record can admit: morse-pins lists no unrevoked prod image with the document's PCRs at"), "check 6")
                self.assertNotIn("which no verified record", out)

    def test_a_live_document_from_a_revoked_image_holding_a_recorded_key_fails_at_once(self):
        self.door.live.append(document(self.door.hpke[2], self.door.tls, pcrs=REVOKED_PCRS))
        self.fails("live document 2 is from an image no record can admit")

    def test_a_certificate_for_a_key_only_a_live_boot_holds_gets_no_grace_from_it(self):
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        self.door.live.append(document(self.door.hpke[2], tls))
        self.assertIn(self.unrecorded(tls), self.section(self.fails(), "check 1"))

    def test_a_live_document_for_another_environment_fails(self):
        self.door.live.append(document(self.door.hpke[1], self.door.tls, environment="dev"))
        self.fails("live document 2: the document's user_data does not name a prod HPKE key")


class RecordsPublicTest(Fixture):
    def test_morse_records_must_answer_public_with_no_token(self):
        for answer, message in (("internal", "answers visibility 'internal'"), ("private", "answers visibility 'private'"), (404, "answers 404")):
            with self.subTest(answer=answer):
                self.door.visibility = answer
                self.assertIn(f"{check_door.checks.RECORDS_REPO_URL}, read with no token, {message}, so an outside watcher cannot read", self.section(self.fails(), "check 9"))
        self.door.visibility = "public"
        self.passes()


if __name__ == "__main__":
    unittest.main()

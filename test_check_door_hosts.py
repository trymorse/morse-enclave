# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2==6.1.5", "cryptography==50.0.2", "tuf==7.0.1", "securesystemslib==1.6.0", "urllib3==2.8.0"]
# ///
"""Tests check-door.py watching both of the door's hostnames: each is judged on the evidence read for it, against the
fixtures in check_door_fixtures.py. It reads nothing from the network.

Usage: uv run test_check_door_hosts.py
"""

import hashlib
import json
import sys
import unittest
import urllib.error
from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.dont_write_bytecode = True
from check_door_fixtures import *  # noqa: E402,F403


class TwoHostsTest(Fixture):
    """The door serves both hostnames on one certificate (the plan for serving the API at api.morseinference.com), and
    the watcher checks each one it is given."""

    SECOND = "api.morseinference.com"

    def setUp(self):
        super().setUp()
        self.door.ct[0] = certificate(self.door.tls, self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai", self.SECOND, "0123456789abcdef.k.inference.trymorse.ai"], issuer_cn="test ca")
        self.door.caa.append({"name": self.SECOND, "caa": CAA})

    def run_both(self, *extra, **kwargs):
        verdict = self.door.root / "verdict.json"
        code, out = self.door.run("--name", "inference.trymorse.ai", "--name", self.SECOND, "--verdict", str(verdict), *extra, **kwargs)
        return code, out, json.loads(verdict.read_text())

    def test_a_door_certificate_naming_both_hosts_passes_for_both(self):
        code, out, verdict = self.run_both()
        self.assertEqual(code, 0, out)
        self.assertIn("1 certificates in CT cover inference.trymorse.ai or api.morseinference.com.", out)
        self.assertEqual(verdict["hosts"], [])

    def test_a_rogue_certificate_for_the_second_host_alone_fails_naming_it_and_only_once_it_is_watched(self):
        rogue = self.door.rogue([self.SECOND])
        code, out = self.door.run()
        self.assertEqual(code, 0, out)
        code, out, verdict = self.run_both()
        self.assertEqual(code, 1, out)
        self.assertIn(f"FAIL: {self.door.root / 'ct.json'} 2 names api.morseinference.com {self.unrecorded(rogue)}, and CT made it public at", out)
        self.assertEqual((verdict["failed"], verdict["hosts"]), ([1], [self.SECOND]))

    def test_a_rogue_wildcard_for_the_second_domain_fails_naming_the_second_host(self):
        rogue = self.door.rogue(["*.morseinference.com"])
        code, out, verdict = self.run_both()
        self.assertEqual(code, 1, out)
        self.assertIn(f"names *.morseinference.com {self.unrecorded(rogue)}", out)
        self.assertEqual(verdict["hosts"], [self.SECOND])

    def test_a_ct_source_with_no_certificate_for_the_second_host_fails_naming_it(self):
        self.door.ct[0] = certificate(self.door.tls, self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai"], issuer_cn="test ca")
        code, out, verdict = self.run_both()
        self.assertEqual(code, 1, out)
        self.assertEqual(self.section(out, "check 1"), f"  FAIL: {self.door.root / 'ct.json'} returned no certificate covering api.morseinference.com, though 1 SPKIs have verified records")
        self.assertEqual(verdict["hosts"], [self.SECOND])

    def test_a_caa_sample_of_the_second_host_naming_another_account_fails_naming_it(self):
        self.door.caa.append({"name": self.SECOND, "caa": ['0 issue "sectigo.com"']})
        code, out, verdict = self.run_both()
        self.assertEqual(code, 1, out)
        self.assertEqual(self.section(out, "check 5"), "  FAIL: api.morseinference.com at 2026-11-03T00:00:00Z: 0 issue \"sectigo.com\" is not one of Morse's ACME accounts with dns-01 only")
        self.assertEqual((verdict["failed"], verdict["hosts"]), ([5], [self.SECOND]))

    def test_a_sample_that_names_no_host_is_the_first_hosts_so_the_second_needs_its_own(self):
        self.door.caa.pop()
        code, out, verdict = self.run_both()
        self.assertEqual(code, 1, out)
        self.assertEqual(self.section(out, "check 5"), "  FAIL: the CAA history has no samples for api.morseinference.com")
        self.assertEqual(verdict["hosts"], [self.SECOND])

    def test_each_run_samples_caa_at_each_host(self):
        asked = []

        def doh(url):
            asked.append(url)
            return json.dumps({"Status": 0, "Answer": [{"type": 257, "data": e} for e in CAA]}).encode()

        self.door.doh = doh
        code, out, _ = self.run_both(sample=True)
        self.assertEqual(code, 0, out)
        self.assertEqual(asked, [check_door.DOH_URL.format("inference.trymorse.ai"), check_door.DOH_URL.format(self.SECOND)])
        written = [json.loads(line) for line in (self.door.root / "caa.jsonl").read_text().splitlines()[2:]]
        self.assertEqual([(w["name"], w["caa"]) for w in written], [("inference.trymorse.ai", CAA), (self.SECOND, CAA)])

    def certspotter_for_the_first_host_only(self):
        self.door.certspotter_answers("inference.trymorse.ai", [self.door.ct[0]])
        self.door.certspotter_answers(self.SECOND, urllib.error.URLError(OSError(101, "Network is unreachable")))
        return "URLError(OSError(101, 'Network is unreachable'))"

    def test_a_ct_source_unread_for_the_second_host_still_judges_the_first_from_it(self):
        error = self.certspotter_for_the_first_host_only()
        ct = self.door.root / "ct.json"
        rogue = self.door.rogue(["inference.trymorse.ai"])
        code, out, verdict = self.run_both("--ct", "certspotter", "--ct", str(ct))
        self.assertEqual(code, 1, out)
        self.assertIn(f"NOTE: certspotter could not be read for api.morseinference.com, so this run judges check 1 for api.morseinference.com from {ct} alone: {error}", out)
        self.assertIn(f"FAIL: {ct} 2 names inference.trymorse.ai {self.unrecorded(rogue)}, and CT made it public at", out)
        self.assertNotIn("returned no certificate covering", out)
        self.assertEqual((verdict["failed"], verdict["hosts"], verdict["ct"]), ([1], ["inference.trymorse.ai"], {"certspotter": error, str(ct): None}))
        self.assertEqual(verdict["ct_hosts"], {"certspotter": {"read": ["inference.trymorse.ai"], "unread": [self.SECOND]}, str(ct): {"read": ["inference.trymorse.ai", self.SECOND], "unread": []}})

    def test_a_host_no_ct_source_could_be_read_for_is_not_enforced_while_the_other_is_judged(self):
        error = self.certspotter_for_the_first_host_only()
        code, out, verdict = self.run_both("--ct", "certspotter")
        self.assertEqual(code, 2, out)
        self.assertEqual(self.section(out, "check 1"), f"  NOT ENFORCED: check 1 not enforced for api.morseinference.com on this run: no CT source could be read for it: certspotter: {error}")
        self.assertEqual((verdict["kind"], verdict["unenforced"], verdict["hosts"]), ("unenforced", [1], [self.SECOND]))
        rogue = certificate(ec.generate_private_key(ec.SECP256R1()), self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai"], issuer_cn="test ca")
        self.door.certspotter_answers("inference.trymorse.ai", [self.door.ct[0], rogue])
        code, out, verdict = self.run_both("--ct", "certspotter")
        self.assertEqual(code, 1, out)
        self.assertIn(f"FAIL: certspotter 1 names inference.trymorse.ai {self.unrecorded(rogue)}, and CT made it public at", out)
        self.assertEqual((verdict["failed"], verdict["hosts"]), ([1], ["inference.trymorse.ai"]))

    def test_a_revoked_wildcard_for_the_second_domain_leaves_the_second_host_out_of_a_first_host_failure(self):
        revoked = self.door.revoking.issue(["morseinference.com", "*.morseinference.com"])
        self.door.revoking.revoke(revoked)
        self.door.ct.append(revoked)
        rogue = self.door.rogue(["inference.trymorse.ai"])
        code, out, verdict = self.run_both()
        self.assertEqual(code, 1, out)
        self.assertIn(f"NOTE: revoked, skipped: {self.door.root / 'ct.json'} 2 names morseinference.com, *.morseinference.com", out)
        self.assertIn(f"FAIL: {self.door.root / 'ct.json'} 3 names inference.trymorse.ai {self.unrecorded(rogue)}", out)
        self.assertEqual(verdict["hosts"], ["inference.trymorse.ai"])
        judged = {c["source"]: (c["hosts"], c["judgment"], c["revoked"]) for c in verdict["certificates"]}
        ct = self.door.root / "ct.json"
        self.assertEqual(judged, {f"{ct} 0": (["inference.trymorse.ai", self.SECOND], "attested", None), f"{ct} 2": ([self.SECOND], "NOTE", True),
                                  f"{ct} 3": (["inference.trymorse.ai"], "FAIL", None)})
        self.assertEqual({c["source"]: c["sha256"] for c in verdict["certificates"]}[f"{ct} 2"], hashlib.sha256(revoked.public_bytes(serialization.Encoding.DER)).hexdigest())
        returned = {e["sha256"] for names in verdict["ct_inventory"].values() for entries in names.values() for e in entries if e["covers"]}
        self.assertEqual(returned, {c["sha256"] for c in verdict["certificates"]})
        self.assertEqual(verdict["unjudged"], [])

    def test_a_certificate_that_does_not_parse_for_the_second_host_leaves_it_not_enforced_while_the_first_is_judged(self):
        self.certspotter_for_the_first_host_only()
        self.door.certspotter_answers(self.SECOND, [{"id": "7", "cert_der": base64.b64encode(b"not a certificate").decode()}])
        ct = self.door.root / "ct.json"
        rogue = self.door.rogue(["inference.trymorse.ai"])
        code, out, verdict = self.run_both("--ct", "certspotter", "--ct", str(ct))
        self.assertEqual(code, 1, out)
        self.assertIn("NOT ENFORCED: check 1 not enforced for api.morseinference.com on this run: certspotter answered with an entry this watcher could not parse, so a certificate for api.morseinference.com may have gone unread: ValueError(", out)
        self.assertIn(f"FAIL: {ct} 2 names inference.trymorse.ai {self.unrecorded(rogue)}", out)
        self.assertEqual((verdict["failed"], verdict["unenforced"], verdict["hosts"]), ([1], [1], ["inference.trymorse.ai"]))

    def test_a_ct_entry_missing_its_certificate_for_the_second_host_leaves_it_not_enforced_while_the_first_is_judged(self):
        self.certspotter_for_the_first_host_only()
        self.door.certspotter_answers(self.SECOND, [{"id": "7"}])
        code, out, verdict = self.run_both("--ct", "certspotter")
        self.assertEqual(code, 2, out)
        self.assertEqual(self.section(out, "check 1"), f"  NOT ENFORCED: check 1 not enforced for {self.SECOND} on this run: certspotter answered with an entry this watcher could not parse, so a certificate for {self.SECOND} may have gone unread: KeyError('cert_der')")
        self.assertEqual((verdict["unenforced"], verdict["hosts"], verdict["ct_hosts"]), ([1], [self.SECOND], {"certspotter": {"read": ["inference.trymorse.ai"], "unread": [self.SECOND]}}))
        self.assertEqual(verdict["ct"], {"certspotter": "KeyError('cert_der')"})

    def test_a_dns_answer_that_is_not_an_object_for_the_second_host_leaves_its_check_5_not_enforced(self):
        def doh(url):
            if url == check_door.DOH_URL.format(self.SECOND):
                return b"[]"
            return json.dumps({"Status": 0, "Answer": [{"type": 257, "data": e} for e in CAA]}).encode()
        self.door.doh = doh
        code, out, verdict = self.run_both(sample=True)
        self.assertEqual(code, 2, out)
        self.assertEqual(self.section(out, "check 5"), "  NOT ENFORCED: check 5 not enforced for api.morseinference.com on this run: its CAA record could not be read: AttributeError(\"'list' object has no attribute 'get'\")")
        written = [json.loads(line) for line in (self.door.root / "caa.jsonl").read_text().splitlines()[2:]]
        self.assertEqual([w["name"] for w in written], ["inference.trymorse.ai"])

    def test_a_rogue_certificate_still_fails_when_every_name_has_a_source_that_does_not_parse(self):
        broken = self.door.root / "broken.json"
        broken.write_text(json.dumps([{"id": "0"}]))
        rogue = self.door.rogue(["inference.trymorse.ai"])
        self.certspotter_for_the_first_host_only()
        self.door.certspotter_answers("inference.trymorse.ai", [self.door.ct[-1]])
        code, out, verdict = self.run_both("--ct", "certspotter", "--ct", str(broken))
        self.assertEqual(code, 1, out)
        self.assertIn(f"FAIL: certspotter 0 names inference.trymorse.ai {self.unrecorded(rogue)}", out)
        for name in ("inference.trymorse.ai", self.SECOND):
            self.assertIn(f"NOT ENFORCED: check 1 not enforced for {name} on this run: {broken} answered with an entry this watcher could not parse", out)
        self.assertEqual((verdict["failed"], verdict["hosts"]), ([1], ["inference.trymorse.ai"]))

    def test_a_caa_value_that_is_not_text_for_the_second_host_is_not_kept_and_the_first_hosts_failure_still_fails(self):
        stray = '0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/9; validationmethods=dns-01"'

        def doh(url):
            if url == check_door.DOH_URL.format(self.SECOND):
                return json.dumps({"Status": 0, "Answer": [{"type": 257, "data": None}]}).encode()
            return json.dumps({"Status": 0, "Answer": [{"type": 257, "data": e} for e in CAA + [stray]]}).encode()
        self.door.doh = doh
        code, out, verdict = self.run_both(sample=True)
        self.assertEqual(code, 1, out)
        check5 = self.section(out, "check 5")
        self.assertIn(f"NOT ENFORCED: check 5 not enforced for {self.SECOND} on this run: its CAA record could not be read: Refused('the DoH answer for {self.SECOND} holds a CAA record that is not text: None')", check5)
        self.assertIn("is not one of Morse's ACME accounts", check5)
        written = [json.loads(line) for line in (self.door.root / "caa.jsonl").read_text().splitlines()[2:]]
        self.assertEqual([w["name"] for w in written], ["inference.trymorse.ai"])
        code, out, _ = self.run_both()
        self.assertNotIn("could not read the evidence", out)

    def test_a_certificate_left_out_by_since_is_listed_as_unjudged_with_why(self):
        expired = self.door.ct[0].not_valid_after_utc + timedelta(days=1)
        code, out, verdict = self.run_both("--since", expired.strftime("%Y-%m-%dT%H:%M:%S"))
        ct = str(self.door.root / "ct.json")
        self.assertEqual(verdict["certificates"], [])
        self.assertEqual([(u["source"], u["name"], u["entry"], u["why"]) for u in verdict["unjudged"]],
                         [(ct, "inference.trymorse.ai", f"{ct} 0", "expired before --since"), (ct, self.SECOND, f"{ct} 0", "expired before --since")])

    def caa_for_the_first_host_only(self, caa=CAA):
        def doh(url):
            if url == check_door.DOH_URL.format(self.SECOND):
                return json.dumps({"Status": 2}).encode()
            return json.dumps({"Status": 0, "Answer": [{"type": 257, "data": e} for e in caa]}).encode()
        self.door.doh = doh

    def test_a_caa_record_unread_for_the_second_host_keeps_the_first_hosts_sample_and_is_not_enforced(self):
        self.caa_for_the_first_host_only()
        code, out, verdict = self.run_both(sample=True)
        self.assertEqual(code, 2, out)
        self.assertEqual(self.section(out, "check 5"), "  NOT ENFORCED: check 5 not enforced for api.morseinference.com on this run: its CAA record could not be read: "
                         "Refused('the DoH answer for api.morseinference.com has Status 2')")
        written = [json.loads(line) for line in (self.door.root / "caa.jsonl").read_text().splitlines()[2:]]
        self.assertEqual([(w["name"], w["caa"]) for w in written], [("inference.trymorse.ai", CAA)])
        self.assertEqual((verdict["unenforced"], verdict["hosts"]), ([5], [self.SECOND]))

    def test_a_bad_caa_record_at_the_first_host_fails_naming_it_while_the_second_cannot_be_read(self):
        self.caa_for_the_first_host_only(['0 issue "sectigo.com"'])
        code, out, verdict = self.run_both(sample=True)
        self.assertEqual(code, 1, out)
        self.assertIn("FAIL: inference.trymorse.ai at ", out)
        self.assertIn("NOT ENFORCED: check 5 not enforced for api.morseinference.com", out)
        self.assertEqual((verdict["failed"], verdict["hosts"]), ([5], ["inference.trymorse.ai"]))

    def test_a_caa_record_neither_host_could_read_leaves_the_evidence_unread(self):
        self.door.doh = lambda url: json.dumps({"Status": 2}).encode()
        code, out, verdict = self.run_both(sample=True)
        self.assertEqual(code, 1, out)
        self.assertIn("FAIL: could not read the evidence: Refused('the DoH answer for inference.trymorse.ai has Status 2')", out)
        self.assertEqual(len((self.door.root / "caa.jsonl").read_text().splitlines()), 2)
        self.assertEqual(verdict["kind"], "unread")


if __name__ == "__main__":
    unittest.main()

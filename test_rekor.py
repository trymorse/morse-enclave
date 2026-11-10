# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2==6.1.5", "cryptography==50.0.2", "tuf==7.0.1", "securesystemslib==1.6.0", "urllib3==2.8.0"]
# ///
"""Tests rekor.py, the Rekor v2 reader check-door.py runs, with the checks that read Rekor and Sigstore's TUF
repository: each shard's checkpoints and tree (check 4), its witnesses (check 8), and the trusted root. The fixtures
are check_door_fixtures.py's, and it reads nothing from the network.

Usage: uv run test_rekor.py
"""

import base64
import hashlib
import json
import sys
import types
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

# check_door_fixtures.py sits beside this file. Nothing here writes bytecode, so a run leaves no __pycache__
# among the files the export copies.
sys.dont_write_bytecode = True
from check_door_fixtures import *  # noqa: E402,F403


class LogsTest(Fixture):
    def grow(self, n=1):
        for _ in range(n):
            self.door.add(self.door.record(document(hashlib.sha256(b"%d" % len(self.door.log.bodies)).digest(), self.door.tls), key_id(self.door.hpke[1]), 9), point=False)

    def test_the_accepted_checkpoint_is_kept_and_a_grown_log_passes(self):
        self.passes()
        saved = self.door.state()["checkpoints"][ORIGIN]
        self.assertEqual((saved["size"], saved["root"]), (2, b64(mth(self.door.log.leaves()))))
        for n in (1, 3, 250):
            with self.subTest(grow=n):
                self.grow(n)
                self.passes()
                self.assertEqual(self.door.state()["checkpoints"][ORIGIN]["size"], len(self.door.log.bodies))

    def test_a_smaller_tree_fails(self):
        self.grow(2)
        self.passes()
        self.door.log.note = self.door.log.checkpoint(size=3)
        self.fails(f"{ORIGIN}'s newest checkpoint holds 3 entries, fewer than the 4 an earlier run accepted")
        self.assertEqual(self.door.state()["checkpoints"][ORIGIN]["size"], 4)

    def test_a_forked_log_fails_and_its_new_entries_do_not_count(self):
        self.passes()
        fork = Log(key=self.door.log.key)
        fork.bodies = [self.door.log.bodies[1], self.door.log.bodies[0]]
        tls = self.door.needed(ec.generate_private_key(ec.SECP256R1()))
        self.door.logs = [fork]
        self.door.log = fork
        index = self.door.add(self.door.record(document(self.door.hpke[2], tls), None, 9))
        self.fails(f"{ORIGIN}'s tree of 3 is not consistent with the tree of 2 an earlier run accepted, so the log forked or rewrote its history",
                   self.ignored(index, "unread: the newest checkpoint this watcher accepted holds 2 entries, so not index 2 yet"), self.unrecorded(tls))

    def test_a_checkpoint_with_too_few_cosignatures_fails_and_the_last_accepted_one_still_serves(self):
        self.passes()
        self.door.log.witnesses = WITNESSES[:2]
        self.fails(f"{ORIGIN}'s newest checkpoint does not verify: witnesses: 2 of the 3 cosignatures needed")
        self.assertEqual(self.door.state()["checkpoints"][ORIGIN]["size"], 2)

    def test_a_first_checkpoint_with_too_few_cosignatures_proves_nothing(self):
        self.door.log.witnesses = WITNESSES[:2]
        self.fails(f"{ORIGIN}'s newest checkpoint does not verify: witnesses: 2 of the 3 cosignatures needed",
                   self.ignored(0, f"unread: this watcher has no checkpoint of {ORIGIN}"), self.unrecorded(self.door.tls))

    def test_two_cosignatures_from_one_operator_count_once(self):
        twin = Witness("w5.test.example", "Operator A")
        self.door.log.witnesses = [WITNESSES[0], twin, WITNESSES[1]]
        with unittest.mock.patch.object(check_door, "WITNESSES", [(w.vkey, w.operator) for w in WITNESSES + [twin]]):
            self.fails("witnesses: 2 of the 3 cosignatures needed")

    def test_a_checkpoint_signed_by_another_log_key_fails(self):
        self.door.log.note = self.door.log.checkpoint(signer=ed25519.Ed25519PrivateKey.generate())
        self.fails(f"{ORIGIN}'s newest checkpoint does not verify: log_signature: no signature line by {ORIGIN} verifies under its key", self.unrecorded(self.door.tls))

    def test_a_checkpoint_that_does_not_parse_fails(self):
        self.door.log.note = "not a note"
        self.fails(f"{ORIGIN}'s newest checkpoint does not verify: checkpoint: the note has no signature block")

    def test_a_shard_whose_checkpoint_cannot_be_read_fails(self):
        self.door.log.gone = {"checkpoint"}
        self.fails(f"{ORIGIN}'s checkpoint could not be read")

    def test_partial_tiles_that_are_gone_are_read_from_the_full_tile(self):
        self.grow(254)
        self.passes()
        self.grow(1)
        self.door.log.note = self.door.log.checkpoint(size=256)
        self.door.log.gone = {"tile/0/000.p/2"}
        self.passes()

    def test_a_trusted_root_that_cannot_be_read_fails_check_4(self):
        with unittest.mock.patch.object(check_door, "read_trusted_root", lambda cache: b"{"):
            code, out = self.door.run(trusted_root=False)
        self.assertEqual(code, 1, out)
        self.assertIn("FAIL: Sigstore's trusted root could not be read through TUF", self.section(out, "check 4"))

    def test_a_rekor_v1_log_in_the_trusted_root_is_left_out(self):
        ecdsa = ec.generate_private_key(ec.SECP256R1())
        self.door.extra_tlogs = [{"baseUrl": "https://rekor.test.example", "hashAlgorithm": "SHA2_256",
                                  "publicKey": {"rawBytes": b64(spki(ecdsa)), "keyDetails": "PKIX_ECDSA_P256_SHA_256", "validFor": {"start": "2020-01-01T00:00:00Z"}},
                                  "logId": {"keyId": b64(hashlib.sha256(spki(ecdsa)).digest())}}]
        self.passes()


class TUFTest(Fixture):
    def repository(self, trusted_root):
        from securesystemslib.signer import CryptoSigner
        from tuf.api.metadata import MetaFile, Metadata, Root, Snapshot, Targets, TargetFile, Timestamp

        signer = CryptoSigner.generate_ed25519()
        expires = NOW + timedelta(days=7)
        root = Root(expires=expires)
        for role in ("root", "timestamp", "snapshot", "targets"):
            root.add_key(signer.public_key, role)
        targets = Targets(expires=expires)
        target = TargetFile.from_data("trusted_root.json", trusted_root)
        targets.targets["trusted_root.json"] = target
        snapshot = Snapshot(expires=expires)
        snapshot.meta["targets.json"] = MetaFile(version=1)
        timestamp = Timestamp(expires=expires)
        timestamp.snapshot_meta = MetaFile(version=1)
        signed = {}
        for name, role in (("1.root.json", root), ("1.targets.json", targets), ("1.snapshot.json", snapshot), ("timestamp.json", timestamp)):
            metadata = Metadata(role)
            metadata.sign(signer)
            signed[name] = metadata.to_bytes()
        files = {f"{check_door.TUF_URL}/{name}": raw for name, raw in signed.items()}
        files[f"{check_door.TUF_URL}/targets/{target.hashes['sha256']}.trusted_root.json"] = trusted_root
        return files, signed["1.root.json"]

    def fetcher(self):
        from tuf.api.exceptions import DownloadHTTPError
        from tuf.ngclient import FetcherInterface

        door = self.door

        class Fetcher(FetcherInterface):
            def _fetch(self, url):
                if url not in door.tuf:
                    raise DownloadHTTPError(f"{url} not found", 404)
                return iter([door.tuf[url]])

        return Fetcher()

    def tuf_run(self, root_sha256=None):
        if self.door.tuf is None:
            self.door.tuf, self.root_json = self.repository(self.door.trusted_root())
        files, root = self.door.tuf, self.root_json
        with unittest.mock.patch.object(check_door, "TUF_ROOT", 1), unittest.mock.patch.object(check_door, "TUF_ROOT_SHA256", root_sha256 or hashlib.sha256(root).hexdigest()), \
                unittest.mock.patch.object(check_door, "TUF_FETCHER", self.fetcher()):
            return self.door.run(trusted_root=False)

    def test_the_trusted_root_is_read_through_tuf_from_the_pinned_root(self):
        code, out = self.tuf_run()
        self.assertEqual(code, 0, out)
        self.assertTrue((self.door.root / "sequence.json.cache/tuf/root.json").exists())
        code, out = self.tuf_run()
        self.assertEqual(code, 0, out)

    def test_a_tuf_root_that_is_not_the_pinned_one_fails_check_4(self):
        code, out = self.tuf_run(root_sha256="0" * 64)
        self.assertEqual(code, 1, out)
        self.assertIn("Sigstore's 1.root.json is not the root the door's image embeds", self.section(out, "check 4"))
        self.assertIn(self.unrecorded(self.door.tls), out)

    def test_the_pinned_root_is_the_door_s(self):
        self.assertEqual(check_door.TUF_ROOT, 16)
        if SOURCE != HERE:
            root = (SOURCE / "internal/sigstore/tuf/sigstore-root-16.json").read_bytes()
            self.assertEqual(hashlib.sha256(root).hexdigest(), check_door.TUF_ROOT_SHA256)


class WitnessesTest(Fixture):
    def test_trust_go_listing_a_witness_the_watcher_does_not_fails(self):
        extra = Witness("w5.test.example", "Operator E")
        self.door.tags["v1"] = trust_go(WITNESSES + [extra], 3)
        self.fails(f"trust.go in v1 lists the witness key {'+'.join(extra.vkey.split('+')[:2])}, which this watcher's policy does not")

    def test_trust_go_with_a_smaller_k_fails(self):
        self.door.tags["v1"] = trust_go(WITNESSES, 2)
        self.fails("trust.go in v1 needs 2 cosignatures, fewer than this watcher's 3")

    def test_trust_go_naming_another_operator_fails(self):
        renamed = Witness(WITNESSES[0].name, "Someone Else")
        renamed.key = WITNESSES[0].key
        self.door.tags["v1"] = trust_go([renamed] + WITNESSES[1:], 3)
        self.fails(f"trust.go in v1 lists {WITNESSES[0].name} under Someone Else, and this watcher under Operator A")

    def test_trust_go_with_fewer_witnesses_or_a_larger_k_passes(self):
        self.door.tags["v1"] = trust_go(WITNESSES[:3], 3)
        self.passes()
        self.door.tags["v1"] = trust_go(WITNESSES, 4)
        self.passes()

    def test_the_newest_pinned_tag_is_read_and_a_revoked_or_untagged_image_is_skipped(self):
        self.door.tags = {"v1": trust_go(WITNESSES, 3), "v0": trust_go(WITNESSES, 1)}
        self.door.pins.append({**self.door.pins[0], "tag": "v9"})
        self.passes()
        self.door.tags = {"v0": trust_go(WITNESSES, 3), "v1": trust_go(WITNESSES, 1)}
        self.fails("trust.go in v1 needs 1 cosignatures")

    def test_no_pinned_image_with_a_tag_fails(self):
        self.door.tags = {"other": trust_go(WITNESSES, 3)}
        self.fails("the newest pinned image's trust.go could not be read: no unrevoked prod image in morse-pins names a tag in the morse-enclave checkout")

    def test_a_trust_go_this_watcher_cannot_read_fails(self):
        self.door.tags["v1"] = trust_go(WITNESSES, 3).replace('", "Operator B"},', '", "Operator B"}, // moved')
        self.fails("trust.go's witnesses list has a line this watcher cannot read")

    def test_a_witness_missing_for_24_hours_fails(self):
        self.door.log.witnesses = WITNESSES[:3]
        self.passes()
        self.door.edit_state(lambda s: s["checkpoints"][ORIGIN]["cosigners"].update({WITNESSES[3].name: (NOW - timedelta(hours=23)).isoformat()}))
        self.passes()
        self.door.edit_state(lambda s: s["checkpoints"][ORIGIN]["cosigners"].update({WITNESSES[3].name: (NOW - timedelta(hours=24, minutes=1)).isoformat()}))
        self.fails(f"{WITNESSES[3].name} has not cosigned a checkpoint of {ORIGIN} that this watcher read since")

    def test_a_retired_shard_the_state_tracks_does_not_lapse_and_a_live_one_does(self):
        self.passes()
        self.door.edit_state(lambda s: s["checkpoints"][ORIGIN].update({"cosigners": {w.name: (NOW - timedelta(hours=30)).isoformat() for w in WITNESSES}}))
        self.door.log.valid = {"start": "2020-01-01T00:00:00Z", "end": (NOW - timedelta(hours=26)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        code, out = self.door.run()
        self.assertNotIn("has not cosigned", out)
        self.assertEqual(self.section(out, "check 8"), "  OK")
        self.door.log.valid = {"start": "2020-01-01T00:00:00Z"}
        self.door.log.witnesses = WITNESSES[:3]
        self.fails(f"{WITNESSES[3].name} has not cosigned a checkpoint of {ORIGIN} that this watcher read since")

    def retire(self):
        self.door.log.cosigned = NOW - timedelta(hours=30)
        self.passes()
        self.door.log.valid = {"start": "2020-01-01T00:00:00Z", "end": (NOW - timedelta(hours=26)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        return self.door.state()["checkpoints"][ORIGIN]

    def test_a_retired_shard_the_state_tracks_that_is_no_longer_served_passes_check_4(self):
        kept = self.retire()
        self.door.log.gone.add("checkpoint")
        out = self.passes(f"NOTE: {ORIGIN} is retired, so this run keeps the checkpoint an earlier run accepted: {ORIGIN}'s checkpoint could not be read")
        self.assertEqual(self.section(out, "check 4"), "  OK")
        self.assertEqual(self.door.state()["checkpoints"][ORIGIN], kept)

    def test_a_retired_shard_whose_newest_checkpoint_has_too_few_cosignatures_passes_check_4(self):
        self.retire()
        self.door.log.witnesses = WITNESSES[:2]
        out = self.passes(f"NOTE: {ORIGIN} is retired, so this run keeps the checkpoint an earlier run accepted: {ORIGIN}'s newest checkpoint does not verify: witnesses: 2 of the 3 cosignatures needed")
        self.assertEqual(self.section(out, "check 4"), "  OK")

    def test_a_retired_shard_whose_newest_checkpoint_holds_fewer_entries_fails(self):
        self.retire()
        self.door.log.note = self.door.log.checkpoint(size=1)
        self.fails(f"FAIL: {ORIGIN}'s newest checkpoint holds 1 entries, fewer than the 2 an earlier run accepted")

    def test_a_live_shard_that_is_not_served_fails_check_4(self):
        self.passes()
        self.door.log.gone.add("checkpoint")
        self.fails(f"FAIL: {ORIGIN}'s checkpoint could not be read")

    def test_a_witness_never_seen_fails_24_hours_after_tracking_starts(self):
        self.door.log.witnesses = WITNESSES[:3]
        self.passes()
        self.door.edit_state(lambda s: s["checkpoints"][ORIGIN].update({"tracked_since": (NOW - timedelta(hours=25)).isoformat()}) or s["checkpoints"][ORIGIN]["cosigners"].pop(WITNESSES[3].name))
        self.fails(f"{WITNESSES[3].name} has not cosigned a checkpoint of {ORIGIN}")

    def test_a_cosigner_neither_list_names_fails(self):
        stranger = Witness("stranger.test.example", "Stranger")
        self.door.log.witnesses = WITNESSES + [stranger]
        self.fails(f"{ORIGIN}'s newest checkpoint carries a cosignature by stranger.test.example, which neither this watcher's policy nor the image's trust.go names")

    def test_each_run_records_its_cosigner_count(self):
        self.passes()
        self.door.log.witnesses = WITNESSES[:3]
        self.passes()
        counts = self.door.state()["checkpoints"][ORIGIN]["counts"]
        self.assertEqual(sum(day.get("4", 0) for day in counts.values()), 1)
        self.assertEqual(sum(day.get("3", 0) for day in counts.values()), 1)

    def test_the_watcher_policy_parses_and_is_the_images_today(self):
        policy = rekor.make_policy(3, check_door.WITNESSES)
        self.assertEqual(policy.k, 3)
        with unittest.mock.patch.object(check_door, "WITNESSES", self.real_witnesses()):
            rekor.make_policy(check_door.WITNESS_K, check_door.WITNESSES)

    def test_the_watchers_trust_is_the_doors(self):
        if WATCHER_TRUST is None:
            self.skipTest("the export holds no internal/door/testdata")
        door, module = json.loads(WATCHER_TRUST.read_text()), self.real_module()
        self.assertEqual(module.WITNESS_K, door["witness_k"])
        self.assertEqual([list(w) for w in module.WITNESSES], door["witnesses"])
        self.assertEqual(module.RECORD_OID, door["record_oid"])
        self.assertEqual(module.RECORD_TYPE, door["record_type"])
        self.assertEqual(module.MAX_KEY_AGE, timedelta(days=door["max_key_age_days"]))
        self.assertEqual(module.TUF_ROOT, door["tuf_root_version"])
        self.assertEqual(module.TUF_ROOT_SHA256, door["tuf_root_sha256"])

    def real_witnesses(self):
        return self.real_module().WITNESSES

    def real_module(self):
        module = types.ModuleType("fresh")
        module.__file__ = check_door.__file__
        exec(compile((HERE / "check-door.py").read_text(), "check-door.py", "exec"), module.__dict__)
        return module


class RekorTest(unittest.TestCase):
    """The Rekor v2 reader on its own: each refusal an entry can draw, and the proofs built from tiles."""

    def setUp(self):
        self.real_root = check_door.nitro.AWS_NITRO_ROOT
        check_door.nitro.AWS_NITRO_ROOT = ROOT
        self.log = Log()
        self.tls = ec.generate_private_key(ec.SECP256R1())
        self.hpke = bytes([11]) * 32
        self.pins = [{"environment": "prod", "pcr0": PROD_PCRS[0].hex(), "pcr1": PROD_PCRS[1].hex(), "pcr2": PROD_PCRS[2].hex(), "revoked": False, "tag": "v1"}]
        self.record = Door.record(None, document(self.hpke, self.tls), None, 7)
        self.index = self.log.add(hashed_rekord(check_door.record_digest(spki_hex(self.tls)), record_certificate(self.record)))
        self.log.add(b"another")
        self.policy = rekor.make_policy(3, [(w.vkey, w.operator) for w in WITNESSES])

    def tearDown(self):
        check_door.nitro.AWS_NITRO_ROOT = self.real_root

    def shards(self, *logs, tlogs=()):
        return rekor.read_shards(json.dumps({"tlogs": [l.tlog() for l in logs or (self.log,)] + list(tlogs)}))[0]

    def verify(self, raw, shards=None):
        return check_door.verify_entry(raw, shards or self.shards(), self.policy, "prod", [(datetime(2000, 1, 1, tzinfo=timezone.utc), self.pins)])

    def refused(self, raw, reason, detail="", shards=None):
        with self.assertRaises(check_door.Refusal) as caught:
            self.verify(raw, shards)
        self.assertEqual(caught.exception.reason, reason, caught.exception)
        self.assertIn(detail, caught.exception.detail)

    def test_a_genuine_entry_verifies(self):
        v = self.verify(self.log.entry(self.index))
        self.assertEqual((v.log, v.index, v.boot, v.spki_sha256, v.born, v.sender, v.floor), (ORIGIN, 0, key_id(self.hpke), spki_hex(self.tls), BORN_TEXT, None, 7))

    def test_an_entry_under_another_log_key_is_an_unknown_log(self):
        other = Log(key=ed25519.Ed25519PrivateKey.generate())
        other.bodies = list(self.log.bodies)
        self.refused(other.entry(0), "unknown_log")

    def test_a_checkpoint_signed_by_another_key_is_refused(self):
        self.refused(self.log.entry(0, note=self.log.checkpoint(signer=ed25519.Ed25519PrivateKey.generate())), "log_signature")

    def test_a_rekor_v1_entry_or_another_kind_is_not_v2(self):
        self.refused(self.log.entry(0, kind=("hashedrekord", "0.0.1")), "not_v2", "the entry is hashedrekord 0.0.1")
        self.refused(self.log.entry(0, kind=("dsse", "0.0.2")), "not_v2")
        v1 = json.dumps({"uuid": {"body": b64(self.log.bodies[0]), "integratedTime": 1, "logID": "00", "logIndex": 1, "verification": {}}}).encode()
        self.refused(v1, "not_v2", "unknown field")

    def test_an_entry_on_a_rekor_v1_log_is_an_unknown_log(self):
        ecdsa = ec.generate_private_key(ec.SECP256R1())
        tlog = {"baseUrl": "https://rekor.test.example", "hashAlgorithm": "SHA2_256",
                "publicKey": {"rawBytes": b64(spki(ecdsa)), "keyDetails": "PKIX_ECDSA_P256_SHA_256", "validFor": {"start": "2020-01-01T00:00:00Z"}},
                "logId": {"keyId": b64(hashlib.sha256(spki(ecdsa)).digest())}}
        entry = json.loads(self.log.entry(0))
        entry["logId"]["keyId"] = tlog["logId"]["keyId"]
        self.refused(json.dumps(entry).encode(), "unknown_log", shards=self.shards(self.log, tlogs=[tlog]))

    def test_an_entry_with_an_unknown_or_repeated_field_is_not_v2(self):
        self.refused(self.log.entry(0, extra=1), "not_v2", "unknown field 'extra'")
        self.refused(self.log.entry(0).replace(b'"logIndex": "0", ', b'"logIndex": "0", "logIndex": "1", ', 1), "not_v2", "repeats a key")
        self.refused(self.log.entry(0).replace(b'"logIndex"', b'"LogIndex"', 1), "not_v2", "unknown field 'LogIndex'")

    def test_too_few_cosignatures_are_refused(self):
        self.refused(self.log.entry(0, note=self.log.checkpoint(witnesses=WITNESSES[:2])), "witnesses", "2 of the 3 cosignatures needed")
        self.verify(self.log.entry(0, note=self.log.checkpoint(witnesses=WITNESSES[:3])))

    def test_a_cosignature_by_a_witness_the_policy_does_not_list_does_not_count(self):
        self.refused(self.log.entry(0, note=self.log.checkpoint(witnesses=WITNESSES[:2] + [Witness("w9.test.example", "Operator Z")])), "witnesses")

    def test_a_cosignature_over_another_time_does_not_count(self):
        note = self.log.checkpoint(witnesses=WITNESSES[:3])
        lines = note.split("\n")
        name, raw = lines[-2].removeprefix("— ").split(" ")
        raw = base64.b64decode(raw)
        lines[-2] = f"— {name} {b64(raw[:4] + (int.from_bytes(raw[4:12], 'big') + 1).to_bytes(8, 'big') + raw[12:])}"
        self.refused(self.log.entry(0, note="\n".join(lines)), "witnesses")

    def test_a_shard_is_valid_at_the_kth_cosignature_and_not_after_its_end(self):
        self.log.valid = {"start": "2020-01-01T00:00:00Z", "end": (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        self.refused(self.log.entry(0), "log_not_valid_now")
        self.verify(self.log.entry(0, note=self.log.checkpoint(when=NOW - timedelta(hours=2))))
        self.log.valid = {"start": (NOW - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        early = self.log.checkpoint(witnesses=[])
        text, lines = early.split("\n\n")
        cosigned = "".join(w.cosign(text.encode() + b"\n", NOW - timedelta(hours=1 if n < 2 else 0)) for n, w in enumerate(WITNESSES[:3]))
        self.verify(self.log.entry(0, note=f"{text}\n\n{lines}{cosigned}"))

    def test_a_proof_that_does_not_reach_its_root_is_refused(self):
        self.refused(self.log.entry(0, hashes=[bytes(32)]), "inclusion", "the proof does not reach its root hash")
        self.refused(self.log.entry(0, hashes=[]), "inclusion", "the inclusion proof has 0 hashes, not 1")
        self.refused(self.log.entry(0, hashes=[bytes(31)]), "inclusion", "a proof hash is not 32 bytes")
        entry = json.loads(self.log.entry(0))
        entry["inclusionProof"]["logIndex"] = "1"
        self.refused(json.dumps(entry).encode(), "inclusion", "the proof is for another index")

    def test_a_checkpoint_for_another_tree_is_refused(self):
        self.log.add(b"third")
        self.refused(self.log.entry(0, size=2, note=self.log.checkpoint(size=3)), "checkpoint", "the checkpoint's size 3 is not the proof's 2")
        self.refused(self.log.entry(0, note=self.log.checkpoint(origin="other.test.example")), "checkpoint", "the checkpoint's origin")

    def test_a_body_that_is_not_a_strict_hashedrekord_is_refused(self):
        for body in (hashed_rekord(bytes(32), b"\x01", version="0.0.1"), hashed_rekord(bytes(32), b"\x01", extra=1), b"{}", b"[]",
                     hashed_rekord(bytes(32), b"\x01").replace(b"PKIX_ECDSA_P256_SHA_256", b"PKIX_ED25519")):
            with self.subTest(body=body[:40]):
                log = Log(key=self.log.key)
                log.add(body)
                self.refused(log.entry(0), "not_this_record", "the body is not a strict hashedrekord v0.0.2")

    def test_the_record_checks_run_in_order(self):
        cases = [
            ("record", hashed_rekord(check_door.record_digest(spki_hex(self.tls)), b"\x30\x00")),
            ("record", hashed_rekord(check_door.record_digest(spki_hex(self.tls)), record_certificate({**self.record, "type": "other"}))),
            ("document", hashed_rekord(check_door.record_digest(spki_hex(self.tls)), record_certificate({**self.record, "document": b64(b"\xa0")}))),
            ("spki", hashed_rekord(check_door.record_digest(spki_hex(self.tls)), record_certificate({**self.record, "spki_sha256": "0" * 64}))),
            ("digest", hashed_rekord(bytes(32), record_certificate(self.record))),
            ("nonce", hashed_rekord(check_door.record_digest(spki_hex(self.tls)), record_certificate({**self.record, "origin": {**self.record["origin"], "floor": 8}}))),
        ]
        for reason, body in cases:
            with self.subTest(reason=reason):
                log = Log(key=self.log.key)
                log.add(body)
                self.refused(log.entry(0), reason)

    def test_tiles_give_rfc_9162_proofs(self):
        log = Log()
        for n in range(300):
            log.add(b"leaf %d" % n)
        shard = list(self.shards(log).values())[0]
        with unittest.mock.patch.object(check_door, "fetch", lambda url: log.serve(url.removeprefix(f"https://{ORIGIN}/api/v2/"), url)):
            for size in list(range(1, 20)) + [255, 256, 257, 300]:
                tiles = rekor.Tiles(shard, size, check_door.fetch)
                leaves = log.leaves(size)
                for index in sorted({0, size // 2, size - 1}):
                    self.assertEqual(tiles.inclusion(index), audit_path(index, leaves))
                    self.assertEqual(rekor.root_from_inclusion(index, size, leaves[index], tiles.inclusion(index)), mth(leaves))
                    self.assertEqual(tiles.entry(index), log.bodies[index])
                for older in sorted({0, 1, size // 3, size - 1, size}):
                    proof = tiles.consistency(older)
                    root = mth(log.leaves(older)) if older else b""
                    self.assertTrue(rekor.consistent(older, size, root, mth(leaves), proof), (older, size))
                    if proof:
                        self.assertFalse(rekor.consistent(older, size, root, mth(leaves), [bytes(32)] + proof[1:]), (older, size))
                        self.assertFalse(rekor.consistent(older, size, root, bytes(32), proof), (older, size))

    def test_tile_paths_are_c2sp(self):
        self.assertEqual([rekor.tile_index(n) for n in (0, 5, 999, 1000, 1234067)], ["000", "005", "999", "x001/000", "x001/x234/067"])

    def test_the_go_twin_verifies_the_same_entries_the_same_way(self):
        if TWIN is None:
            self.skipTest("the morse-enclave export does not carry internal/door/watch")
        twin = json.loads(TWIN.read_text())
        check_door.nitro.AWS_NITRO_ROOT = x509.load_der_x509_certificate(base64.b64decode(twin["nitro_root"]))
        shards, _ = rekor.read_shards(json.dumps(twin["trusted_root"]))
        policy = rekor.make_policy(twin["k"], twin["witnesses"])
        history = [(datetime(2000, 1, 1, tzinfo=timezone.utc), twin["pins"])]
        self.assertGreater(len(twin["cases"]), 10)
        for case in twin["cases"]:
            with self.subTest(case=case["name"]):
                try:
                    v = check_door.verify_entry(base64.b64decode(case["entry"]), shards, policy, twin["environment"], history)
                    got = {"boot": v.boot, "spki_sha256": v.spki_sha256, "log": v.log, "index": v.index, "born": v.born, "from": v.sender, "floor": v.floor}
                except check_door.Refusal as e:
                    got = {"reason": e.reason}
                self.assertEqual(got, case["want"])


if __name__ == "__main__":
    unittest.main()

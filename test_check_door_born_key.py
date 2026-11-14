# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2==6.1.5", "cryptography==50.0.2", "tuf==7.0.1", "securesystemslib==1.6.0", "urllib3==2.8.0"]
# ///
"""Tests check-door.py's check 6 for a boot that held more than one SPKI: a born key it held before it took a handed
one, a second key after its handed one, and state from before the watcher dated each SPKI, against the fixtures in
check_door_fixtures.py. It reads nothing from the network.

Usage: uv run test_check_door_born_key.py
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import ec

sys.dont_write_bytecode = True
from check_door_fixtures import *  # noqa: E402,F403


class BornKeyTest(Fixture):
    def gone(self, hpke, tls):
        return f"the boot with HPKE key {key_id(hpke)} has no verified record of SPKI {spki_hex(tls)}, which it held live"

    def served_on_a_second_spki_inside_its_grace(self):
        self.door.add(self.door.record(document(self.door.hpke[2], self.door.tls), key_id(self.door.hpke[1]), 8))
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        self.passes()
        first = datetime.fromisoformat(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])
        handed = self.door.state()["last_run"]
        second = ec.generate_private_key(ec.SECP256R1())
        self.door.live[-1] = document(self.door.hpke[2], second)
        self.door.ran(first + timedelta(minutes=25))
        code, out = self.at(first + timedelta(minutes=30))
        self.assertEqual(code, 0, out)
        self.assertEqual(self.door.state()["boots"][key_id(self.door.hpke[2])], {"first_seen": first.isoformat(), "spkis": {spki_hex(self.door.tls): handed, spki_hex(second): (first + timedelta(minutes=30)).isoformat()}})
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

    def test_a_state_with_one_spki_per_boot_is_read_and_rewritten_with_undated_spkis(self):
        first = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self.door.edit_state(lambda s: s["boots"].update({key_id(self.door.hpke[1]): {"first_seen": first, "spki_sha256": spki_hex(self.door.tls)},
                                                           key_id(self.door.hpke[2]): {"first_seen": first, "spki_sha256": spki_hex(self.door.tls)}}))
        self.fails(f"{self.gone(self.door.hpke[2], self.door.tls)}, and this watcher first saw it live at")
        self.assertEqual(self.door.state()["boots"], {key_id(self.door.hpke[1]): {"first_seen": first, "spkis": {spki_hex(self.door.tls): None}},
                                                      key_id(self.door.hpke[2]): {"first_seen": first, "spkis": {spki_hex(self.door.tls): None}}})

    def test_a_boot_that_took_a_handed_key_passes_for_the_born_key_it_held_before(self):
        born = ec.generate_private_key(ec.SECP256R1())
        self.door.live.append(document(self.door.hpke[2], born))
        self.passes()
        first = datetime.fromisoformat(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])
        self.door.add(self.door.record(document(self.door.hpke[2], self.door.tls), key_id(self.door.hpke[1]), 8))
        self.door.live[-1] = document(self.door.hpke[2], self.door.tls)
        self.door.ran(first + timedelta(minutes=5))
        code, out = self.at(first + timedelta(minutes=10))
        self.assertEqual(code, 0, out)
        self.door.live.pop()
        self.door.ran(first + check_door.checks.LIVE_GRACE - timedelta(minutes=4))
        code, out = self.at(first + check_door.checks.LIVE_GRACE + timedelta(minutes=1))
        self.assertEqual(code, 0, out)
        self.assertIn(f"NOTE: the boot with HPKE key {key_id(self.door.hpke[2])} has no verified record of SPKI {spki_hex(born)}, which it held live before it took SPKI {spki_hex(self.door.tls)} from boot {key_id(self.door.hpke[1])}", self.section(out, "check 6"))

    def test_a_boot_that_took_a_handed_key_still_fails_check_1_for_a_certificate_of_its_born_key(self):
        born = ec.generate_private_key(ec.SECP256R1())
        self.door.live.append(document(self.door.hpke[2], born))
        self.passes()
        first = datetime.fromisoformat(self.door.state()["boots"][key_id(self.door.hpke[2])]["first_seen"])
        self.door.add(self.door.record(document(self.door.hpke[2], self.door.tls), key_id(self.door.hpke[1]), 8))
        self.door.live[-1] = document(self.door.hpke[2], self.door.tls)
        self.door.ran(first + timedelta(minutes=5))
        self.assertEqual(self.at(first + timedelta(minutes=10))[0], 0)
        self.door.live.pop()
        self.door.needed(born)
        self.door.ran(first + check_door.checks.LIVE_GRACE - timedelta(minutes=4))
        code, out = self.at(first + check_door.checks.LIVE_GRACE + timedelta(minutes=1))
        self.assertEqual(code, 1, out)
        self.assertIn(self.unrecorded(born), self.section(out, "check 1"))
        self.assertNotIn("FAIL", self.section(out, "check 6"))

    def test_a_watcher_with_no_state_still_fails_an_unrecorded_spki_a_boot_showed_after_its_handed_key(self):
        (self.door.root / "sequence.json").unlink()
        self.door.add(self.door.record(document(self.door.hpke[2], self.door.tls), key_id(self.door.hpke[1]), 8))
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        start = datetime.now(timezone.utc)
        self.assertEqual(self.at(start)[0], 2)
        later = ec.generate_private_key(ec.SECP256R1())
        self.door.live[-1] = document(self.door.hpke[2], later)
        code, out = self.at(start + timedelta(minutes=5))
        self.assertEqual(code, 1, out)
        self.door.live.pop()
        code, out = self.at(start + timedelta(minutes=10))
        self.assertEqual(code, 1, out)
        self.assertIn(self.gone(self.door.hpke[2], later), self.section(out, "check 6"))
        self.assertNotIn("NOTE", self.section(out, "check 6"))

    def test_a_boot_from_state_with_undated_spkis_passes_for_one_unrecorded_spki_beside_a_handed_one(self):
        born = ec.generate_private_key(ec.SECP256R1())
        first = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self.door.add(self.door.record(document(self.door.hpke[2], self.door.tls), key_id(self.door.hpke[1]), 8))
        self.door.edit_state(lambda s: s["boots"].update({key_id(self.door.hpke[2]): {"first_seen": first, "spkis": [spki_hex(born), spki_hex(self.door.tls)]}}))
        out = self.passes(f"NOTE: the boot with HPKE key {key_id(self.door.hpke[2])} has no verified record of SPKI {spki_hex(born)}, which it held live beside SPKI {spki_hex(self.door.tls)} it took from boot {key_id(self.door.hpke[1])}, though this watcher's older state did not record when it saw each key")
        self.assertNotIn("FAIL", out)
        self.assertEqual(self.door.state()["boots"][key_id(self.door.hpke[2])]["spkis"], {spki_hex(born): None, spki_hex(self.door.tls): None})

    def test_a_boot_from_state_with_undated_spkis_fails_for_two_unrecorded_spkis_beside_a_handed_one(self):
        born, other = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
        first = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self.door.add(self.door.record(document(self.door.hpke[2], self.door.tls), key_id(self.door.hpke[1]), 8))
        self.door.edit_state(lambda s: s["boots"].update({key_id(self.door.hpke[2]): {"first_seen": first, "spkis": [spki_hex(born), spki_hex(other), spki_hex(self.door.tls)]}}))
        self.fails(self.gone(self.door.hpke[2], born), self.gone(self.door.hpke[2], other))


if __name__ == "__main__":
    unittest.main()

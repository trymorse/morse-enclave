# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2==6.1.5", "cryptography==50.0.2", "tuf==7.0.1", "securesystemslib==1.6.0", "urllib3==2.8.0"]
# ///
"""Tests check-door.py's --ack-boot, which keeps check 6 a note for one named boot that held an SPKI live and has no
verified record, against the fixtures in check_door_fixtures.py. It reads nothing from the network.

Usage: uv run test_check_door_ack_boot.py
"""

import sys
import unittest
from datetime import timedelta

sys.dont_write_bytecode = True
from check_door_fixtures import *  # noqa: E402,F403


class AckBootTest(Fixture):
    def gone(self, hpke, tls):
        return f"the boot with HPKE key {key_id(hpke)} has no verified record of SPKI {spki_hex(tls)}, which it held live"

    def no_record(self, hpke, tls):
        return f"the boot with HPKE key {key_id(hpke)} holds SPKI {spki_hex(tls)}, which no verified record of that boot attests"

    NOTE_URL = "https://example.org/unrecorded-boots#2026-11-14"

    def gone_boot(self, hpke, tls):
        self.door.seen(hpke, tls, check_door.checks.LIVE_GRACE + timedelta(seconds=1))
        return f"{key_id(hpke)}={self.NOTE_URL}"

    def test_an_acknowledged_boot_is_a_note_naming_it_and_its_public_note_on_every_run(self):
        ack = self.gone_boot(self.door.hpke[2], self.door.tls)
        for _ in range(2):
            code, out = self.door.run("--ack-boot", ack)
            self.assertEqual(code, 0, out)
            self.assertIn(f"NOTE: acknowledged: {self.gone(self.door.hpke[2], self.door.tls)}, and this watcher first saw it live at", self.section(out, "check 6"))
            self.assertIn(f"--ack-boot {key_id(self.door.hpke[2])} names it, with the public note {self.NOTE_URL} on why no record of it can exist", out)
        self.assertIn(key_id(self.door.hpke[2]), self.door.state()["boots"])

    def test_an_acknowledgement_clears_only_the_boot_it_names(self):
        ack = self.gone_boot(self.door.hpke[2], self.door.tls)
        other = bytes([14]) * 32
        self.door.seen(other, self.door.tls, check_door.checks.LIVE_GRACE + timedelta(seconds=1))
        code, out = self.door.run("--ack-boot", ack)
        self.assertEqual(code, 1, out)
        self.assertIn(f"FAIL: {self.gone(other, self.door.tls)}, and this watcher first saw it live at", out)
        self.assertIn(f"NOTE: acknowledged: {self.gone(self.door.hpke[2], self.door.tls)}", out)

    def test_an_acknowledgement_does_not_clear_its_boot_while_it_is_live(self):
        self.door.live.append(document(self.door.hpke[2], self.door.tls))
        ack = self.gone_boot(self.door.hpke[2], self.door.tls)
        code, out = self.door.run("--ack-boot", ack)
        self.assertEqual(code, 1, out)
        self.assertIn(f"live document 2: {self.no_record(self.door.hpke[2], self.door.tls)}", out)
        self.assertIn(f"FAIL: --ack-boot {key_id(self.door.hpke[2])} names a boot that does not hold, past its grace and no longer live, an SPKI with no verified record", out)

    def test_an_acknowledgement_of_a_boot_this_watcher_does_not_keep_is_a_note(self):
        code, out = self.door.run("--ack-boot", f"{'ab' * 8}={self.NOTE_URL}")
        self.assertEqual(code, 0, out)
        self.assertIn(f"NOTE: --ack-boot {'ab' * 8} names no boot this watcher keeps, so its public note {self.NOTE_URL} has nothing here to acknowledge", self.section(out, "check 6"))

    def test_a_malformed_acknowledgement_fails_and_clears_nothing(self):
        ack = self.gone_boot(self.door.hpke[2], self.door.tls)
        for bad in (key_id(self.door.hpke[2]), ack.upper(), f"{key_id(self.door.hpke[2])}=http://example.com/note", f"{key_id(self.door.hpke[2])[:15]}={self.NOTE_URL}"):
            code, out = self.door.run("--ack-boot", bad)
            self.assertEqual(code, 1, out)
            self.assertIn(f"FAIL: --ack-boot {bad!r} is not <HPKE key id, 16 hex digits>=<https URL of the public note>", out)
            self.assertIn(f"FAIL: {self.gone(self.door.hpke[2], self.door.tls)}", out)


if __name__ == "__main__":
    unittest.main()

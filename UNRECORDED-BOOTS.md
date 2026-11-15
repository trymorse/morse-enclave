# Boots with no record

Check 6 of [DOOR.md](DOOR.md) fails for a boot that `/v1/attestation` listed and that has no verified record 2 hours after the watcher first saw it, whether the boot is still listed or died waiting for its record. This file lists each such boot whose record can never exist, and what happened to it. Morse's door watcher passes `--ack-boot <HPKE key id>=<link to its entry>` for each one, so check 6 prints a note for that boot on every run instead of failing. The acknowledgement covers that boot and no other.

## 2026-11-14

Boot with HPKE key `77342b559a4995c1`, holding the door's TLS key with SPKI SHA-256 `51ff1bfcc71c78a34940a99cf6641bc7aecd0a33cd81bfeeda1a6cab596d5190`, which other boots hold with verified records. All times are UTC.

- 10:09:37: a restart deploy took one of the two prod boxes out of service.
- 10:10:23: a new enclave on that box, this boot, took the door's TLS key from the boot on the other box. It did not post its record to Rekor at once. The door then spaced its posts per key, and that box had last posted for this key at 09:46:03, so its next post was due at 10:46:03.
- 10:14 to about 10:25: `/v1/attestation` listed this boot and its HPKE key.
- 10:15:19: the deploy failed, because the door did not report that it was serving. The box stayed out of service.
- 10:22:44: a re-run of the deploy restarted the enclave, and this boot ended before it posted. Its record certificate existed only inside the enclave, so no record of this boot can be logged now. A record posted later would describe a different custody.

This boot never served TLS. A door serves on a key only after it logs its record, and this boot never logged one. The deploy kept the box out of the door's target group, and out of the API's, from 10:09:37 until the boot ended, so a prompt sealed to this boot's HPKE key would reach the other box, which refuses a key it does not hold. No record names this boot as a sender, so no other boot took the key from it.

Check 6 failed for this boot from 12:09, when its 2 hours of grace ended. At 20:04 the same day, Morse changed the door to count and space its posts per custody, not per key, so a new boot that takes a key posts its record at once.

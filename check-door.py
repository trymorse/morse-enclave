# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2==6.1.5", "cryptography==50.0.2", "tuf==7.0.1", "securesystemslib==1.6.0", "urllib3==2.8.0"]
# ///
"""Checks that every certificate for Morse's inference door holds a key whose boot record a pinned enclave logged in Rekor. The logic is in check_door.py; this file is the entry point `uv run check-door.py` reads its dependencies from."""

from check_door import main

if __name__ == "__main__":
    main()

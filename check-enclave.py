# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2==6.1.5", "cryptography==50.0.2"]
# ///
"""Checks the enclaves Morse runs right now against the images morse-pins lists. The logic is in check_enclave.py; this file is the entry point `uv run check-enclave.py` reads its dependencies from."""

from check_enclave import main

if __name__ == "__main__":
    main()

# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2==6.1.5", "cryptography==50.0.2"]
# ///
"""Checks the enclaves Morse runs right now against the images morse-pins lists.

Usage: uv run check-enclave.py [--pins enclave_pins.json]

It fetches each running enclave's attestation document, checks that AWS's Nitro hardware signed it,
and looks its PCRs up in morse-pins. It exits 1 if any enclave fails.
"""

import argparse
import base64
import hashlib
import json
import sys
import time
import urllib.request
from datetime import datetime, timezone

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ATTESTATION_URL = "https://api.trymorse.ai/v1/attestation"
PINS_URL = "https://raw.githubusercontent.com/trymorse/morse-pins/main/enclave_pins.json"
SOURCE_URL = "https://github.com/trymorse/morse-enclave/tree/"
MAX_AGE_SECONDS = 30 * 60

# The AWS Nitro Enclaves root, G1, from https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
AWS_NITRO_ROOT_SHA256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
AWS_NITRO_ROOT = x509.load_pem_x509_certificate(b"""-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----""")
assert AWS_NITRO_ROOT.fingerprint(hashes.SHA256()).hex() == AWS_NITRO_ROOT_SHA256


class Refused(Exception):
    pass


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as reply:
        return json.load(reply)


def check_chain(leaf, bundle, at):
    # cabundle runs from the root to the leaf's issuer. Trust only the root pinned above.
    chain = [AWS_NITRO_ROOT] + [x509.load_der_x509_certificate(c) for c in bundle[1:]] + [leaf]
    for issuer, cert in zip(chain, chain[1:]):
        try:
            cert.verify_directly_issued_by(issuer)
        except Exception as e:
            raise Refused(f"{cert.subject.rfc4514_string()} is not signed by {issuer.subject.rfc4514_string()}") from e
    for cert in chain:
        if not cert.not_valid_before_utc <= at <= cert.not_valid_after_utc:
            raise Refused(f"{cert.subject.rfc4514_string()} was not valid when the document was issued")


def check(document):
    sign1 = cbor2.loads(document)
    if isinstance(sign1, cbor2.CBORTag) and sign1.tag == 18:
        sign1 = sign1.value
    if not isinstance(sign1, list) or len(sign1) != 4:
        raise Refused("the document is not a COSE_Sign1")
    protected, _, payload_bytes, signature = sign1
    if cbor2.loads(protected).get(1) != -35:
        raise Refused("the document is not signed with ES384")
    payload = cbor2.loads(payload_bytes)
    if payload.get("digest") != "SHA384":
        raise Refused("the document's digest is not SHA384")

    issued_at = datetime.fromtimestamp(payload["timestamp"] / 1000, timezone.utc)
    leaf = x509.load_der_x509_certificate(payload["certificate"])
    key = leaf.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp384r1":
        raise Refused("the signing certificate is not a P-384 key")
    check_chain(leaf, payload["cabundle"], issued_at)

    signed = cbor2.dumps(["Signature1", protected, b"", payload_bytes])
    r, s = int.from_bytes(signature[:48], "big"), int.from_bytes(signature[48:], "big")
    try:
        key.verify(encode_dss_signature(r, s), signed, ec.ECDSA(hashes.SHA384()))
    except Exception as e:
        raise Refused("the document's signature does not verify") from e

    age = time.time() - issued_at.timestamp()
    if age > MAX_AGE_SECONDS:
        raise Refused(f"the document was issued {age / 60:.0f} minutes ago")
    return [payload["pcrs"][i].hex() for i in range(3)], age


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pins", help="read enclave_pins.json from this file instead of morse-pins")
    args = parser.parse_args()

    if args.pins:
        with open(args.pins) as f:
            pins = json.load(f)
    else:
        pins = fetch(PINS_URL)
    instances = fetch(ATTESTATION_URL)["instances"]

    failed = False
    for n, instance in enumerate(instances, 1):
        print(f"Enclave {n} of {len(instances)}")
        try:
            pcrs, age = check(base64.b64decode(instance))
        except Refused as e:
            print(f"  FAIL: {e}\n")
            failed = True
            continue
        print(f"  AWS Nitro signed this document {age:.0f} seconds ago.")
        for i, value in enumerate(pcrs):
            print(f"  PCR{i}  {value}")
        entry = next((p for p in pins if [p["pcr0"], p["pcr1"], p["pcr2"]] == pcrs), None)
        if entry is None:
            print("  FAIL: morse-pins lists no image with these PCRs.\n")
            failed = True
        elif entry["revoked"]:
            print(f"  FAIL: these are the PCRs of {entry['tag']}, which morse-pins marks revoked.\n")
            failed = True
        else:
            print(f"  OK: this is {entry['tag']}. Source: {SOURCE_URL}{entry['tag']}\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

"""The public image signer's statements, verified offline, for check_door.py's check 7. It is
not a script.

It checks a Sigstore bundle over a statement as the enclave's pinsig.VerifyBundleV2 does: one hashedrekord v0.0.2
entry in a Rekor v2 shard with k witness cosignatures, read by rekor.py, a Fulcio certificate that chains to
Sigstore's trusted root at its NotBefore, the identity of sign.yml on main of trymorse/morse-pins in the first attempt
of a push or schedule run, a signature over the statement's digest, and k cosignatures at or before the
certificate's NotAfter. It also recomputes what a statement must say from the morse-pins commit it names.
"""

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import ExtendedKeyUsageOID

BUNDLE_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
ISSUER = "https://token.actions.githubusercontent.com"
REPOSITORY = "https://github.com/trymorse/morse-pins"
REPOSITORY_ID = "1437511167"
OWNER_ID = "345029672"
WORKFLOW = f"{REPOSITORY}/.github/workflows/sign.yml@refs/heads/main"
TRIGGERS = ("push", "schedule")
VENDOR_FILES = ("near_pins.json", "phala_model_pins.json", "phala_pins.json", "tinfoil_pins.json")
SIGNED_FILES = ("enclave_pins.json", *VENDOR_FILES)

OID = "1.3.6.1.4.1.57264.1."
ISSUER_V1, ISSUER_V2, BUILD_SIGNER, RUNNER, SOURCE_URI, SOURCE_DIGEST, SOURCE_REF, SOURCE_ID, OWNER, CONFIG_URI, CONFIG_DIGEST, TRIGGER, RUN = (
    OID + n for n in ("1", "8", "9", "11", "12", "13", "14", "15", "17", "18", "19", "20", "21"))


class Unsigned(Exception):
    """Why a bundle does not prove that sign.yml signed a statement."""


@dataclass(frozen=True)
class Signed:
    commit: str
    run: str


@dataclass(frozen=True)
class Authority:
    chain: tuple
    start: object
    end: object

    def valid_at(self, t):
        return t >= self.start and (self.end is None or t <= self.end)


def read_authorities(trusted_root, rfc3339):
    """The Fulcio CAs of a trusted_root.json, each chain from its intermediates up to its root."""
    authorities = []
    for ca in json.loads(trusted_root).get("certificateAuthorities") or []:
        chain = tuple(x509.load_der_x509_certificate(base64.b64decode(c["rawBytes"], validate=True)) for c in ca["certChain"]["certificates"])
        valid = ca.get("validFor") or {}
        authorities.append(Authority(chain, rfc3339(valid["start"], "validFor.start")[0], rfc3339(valid["end"], "validFor.end")[0] if valid.get("end") else None))
    if not authorities:
        raise ValueError("Sigstore's trusted root lists no certificate authority")
    return authorities


def der_utf8(raw):
    if len(raw) < 2 or raw[0] != 0x0C:
        raise ValueError("not a UTF8String")
    length, start = raw[1], 2
    if length & 0x80:
        width = length & 0x7F
        length, start = int.from_bytes(raw[2:2 + width], "big"), 2 + width
    if len(raw) != start + length:
        raise ValueError("not one UTF8String")
    return raw[start:].decode()


def extension(leaf, oid):
    try:
        raw = leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid)).value.value
    except x509.ExtensionNotFound:
        raise Unsigned(f"the certificate has no extension {oid}") from None
    try:
        return raw if oid == ISSUER_V1 else der_utf8(raw)
    except (ValueError, UnicodeDecodeError) as e:
        raise Unsigned(f"the certificate's extension {oid} is not a UTF8String") from e


def check_identity(leaf):
    """The commit and run of sign.yml that the certificate names, as pinsig's checkIdentity reads them."""
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        raise Unsigned("the certificate has no SAN") from None
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1 or len(list(san)) != 1:
        raise Unsigned("the SAN is not exactly one URI")
    if extension(leaf, SOURCE_REF) != "refs/heads/main":
        raise Unsigned(f"the source ref is {extension(leaf, SOURCE_REF)!r}, not refs/heads/main")
    if uris[0] != WORKFLOW:
        raise Unsigned(f"the SAN is {uris[0]}, not {WORKFLOW}")
    for oid, want in ((ISSUER_V2, ISSUER), (BUILD_SIGNER, WORKFLOW), (RUNNER, "github-hosted"), (SOURCE_URI, REPOSITORY),
                      (SOURCE_ID, REPOSITORY_ID), (OWNER, OWNER_ID), (CONFIG_URI, WORKFLOW)):
        if extension(leaf, oid) != want:
            raise Unsigned(f"the certificate's extension {oid} is {extension(leaf, oid)!r}, not {want!r}")
    try:
        legacy = leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier(ISSUER_V1)).value.value
        if legacy != ISSUER.encode():
            raise Unsigned(f"the certificate's deprecated issuer is {legacy!r}, not {ISSUER!r}")
    except x509.ExtensionNotFound:
        pass
    if extension(leaf, TRIGGER) not in TRIGGERS:
        raise Unsigned(f"the run was started by {extension(leaf, TRIGGER)!r}, not by one of {', '.join(TRIGGERS)}")
    commit = extension(leaf, SOURCE_DIGEST)
    if extension(leaf, CONFIG_DIGEST) != commit:
        raise Unsigned(f"the build config digest {extension(leaf, CONFIG_DIGEST)} is not the source digest {commit}")
    run = extension(leaf, RUN)
    if not re.fullmatch(re.escape(REPOSITORY) + r"/actions/runs/[0-9]+/attempts/1", run, re.ASCII):
        raise Unsigned(f"the run {run} is not the first attempt of a run in {REPOSITORY}")
    return Signed(commit, run)


def verify_chain(leaf, authorities):
    try:
        usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        usage = []
    if ExtendedKeyUsageOID.CODE_SIGNING not in usage:
        raise Unsigned("the certificate has no code-signing extended key usage")
    at = leaf.not_valid_before_utc
    for authority in authorities:
        if not authority.valid_at(at):
            continue
        chain = (leaf, *authority.chain)
        try:
            for child, parent in zip(chain, chain[1:]):
                child.verify_directly_issued_by(parent)
                if not parent.not_valid_before_utc <= at <= parent.not_valid_after_utc:
                    raise ValueError(f"{parent.subject.rfc4514_string()} is not valid at {at.isoformat()}")
                if not parent.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                    raise ValueError(f"{parent.subject.rfc4514_string()} is not a CA")
            chain[-1].verify_directly_issued_by(chain[-1])
        except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
            continue
        if not leaf.not_valid_before_utc <= at <= leaf.not_valid_after_utc:
            continue
        return
    raise Unsigned(f"the certificate does not chain to a Fulcio CA of Sigstore's trusted root valid at {at.isoformat()}")


def verify_statement(statement, bundle, shards, authorities, policy, rekor):
    """The commit and run that signed statement, if bundle proves sign.yml signed it, else Unsigned. rekor is
    check-door.py's rekor.py module, which checks the entry, its checkpoint and its witnesses."""
    try:
        b = json.loads(bundle)
        if b.get("mediaType") != BUNDLE_TYPE:
            raise ValueError(f"the bundle is a {b.get('mediaType')!r}, not a {BUNDLE_TYPE}")
        material, message = b["verificationMaterial"], b["messageSignature"]
        entries = material["tlogEntries"]
        if len(entries) != 1:
            raise ValueError(f"the bundle carries {len(entries)} log entries, not one")
        leaf_der = base64.b64decode(material["certificate"]["rawBytes"], validate=True)
        if message["messageDigest"]["algorithm"] != "SHA2_256":
            raise ValueError("the bundle does not sign a SHA2_256 digest")
        digest = base64.b64decode(message["messageDigest"]["digest"], validate=True)
        signature = base64.b64decode(message["signature"], validate=True)
        leaf = x509.load_der_x509_certificate(leaf_der)
    except (ValueError, KeyError, TypeError, AttributeError, binascii.Error) as e:
        raise Unsigned(f"the bundle does not parse: {e}") from e
    if digest != hashlib.sha256(statement).digest():
        raise Unsigned("the bundle signs another digest than the statement's")
    signed = check_identity(leaf)
    try:
        logged = rekor.verify_logged(json.dumps(entries[0]).encode(), shards, policy)
    except rekor.Refusal as e:
        raise Unsigned(f"the log entry does not verify: {e}") from e
    if (logged.body.digest, logged.body.signature, logged.body.certificate) != (digest, signature, leaf_der):
        raise Unsigned("the log entry names another digest, signature or certificate than the bundle")
    verify_chain(leaf, authorities)
    try:
        leaf.public_key().verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except (InvalidSignature, AttributeError, TypeError) as e:
        raise Unsigned("the certificate's key did not sign the statement") from e
    cosigners = logged.checkpoint.cosigners
    if len(cosigners) < policy.k or cosigners[policy.k - 1].time > leaf.not_valid_after_utc:
        raise Unsigned(f"fewer than {policy.k} counted cosignatures are at or before the certificate's NotAfter {leaf.not_valid_after_utc.isoformat()}")
    return signed


def jcs_sha256(raw):
    """The sha256 of a vendor pins file's RFC 8785 bytes, as sign.yml's jq -cS writes them for the subset it admits."""
    canonical = json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def expected_statement(statement, show, count):
    """What a statement must say, from the morse-pins commit it names. show(name) reads a file at that commit, and
    count() gives the commit's git rev-list --count, the sequence sign.yml writes."""
    kind = statement.get("type")
    if kind == "morse-enclave-pins-v1":
        pins = json.loads(show("enclave_pins.json"))
        images = sorted(({k: p[k] for k in ("pcr0", "pcr1", "pcr2", "revoked")} for p in pins if p["environment"] == statement.get("environment")),
                        key=lambda image: image["pcr0"])
        body = {"environment": statement.get("environment"), "images": images}
    elif kind == "morse-vendor-pins-v1":
        body = {"files": {f"v4/{name}": jcs_sha256(show(name)) for name in VENDOR_FILES}}
    else:
        raise ValueError(f"the statement's type is {kind!r}")
    return {"type": kind, "sequence": count(), "pins_commit": statement.get("pins_commit"), "time": statement.get("time"), **body}

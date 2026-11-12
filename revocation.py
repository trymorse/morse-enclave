"""Certificate revocation, read from a certificate's CA by OCSP or CRL, for check-door.py, which reads this file. It is
not a script. Each lookup reads the network through the fetch it is given.
"""

import base64
import urllib.parse
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID


@dataclass(frozen=True)
class Revocation:
    revoked: bool | None
    how: str


class Unread(Exception):
    pass


def uris(cert, extension, method=None):
    try:
        value = cert.extensions.get_extension_for_class(extension).value
    except x509.ExtensionNotFound:
        return []
    if method is None:
        names = [n for point in value for n in point.full_name or []]
    else:
        names = [d.access_location for d in value if d.access_method == method]
    return [n.value for n in names if isinstance(n, x509.UniformResourceIdentifier)]


def read_issuer(cert, fetch):
    urls = uris(cert, x509.AuthorityInformationAccess, AuthorityInformationAccessOID.CA_ISSUERS)
    if not urls:
        raise Unread("it names no issuer to check a revocation answer against")
    try:
        raw = fetch(urls[0])
    except OSError as e:
        raise Unread(f"its issuer at {urls[0]} could not be read: {e!r}") from e
    try:
        issuer = x509.load_der_x509_certificate(raw) if raw[:1] == b"0" else x509.load_pem_x509_certificate(raw)
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature) as e:
        raise Unread(f"{urls[0]} holds no certificate that signed it: {e!r}") from e
    return issuer


def signed_by(key, signature, data, algorithm):
    if isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, data, padding.PKCS1v15(), algorithm)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(signature, data, ec.ECDSA(algorithm))
    else:
        raise InvalidSignature(f"a {type(key).__name__} signature is not one this check verifies")


def delegated(responder, issuer, when):
    try:
        responder.verify_directly_issued_by(issuer)
        usage = responder.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
        return False
    return ExtendedKeyUsageOID.OCSP_SIGNING in usage and responder.not_valid_before_utc <= when <= responder.not_valid_after_utc


def ask_ocsp(cert, issuer, url, fetch):
    request = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build().public_bytes(serialization.Encoding.DER)
    try:
        reply = ocsp.load_der_ocsp_response(fetch(f"{url.rstrip('/')}/{urllib.parse.quote(base64.b64encode(request).decode(), safe='')}"))
    except (OSError, ValueError) as e:
        raise Unread(f"the OCSP responder at {url} could not be read: {e!r}") from e
    if reply.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise Unread(f"the OCSP responder at {url} answered {reply.response_status.name}")
    single = None
    for r in reply.responses:
        asked = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, r.hash_algorithm).build()
        if (r.serial_number, r.issuer_name_hash, r.issuer_key_hash) == (cert.serial_number, asked.issuer_name_hash, asked.issuer_key_hash):
            single = r
    if single is None:
        raise Unread(f"the OCSP responder at {url} answered for another certificate")
    signers = [issuer] + [d for d in reply.certificates if delegated(d, issuer, single.this_update_utc)]
    for signer in signers:
        try:
            signed_by(signer.public_key(), reply.signature, reply.tbs_response_bytes, reply.signature_hash_algorithm)
            break
        except (InvalidSignature, TypeError, ValueError):
            continue
    else:
        raise Unread(f"the OCSP responder at {url} answered with a signature its issuer did not make or delegate")
    if single.certificate_status == ocsp.OCSPCertStatus.UNKNOWN:
        raise Unread(f"the OCSP responder at {url} does not know it")
    return single.certificate_status == ocsp.OCSPCertStatus.REVOKED, single.revocation_reason


def ask_crl(cert, issuer, url, fetch):
    try:
        crl = x509.load_der_x509_crl(fetch(url))
    except (OSError, ValueError) as e:
        raise Unread(f"the CRL at {url} could not be read: {e!r}") from e
    if crl.issuer != issuer.subject or not crl.is_signature_valid(issuer.public_key()):
        raise Unread(f"the CRL at {url} is not signed by its issuer")
    entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if entry is None:
        return False, None
    try:
        return True, entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
    except x509.ExtensionNotFound:
        return True, None


def revocation(der, fetch):
    """A revocation is final unless its reason is certificateHold (RFC 6960 section 2.2), so an old revoked answer is
    as good as a fresh one."""
    cert = x509.load_der_x509_certificate(der)
    asks = [("OCSP", ask_ocsp, u) for u in uris(cert, x509.AuthorityInformationAccess, AuthorityInformationAccessOID.OCSP)[:1]]
    asks += [("CRL", ask_crl, u) for u in uris(cert, x509.CRLDistributionPoints)[:1]]
    if not asks:
        return Revocation(None, "it names neither an OCSP responder nor a CRL")
    try:
        issuer = read_issuer(cert, fetch)
    except Unread as e:
        return Revocation(None, str(e))
    except Exception as e:
        return Revocation(None, f"its issuer could not be read: {e!r}")
    why = []
    for kind, ask, url in asks:
        try:
            revoked, reason = ask(cert, issuer, url, fetch)
        except Unread as e:
            why.append(str(e))
            continue
        except Exception as e:
            why.append(f"the {kind} answer from {url} could not be read: {e!r}")
            continue
        if reason == x509.ReasonFlags.certificate_hold:
            return Revocation(None, f"its CA holds it, by {kind} {url}, and may release it")
        return Revocation(revoked, f"by {kind} {url}")
    return Revocation(None, "; ".join(why))

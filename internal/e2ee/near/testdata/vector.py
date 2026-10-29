from nacl import bindings as b
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import hashlib

seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
pk, sk = b.crypto_sign_seed_keypair(seed)
x_pub = b.crypto_sign_ed25519_pk_to_curve25519(pk)
x_sec = b.crypto_sign_ed25519_sk_to_curve25519(sk)
print("ed25519 pub", pk.hex())
print("x25519 pub", x_pub.hex())
print("x25519 sec", x_sec.hex())
eph_sec = hashlib.sha256(b"morse near kat ephemeral").digest()
eph_pub = b.crypto_scalarmult_base(eph_sec)
shared = b.crypto_scalarmult(eph_sec, x_pub)
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ed25519_encryption").derive(shared)
nonce = bytes(range(24))
ct = b.crypto_aead_xchacha20poly1305_ietf_encrypt(b"near e2ee v2 known answer", None, nonce, key)
print("wire", (eph_pub + nonce + ct).hex())

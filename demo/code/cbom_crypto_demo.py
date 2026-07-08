#!/usr/bin/env python3
"""
CBOM-flavored cryptography demo using pyca/cryptography.

This script demonstrates algorithms whose names/families appear in the
CycloneDX Cryptography Registry for CBOM-style cryptographic assets:

  - AES-256-GCM       authenticated encryption (AEAD)
  - SHA-256           hash
  - HMAC-SHA-256      MAC
  - ECDH-P-256        key agreement
  - HKDF-SHA-256      key derivation
  - ECDSA-P-256-SHA-256 signature
  - RSA-PSS-SHA-256-3072 signature
  - Ed25519           signature

Run:
    python cbom_crypto_demo.py

Install dependency:
    python -m pip install cryptography
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import datetime, timezone
from importlib.metadata import version
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64(data: bytes) -> str:
    """Base64-encode bytes so JSON output stays readable."""
    return base64.b64encode(data).decode("ascii")


def sha256_hex(data: bytes) -> str:
    """CycloneDX name: SHA-256. Primitive: hash."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def hmac_sha256_tag(key: bytes, data: bytes) -> bytes:
    """CycloneDX name: HMAC-SHA-256. Primitive: MAC."""
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def verify_hmac_sha256(key: bytes, data: bytes, tag: bytes) -> bool:
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    try:
        mac.verify(tag)
        return True
    except InvalidSignature:
        return False


def aes_256_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> dict[str, str]:
    """
    CycloneDX name: AES-256-GCM-128-96.

    AES-GCM gives confidentiality + integrity. The 96-bit nonce must be unique
    for every encryption under the same key. The 128-bit authentication tag is
    appended by pyca/cryptography to the ciphertext.
    """
    nonce = os.urandom(12)  # 96-bit IV/nonce for GCM
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "alg": "AES-256-GCM-128-96",
        "nonce_b64": b64(nonce),
        "aad_b64": b64(aad),
        "ciphertext_and_tag_b64": b64(ciphertext_and_tag),
    }


def aes_256_gcm_decrypt(key: bytes, package: dict[str, str]) -> bytes:
    nonce = base64.b64decode(package["nonce_b64"])
    aad = base64.b64decode(package["aad_b64"])
    ciphertext_and_tag = base64.b64decode(package["ciphertext_and_tag_b64"])
    return AESGCM(key).decrypt(nonce, ciphertext_and_tag, aad)


def ecdh_p256_hkdf_sha256_shared_key() -> tuple[bytes, bytes]:
    """
    CycloneDX names: ECDH-P-256 and HKDF-SHA-256.

    ECDH gives both parties the same raw shared secret. HKDF turns that raw
    shared secret into a uniformly distributed AES key.
    """
    alice_private = ec.generate_private_key(ec.SECP256R1())
    bob_private = ec.generate_private_key(ec.SECP256R1())

    alice_raw_secret = alice_private.exchange(ec.ECDH(), bob_private.public_key())
    bob_raw_secret = bob_private.exchange(ec.ECDH(), alice_private.public_key())
    assert alice_raw_secret == bob_raw_secret

    salt = os.urandom(16)
    info = b"cbom-demo: ECDH-P-256 -> AES-256-GCM content key"

    alice_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(alice_raw_secret)

    bob_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(bob_raw_secret)

    return alice_key, bob_key


def ecdsa_p256_sha256_sign_and_verify(message: bytes) -> bool:
    """CycloneDX name: ECDSA-P-256-SHA-256. Primitive: signature."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    try:
        private_key.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def rsa_pss_sha256_sign_and_verify(message: bytes) -> bool:
    """CycloneDX name: RSA-PSS-SHA-256-MGF1-SHA-256-32-3072. Primitive: signature."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32,
        ),
        hashes.SHA256(),
    )
    try:
        private_key.public_key().verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def ed25519_sign_and_verify(message: bytes) -> bool:
    """CycloneDX name: Ed25519. Primitive: signature."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    signature = private_key.sign(message)
    try:
        private_key.public_key().verify(signature, message)
        return True
    except InvalidSignature:
        return False


def public_key_fingerprint_sha256(public_key: Any) -> str:
    """Hash a public key in DER form; useful evidence without leaking private keys."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_hex(der)


def cbom_algorithm_component(
    name: str,
    primitive: str,
    family: str,
    parameter_set: str | None,
    functions: list[str],
    mode: str | None = None,
    classical_security_bits: int | None = None,
) -> dict[str, Any]:
    algorithm_properties: dict[str, Any] = {
        "primitive": primitive,
        "algorithmFamily": family,
        "cryptoFunctions": functions,
    }
    if parameter_set is not None:
        algorithm_properties["parameterSetIdentifier"] = parameter_set
    if mode is not None:
        algorithm_properties["mode"] = mode
    if classical_security_bits is not None:
        algorithm_properties["classicalSecurityLevel"] = classical_security_bits

    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/algorithm/{name}",
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": algorithm_properties,
        },
    }


def build_cbom_snippet() -> dict[str, Any]:
    """
    A small CycloneDX-style CBOM snippet for the algorithms used in this file.
    It inventories algorithm assets only; it intentionally does not export keys.
    """
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": "cbom-pyca-cryptography-demo",
                "version": "1.0.0",
            },
            "tools": [
                {
                    "vendor": "pyca",
                    "name": "cryptography",
                    "version": version("cryptography"),
                }
            ],
        },
        "components": [
            cbom_algorithm_component(
                "AES-256-GCM-128-96",
                primitive="ae",
                family="AES",
                parameter_set="256",
                mode="GCM",
                functions=["encrypt", "decrypt"],
                classical_security_bits=256,
            ),
            cbom_algorithm_component(
                "SHA-256",
                primitive="hash",
                family="SHA-2",
                parameter_set="256",
                functions=["digest"],
                classical_security_bits=128,
            ),
            cbom_algorithm_component(
                "HMAC-SHA-256",
                primitive="mac",
                family="HMAC",
                parameter_set="SHA-256",
                functions=["mac", "verify"],
                classical_security_bits=256,
            ),
            cbom_algorithm_component(
                "ECDH-P-256",
                primitive="key-agree",
                family="ECDH",
                parameter_set="P-256",
                functions=["key-agree"],
                classical_security_bits=128,
            ),
            cbom_algorithm_component(
                "HKDF-SHA-256",
                primitive="kdf",
                family="HKDF",
                parameter_set="SHA-256",
                functions=["key-derive"],
                classical_security_bits=128,
            ),
            cbom_algorithm_component(
                "ECDSA-P-256-SHA-256",
                primitive="signature",
                family="ECDSA",
                parameter_set="P-256",
                functions=["sign", "verify"],
                classical_security_bits=128,
            ),
            cbom_algorithm_component(
                "RSA-PSS-SHA-256-MGF1-SHA-256-32-3072",
                primitive="signature",
                family="RSASSA-PSS",
                parameter_set="3072",
                functions=["sign", "verify"],
                classical_security_bits=128,
            ),
            cbom_algorithm_component(
                "Ed25519",
                primitive="signature",
                family="EdDSA",
                parameter_set="25519",
                functions=["sign", "verify"],
                classical_security_bits=128,
            ),
        ],
    }


def main() -> None:
    plaintext = b"A small secret that will be protected with CBOM-relevant algorithms."
    aad = b"component=pkg:pypi/cbom-pyca-cryptography-demo@1.0.0"

    # 1) Direct AES-GCM encryption/decryption.
    aes_key = AESGCM.generate_key(bit_length=256)
    encrypted = aes_256_gcm_encrypt(aes_key, plaintext, aad)
    decrypted = aes_256_gcm_decrypt(aes_key, encrypted)
    assert decrypted == plaintext

    # Show that tampering is detected by AES-GCM's tag.
    tampered = dict(encrypted)
    raw = bytearray(base64.b64decode(tampered["ciphertext_and_tag_b64"]))
    raw[0] ^= 1
    tampered["ciphertext_and_tag_b64"] = b64(bytes(raw))
    try:
        aes_256_gcm_decrypt(aes_key, tampered)
        tamper_detected = False
    except InvalidTag:
        tamper_detected = True

    # 2) ECDH + HKDF to agree on a fresh AES key.
    alice_key, bob_key = ecdh_p256_hkdf_sha256_shared_key()
    assert alice_key == bob_key
    ecdh_encrypted = aes_256_gcm_encrypt(alice_key, b"Message encrypted with an ECDH-derived key", aad)
    ecdh_decrypted = aes_256_gcm_decrypt(bob_key, ecdh_encrypted)

    # 3) Hash and MAC.
    hmac_key = os.urandom(32)
    tag = hmac_sha256_tag(hmac_key, plaintext)

    # 4) Digital signatures.
    ecdsa_ok = ecdsa_p256_sha256_sign_and_verify(plaintext)
    rsa_ok = rsa_pss_sha256_sign_and_verify(plaintext)
    ed25519_ok = ed25519_sign_and_verify(plaintext)

    result = {
        "demo_results": {
            "aes_gcm_round_trip_ok": decrypted == plaintext,
            "aes_gcm_tamper_detected": tamper_detected,
            "ecdh_hkdf_shared_keys_match": alice_key == bob_key,
            "ecdh_derived_aes_round_trip_ok": ecdh_decrypted == b"Message encrypted with an ECDH-derived key",
            "sha256_plaintext_hex": sha256_hex(plaintext),
            "hmac_sha256_valid": verify_hmac_sha256(hmac_key, plaintext, tag),
            "ecdsa_p256_sha256_signature_valid": ecdsa_ok,
            "rsa_pss_sha256_signature_valid": rsa_ok,
            "ed25519_signature_valid": ed25519_ok,
        },
        "example_ciphertext_package": encrypted,
        "cbom_snippet": build_cbom_snippet(),
        "important_security_notes": [
            "Never reuse an AES-GCM nonce with the same key.",
            "Do not put private keys or symmetric keys into a CBOM; inventory the algorithm/key metadata instead.",
            "Use authenticated encryption such as AES-GCM instead of raw AES-CBC for new designs unless a standard explicitly requires otherwise.",
            "ECDH, ECDSA, RSA, and Ed25519 are not post-quantum safe; CBOM helps identify them for future migration planning.",
        ],
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

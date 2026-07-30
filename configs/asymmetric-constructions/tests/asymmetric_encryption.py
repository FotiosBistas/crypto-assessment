# configs/asymmetric-constructions/tests/asymmetric_encryption.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP, PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


MESSAGE = b"CBOMkit ECCG asymmetric encryption scheme example"
RSAES_OAEP_SCHEME = "RSAES-OAEP"
RSAES_PKCS1_V1_5_SCHEME = "RSAES-PKCS1-v1_5"


def generate_rsa_key_pair():
    """
    Shared RSA key pair for asymmetric-encryption scheme examples.

    The scheme classification in ECCG section 5.1 is about the encryption
    padding/scheme. The 3072-bit modulus keeps the RSA primitive itself in
    the recommended size range used elsewhere in the policy examples.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )


def fire_eccg_as_enc_001_rsaes_oaep():
    """
    Scanner-first RSAES-OAEP example.

    This deliberately keeps every useful signal at the call site:
    - function name contains ECCG-AS-ENC-001 and RSAES-OAEP
    - RSA key variables are type annotated
    - plaintext is a literal bytes value
    - padding.OAEP(...) is inline in public_key.encrypt(...)
    """
    private_key: RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    public_key: RSAPublicKey = private_key.public_key()

    ciphertext = public_key.encrypt(
        b"ECCG-AS-ENC-001 RSAES-OAEP recommended encryption example",
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "primitive": "RSA",
        "scheme": RSAES_OAEP_SCHEME,
        "classification": "R",
        "status": "recommended",
        "padding": "OAEP",
        "ciphertext_length": len(ciphertext),
        "round_trip_ok": plaintext == b"ECCG-AS-ENC-001 RSAES-OAEP recommended encryption example",
    }


def fire_eccg_as_enc_001_rsaes_pkcs1_v1_5():
    """
    Scanner-first RSAES-PKCS1-v1_5 example.

    This intentionally mirrors the OAEP example but uses
    padding.PKCS1v15() inline so CBOMkit can observe the legacy scheme.
    """
    private_key: RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    public_key: RSAPublicKey = private_key.public_key()

    ciphertext = public_key.encrypt(
        b"ECCG-AS-ENC-001 RSAES-PKCS1-v1_5 legacy encryption example",
        padding.PKCS1v15(),
    )

    plaintext = private_key.decrypt(
        ciphertext,
        padding.PKCS1v15(),
    )

    return {
        "primitive": "RSA",
        "scheme": RSAES_PKCS1_V1_5_SCHEME,
        "classification": "L",
        "status": "legacy",
        "padding": "PKCS1v15",
        "ciphertext_length": len(ciphertext),
        "round_trip_ok": plaintext == b"ECCG-AS-ENC-001 RSAES-PKCS1-v1_5 legacy encryption example",
    }


def rsaes_oaep_recommended_example():
    """
    ECCG-AS-ENC-001 recommended asymmetric encryption scheme.

    Table entry:
    - Primitive: RSA
    - Scheme: RSAES-OAEP / OAEP (PKCS #1 v2.2, RFC 8017)
    - Classification: R

    pyca/cryptography signal:
    - public_key.encrypt(..., padding.OAEP(...))
    - private_key.decrypt(..., padding.OAEP(...))
    """
    private_key = generate_rsa_key_pair()
    public_key = private_key.public_key()

    # Keep padding.OAEP inline. CBOMkit/static scanners often match the
    # constructor at the encryption/decryption call site and do not resolve
    # padding objects assigned to variables.
    ciphertext = public_key.encrypt(
        MESSAGE,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "primitive": "RSA",
        "scheme": "RSAES-OAEP",
        "scheme_aliases": [
            "OAEP (PKCS #1 v2.2)",
            "RSAES-OAEP (RFC 8017)",
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
        ],
        "classification": "R",
        "status": "recommended",
        "padding": "OAEP",
        "mgf": "MGF1",
        "hash": "SHA-256",
        "ciphertext_length": len(ciphertext),
        "round_trip_ok": plaintext == MESSAGE,
    }


def rsaes_pkcs1_v1_5_legacy_example():
    """
    ECCG-AS-ENC-001 legacy asymmetric encryption scheme.

    Table entry:
    - Primitive: RSA
    - Scheme: RSAES-PKCS1-v1_5 / PKCS #1 v1.5 (RFC 8017)
    - Classification: L

    pyca/cryptography signal:
    - public_key.encrypt(..., padding.PKCS1v15())
    - private_key.decrypt(..., padding.PKCS1v15())
    """
    private_key = generate_rsa_key_pair()
    public_key = private_key.public_key()

    # Keep padding.PKCS1v15 inline for scanner detection.
    ciphertext = public_key.encrypt(
        MESSAGE,
        padding.PKCS1v15(),
    )

    plaintext = private_key.decrypt(
        ciphertext,
        padding.PKCS1v15(),
    )

    return {
        "primitive": "RSA",
        "scheme": "RSAES-PKCS1-v1_5",
        "scheme_aliases": [
            "PKCS#1 v1.5",
            "PKCS1v15",
            "RSAES-PKCS1-v1_5 (RFC 8017)",
            "RSA/ECB/PKCS1Padding",
        ],
        "classification": "L",
        "status": "legacy",
        "padding": "PKCS1v15",
        "ciphertext_length": len(ciphertext),
        "round_trip_ok": plaintext == MESSAGE,
    }


def rsaes_oaep_direct_constructor_signal():
    """
    Scanner-friendly OAEP variant using directly imported constructor names.

    Some analyzers match OAEP(...) more easily than padding.OAEP(...), so this
    function intentionally repeats the same recommended RSAES-OAEP scheme in a
    second import style.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    public_key = private_key.public_key()

    ciphertext = public_key.encrypt(
        MESSAGE,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    plaintext = private_key.decrypt(
        ciphertext,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "primitive": "RSA",
        "scheme": "RSAES-OAEP",
        "classification": "R",
        "status": "recommended",
        "padding": "OAEP",
        "ciphertext_length": len(ciphertext),
        "round_trip_ok": plaintext == MESSAGE,
    }


def rsaes_pkcs1_v1_5_direct_constructor_signal():
    """
    Scanner-friendly PKCS #1 v1.5 variant using directly imported constructor
    names.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    public_key = private_key.public_key()

    ciphertext = public_key.encrypt(
        MESSAGE,
        PKCS1v15(),
    )

    plaintext = private_key.decrypt(
        ciphertext,
        PKCS1v15(),
    )

    return {
        "primitive": "RSA",
        "scheme": "RSAES-PKCS1-v1_5",
        "classification": "L",
        "status": "legacy",
        "padding": "PKCS1v15",
        "ciphertext_length": len(ciphertext),
        "round_trip_ok": plaintext == MESSAGE,
    }


def asymmetric_encryption_scheme_examples():
    return {
        "fire_eccg_as_enc_001_rsaes_oaep": fire_eccg_as_enc_001_rsaes_oaep(),
        "fire_eccg_as_enc_001_rsaes_pkcs1_v1_5": fire_eccg_as_enc_001_rsaes_pkcs1_v1_5(),
        "rsaes_oaep_recommended": rsaes_oaep_recommended_example(),
        "rsaes_pkcs1_v1_5_legacy": rsaes_pkcs1_v1_5_legacy_example(),
        "rsaes_oaep_direct_constructor": rsaes_oaep_direct_constructor_signal(),
        "rsaes_pkcs1_v1_5_direct_constructor": rsaes_pkcs1_v1_5_direct_constructor_signal(),
    }


if __name__ == "__main__":
    for name, result in asymmetric_encryption_scheme_examples().items():
        print(f"\n{name}")
        print(f"primitive={result['primitive']}")
        print(f"scheme={result['scheme']}")
        print(f"aliases={result.get('scheme_aliases', [])}")
        print(f"classification={result['classification']}")
        print(f"status={result['status']}")
        print(f"padding={result['padding']}")
        print(f"ciphertext_length={result['ciphertext_length']}")
        print(f"round_trip_ok={result['round_trip_ok']}")

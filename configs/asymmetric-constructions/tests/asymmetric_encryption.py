# configs/asymmetric-constructions/tests/asymmetric_encryption.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


MESSAGE = b"CBOMkit ECCG asymmetric encryption scheme example"


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

    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    ciphertext = public_key.encrypt(
        MESSAGE,
        oaep_padding,
    )

    plaintext = private_key.decrypt(
        ciphertext,
        oaep_padding,
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

    pkcs1_v1_5_padding = padding.PKCS1v15()

    ciphertext = public_key.encrypt(
        MESSAGE,
        pkcs1_v1_5_padding,
    )

    plaintext = private_key.decrypt(
        ciphertext,
        pkcs1_v1_5_padding,
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


def asymmetric_encryption_scheme_examples():
    return {
        "rsaes_oaep_recommended": rsaes_oaep_recommended_example(),
        "rsaes_pkcs1_v1_5_legacy": rsaes_pkcs1_v1_5_legacy_example(),
    }


if __name__ == "__main__":
    for name, result in asymmetric_encryption_scheme_examples().items():
        print(f"\n{name}")
        print(f"primitive={result['primitive']}")
        print(f"scheme={result['scheme']}")
        print(f"aliases={result['scheme_aliases']}")
        print(f"classification={result['classification']}")
        print(f"status={result['status']}")
        print(f"padding={result['padding']}")
        print(f"ciphertext_length={result['ciphertext_length']}")
        print(f"round_trip_ok={result['round_trip_ok']}")

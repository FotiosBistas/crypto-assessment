import argparse
import json
import shutil
import subprocess
from pathlib import Path

try:
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dh, ec, x25519, x448
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    CRYPTOGRAPHY_IMPORT_ERROR = None
except ModuleNotFoundError as error:
    UnsupportedAlgorithm = None
    hashes = None
    serialization = None
    dh = None
    ec = None
    x25519 = None
    x448 = None
    AESGCM = None
    HKDF = None
    CRYPTOGRAPHY_IMPORT_ERROR = error

try:
    from cryptography.hazmat.primitives.asymmetric import mlkem

    MLKEM_IMPORT_ERROR = None
except (ModuleNotFoundError, ImportError) as error:
    mlkem = None
    MLKEM_IMPORT_ERROR = error


SOURCE_PATH = "configs/asymmetric-constructions/tests/key_establishment_key_encapsulation.py"
MESSAGE = b"CBOMkit ECCG key establishment and key encapsulation example"


def derive_handshake_key(shared_secret, info):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


def public_key_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def dh_sp800_56a_ffdhe3072_key_agreement():
    """
    ECCG-KEE-002 pyca finite-field DH example.

    Table entry:
    - Primitive: FF-DLOG
    - Scheme: DH [SP 800-56A, ISO 11770-3]
    - Classification: R

    pyca/cryptography signal:
    - dh.generate_parameters(generator=2, key_size=3072)
    - private_key.exchange(peer_public_key)
    """
    parameters = dh.generate_parameters(
        generator=2,
        key_size=3072,
    )
    private_key = parameters.generate_private_key()
    peer_private_key = parameters.generate_private_key()

    shared_secret = private_key.exchange(peer_private_key.public_key())
    peer_shared_secret = peer_private_key.exchange(private_key.public_key())
    derived_key = derive_handshake_key(
        shared_secret,
        b"ECCG-KEE-002 DH ffdhe3072 key-agree",
    )
    peer_derived_key = derive_handshake_key(
        peer_shared_secret,
        b"ECCG-KEE-002 DH ffdhe3072 key-agree",
    )

    return {
        "eccg_scheme": "DH",
        "registry_name": "FFDH-ffdhe3072",
        "primitive": "key-agree",
        "classification": "R",
        "status": "implementation-obligation",
        "parameter_set": "ffdhe3072",
        "key_size": private_key.key_size,
        "public_key_pem": public_key_bytes(private_key.public_key()),
        "shared_secret_length": len(shared_secret),
        "derived_key_length": len(derived_key),
        "round_trip_ok": derived_key == peer_derived_key,
    }


def ecdh_sp800_56a_p256_key_agreement():
    """
    ECCG-KEE-002 pyca EC-DH example over NIST P-256.

    Table entry:
    - Primitive: EC-DLOG
    - Scheme: EC-DH [SP 800-56A, ISO 11770-3]
    - Classification: R

    pyca/cryptography signal:
    - ec.generate_private_key(ec.SECP256R1())
    - private_key.exchange(ec.ECDH(), peer_public_key)
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    peer_private_key = ec.generate_private_key(ec.SECP256R1())

    shared_secret = private_key.exchange(
        ec.ECDH(),
        peer_private_key.public_key(),
    )
    peer_shared_secret = peer_private_key.exchange(
        ec.ECDH(),
        private_key.public_key(),
    )
    derived_key = derive_handshake_key(
        shared_secret,
        b"ECCG-KEE-002 EC-DH nist/P-256 key-agree",
    )
    peer_derived_key = derive_handshake_key(
        peer_shared_secret,
        b"ECCG-KEE-002 EC-DH nist/P-256 key-agree",
    )

    return {
        "eccg_scheme": "EC-DH",
        "registry_name": "ECDH-nist/P-256",
        "primitive": "key-agree",
        "classification": "R",
        "status": "implementation-obligation",
        "curve": private_key.curve.name,
        "key_size": private_key.key_size,
        "public_key_pem": public_key_bytes(private_key.public_key()),
        "shared_secret_length": len(shared_secret),
        "derived_key_length": len(derived_key),
        "round_trip_ok": derived_key == peer_derived_key,
    }


def ecdh_sp800_56a_brainpoolp256r1_key_agreement():
    """
    ECCG-KEE-002 pyca EC-DH example over BrainpoolP256r1.

    This gives scanners a second agreed EC-DH curve family signal.
    """
    private_key = ec.generate_private_key(ec.BrainpoolP256R1())
    peer_private_key = ec.generate_private_key(ec.BrainpoolP256R1())

    shared_secret = private_key.exchange(
        ec.ECDH(),
        peer_private_key.public_key(),
    )
    peer_shared_secret = peer_private_key.exchange(
        ec.ECDH(),
        private_key.public_key(),
    )
    derived_key = derive_handshake_key(
        shared_secret,
        b"ECCG-KEE-002 EC-DH brainpoolP256r1 key-agree",
    )
    peer_derived_key = derive_handshake_key(
        peer_shared_secret,
        b"ECCG-KEE-002 EC-DH brainpoolP256r1 key-agree",
    )

    return {
        "eccg_scheme": "EC-DH",
        "registry_name": "ECDH-brainpoolP256r1",
        "primitive": "key-agree",
        "classification": "R",
        "status": "implementation-obligation",
        "curve": private_key.curve.name,
        "key_size": private_key.key_size,
        "public_key_pem": public_key_bytes(private_key.public_key()),
        "shared_secret_length": len(shared_secret),
        "derived_key_length": len(derived_key),
        "round_trip_ok": derived_key == peer_derived_key,
    }


def x25519_registry_key_agreement_variant():
    """
    ECCG-KEE-001 negative-control registry variant: x25519.

    The CycloneDX registry lists x25519 as a key-agreement pattern. It is not
    one of the four recommended schemes named by ECCG-KEE-001.
    """
    private_key = x25519.X25519PrivateKey.generate()
    peer_private_key = x25519.X25519PrivateKey.generate()

    shared_secret = private_key.exchange(peer_private_key.public_key())
    peer_shared_secret = peer_private_key.exchange(private_key.public_key())
    derived_key = derive_handshake_key(
        shared_secret,
        b"ECCG-KEE-001 x25519 registry key-agree variant",
    )
    peer_derived_key = derive_handshake_key(
        peer_shared_secret,
        b"ECCG-KEE-001 x25519 registry key-agree variant",
    )

    return {
        "eccg_scheme": "EC-DH",
        "registry_name": "x25519",
        "primitive": "key-agree",
        "classification": "non_compliant",
        "status": "not_recommended",
        "shared_secret_length": len(shared_secret),
        "derived_key_length": len(derived_key),
        "round_trip_ok": derived_key == peer_derived_key,
    }


def x448_registry_key_agreement_variant():
    """
    ECCG-KEE-001 negative-control registry variant: x448.
    """
    private_key = x448.X448PrivateKey.generate()
    peer_private_key = x448.X448PrivateKey.generate()

    shared_secret = private_key.exchange(peer_private_key.public_key())
    peer_shared_secret = peer_private_key.exchange(private_key.public_key())
    derived_key = derive_handshake_key(
        shared_secret,
        b"ECCG-KEE-001 x448 registry key-agree variant",
    )
    peer_derived_key = derive_handshake_key(
        peer_shared_secret,
        b"ECCG-KEE-001 x448 registry key-agree variant",
    )

    return {
        "eccg_scheme": "EC-DH",
        "registry_name": "x448",
        "primitive": "key-agree",
        "classification": "non_compliant",
        "status": "not_recommended",
        "shared_secret_length": len(shared_secret),
        "derived_key_length": len(derived_key),
        "round_trip_ok": derived_key == peer_derived_key,
    }


def ecies_kem_p256_composition_example():
    """
    ECCG-KEE-002 ECIES-KEM scanner example.

    pyca/cryptography does not expose a first-class ECIES-KEM API. This uses
    the underlying pyca ECDH + HKDF + AES-GCM composition and keeps ECIES-KEM
    in the function name and metadata for scanners that preserve source
    context.
    """
    recipient_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())

    shared_secret = ephemeral_private_key.exchange(
        ec.ECDH(),
        recipient_private_key.public_key(),
    )
    wrapping_key = derive_handshake_key(
        shared_secret,
        b"ECCG-KEE-002 ECIES-KEM nist/P-256",
    )
    nonce = b"\x00" * 12
    ciphertext = AESGCM(wrapping_key).encrypt(
        nonce,
        MESSAGE,
        b"ECIES-KEM-nist/P-256",
    )

    return {
        "eccg_scheme": "ECIES-KEM",
        "registry_name": "ECIES-nist/P-256-HKDF-AES-256-GCM",
        "primitive": "pke",
        "classification": "R",
        "status": "implementation-obligation",
        "curve": recipient_private_key.curve.name,
        "ciphertext_length": len(ciphertext),
        "ephemeral_public_key_pem": public_key_bytes(ephemeral_private_key.public_key()),
    }


def dlies_kem_ffdhe3072_composition_example():
    """
    ECCG-KEE-002 DLIES-KEM scanner example.

    pyca/cryptography does not expose a first-class DLIES-KEM API. This uses
    the underlying pyca finite-field DH + HKDF + AES-GCM composition and keeps
    DLIES-KEM in the function name and metadata for scanner coverage.
    """
    parameters = dh.generate_parameters(
        generator=2,
        key_size=3072,
    )
    recipient_private_key = parameters.generate_private_key()
    ephemeral_private_key = parameters.generate_private_key()

    shared_secret = ephemeral_private_key.exchange(recipient_private_key.public_key())
    wrapping_key = derive_handshake_key(
        shared_secret,
        b"ECCG-KEE-002 DLIES-KEM ffdhe3072",
    )
    nonce = b"\x01" * 12
    ciphertext = AESGCM(wrapping_key).encrypt(
        nonce,
        MESSAGE,
        b"DLIES-KEM-ffdhe3072",
    )

    return {
        "eccg_scheme": "DLIES-KEM",
        "registry_name": "DLIES-KEM-ffdhe3072-HKDF-AES-256-GCM",
        "primitive": "kem",
        "classification": "R",
        "status": "implementation-obligation",
        "parameter_set": "ffdhe3072",
        "key_size": recipient_private_key.key_size,
        "ciphertext_length": len(ciphertext),
        "ephemeral_public_key_pem": public_key_bytes(ephemeral_private_key.public_key()),
    }


def ml_kem_768_key_encapsulation():
    """
    ECCG-KEE-001 negative-control pyca ML-KEM-768 example.

    ML-KEM is intentionally present as scanner input, but it is not one of the
    four recommended schemes named by ECCG-KEE-001.

    pyca/cryptography signal:
    - mlkem.MLKEM768PrivateKey.generate()
    - public_key.encapsulate()
    - private_key.decapsulate(ciphertext)
    """
    private_key = mlkem.MLKEM768PrivateKey.generate()
    public_key = private_key.public_key()
    shared_secret, ciphertext = public_key.encapsulate()
    recovered_secret = private_key.decapsulate(ciphertext)

    return {
        "eccg_scheme": "ML-KEM",
        "registry_name": "ML-KEM-768",
        "primitive": "kem",
        "classification": "non_compliant",
        "status": "not_recommended",
        "parameter_set": 768,
        "shared_secret_length": len(shared_secret),
        "ciphertext_length": len(ciphertext),
        "round_trip_ok": shared_secret == recovered_secret,
    }


def ml_kem_1024_key_encapsulation():
    """
    ECCG-KEE-001 negative-control pyca ML-KEM-1024 example.
    """
    private_key = mlkem.MLKEM1024PrivateKey.generate()
    public_key = private_key.public_key()
    shared_secret, ciphertext = public_key.encapsulate()
    recovered_secret = private_key.decapsulate(ciphertext)

    return {
        "eccg_scheme": "ML-KEM",
        "registry_name": "ML-KEM-1024",
        "primitive": "kem",
        "classification": "non_compliant",
        "status": "not_recommended",
        "parameter_set": 1024,
        "shared_secret_length": len(shared_secret),
        "ciphertext_length": len(ciphertext),
        "round_trip_ok": shared_secret == recovered_secret,
    }


def ml_kem_512_scanner_metadata():
    """
    ML-KEM-512 scanner marker for ECCG-KEE-001.

    The current pyca/cryptography ML-KEM API exposes MLKEM768PrivateKey and
    MLKEM1024PrivateKey. This metadata keeps the lower parameter-set name in
    source for scanners that detect registry-style strings.
    """
    return {
        "eccg_scheme": "ML-KEM",
        "registry_name": "ML-KEM-512",
        "primitive": "kem",
        "classification": "non_compliant",
        "status": "not_recommended",
        "parameter_set": 512,
        "pyca_cryptography_support": "not_exposed_as_MLKEM512PrivateKey",
    }


def frodokem_scanner_metadata():
    """
    FrodoKEM scanner marker for ECCG-KEE-001.

    pyca/cryptography does not expose FrodoKEM. Keep the registry/ECCG names
    in source so static scanners can still emit CBOM components for policy
    validation.
    """
    return {
        "eccg_scheme": "FrodoKEM",
        "registry_names": [
            "FrodoKEM-640",
            "FrodoKEM-976",
            "FrodoKEM-1344",
        ],
        "primitive": "kem",
        "classification": "non_compliant",
        "status": "not_recommended",
        "recommended_parameter_sets": [976, 1344],
        "pyca_cryptography_support": "not_available",
    }


def pyca_key_establishment_examples(run_expensive_dh=False):
    """
    Execute pyca-backed key establishment examples where the installed
    cryptography version supports them.

    Finite-field DH and DLIES examples generate 3072-bit parameters and can be
    slow, so they are opt-in through --run-expensive-dh.
    """
    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        return {
            "available": False,
            "error": str(CRYPTOGRAPHY_IMPORT_ERROR),
            "installHint": "Install pyca/cryptography to execute these examples.",
        }

    examples = {
        "ECDH-nist/P-256": ecdh_sp800_56a_p256_key_agreement(),
        "ECDH-brainpoolP256r1": ecdh_sp800_56a_brainpoolp256r1_key_agreement(),
        "x25519": x25519_registry_key_agreement_variant(),
        "x448": x448_registry_key_agreement_variant(),
        "ECIES-KEM-nist/P-256": ecies_kem_p256_composition_example(),
        "ML-KEM-512": ml_kem_512_scanner_metadata(),
        "FrodoKEM": frodokem_scanner_metadata(),
    }

    if run_expensive_dh:
        examples["DH-ffdhe3072"] = dh_sp800_56a_ffdhe3072_key_agreement()
        examples["DLIES-KEM-ffdhe3072"] = dlies_kem_ffdhe3072_composition_example()
    else:
        examples["DH-ffdhe3072"] = {
            "available": True,
            "skipped": True,
            "reason": "3072-bit DH parameter generation is intentionally opt-in.",
        }
        examples["DLIES-KEM-ffdhe3072"] = {
            "available": True,
            "skipped": True,
            "reason": "3072-bit DH parameter generation is intentionally opt-in.",
        }

    if MLKEM_IMPORT_ERROR is not None:
        examples["ML-KEM-768"] = {
            "available": False,
            "error": str(MLKEM_IMPORT_ERROR),
            "installHint": "Use cryptography >= 47.0.0 with backend ML-KEM support.",
        }
        examples["ML-KEM-1024"] = {
            "available": False,
            "error": str(MLKEM_IMPORT_ERROR),
            "installHint": "Use cryptography >= 47.0.0 with backend ML-KEM support.",
        }
    else:
        for name, factory in {
            "ML-KEM-768": ml_kem_768_key_encapsulation,
            "ML-KEM-1024": ml_kem_1024_key_encapsulation,
        }.items():
            try:
                examples[name] = factory()
            except (UnsupportedAlgorithm, AttributeError, ValueError) as error:
                examples[name] = {
                    "available": False,
                    "error": str(error),
                    "installHint": "Use a cryptography backend with ML-KEM support.",
                }

    return examples


def key_establishment_component(
    name,
    bom_ref,
    line,
    primitive,
    algorithm_family=None,
    parameter_set=None,
    elliptic_curve=None,
    crypto_functions=None,
):
    algorithm_properties = {
        "primitive": primitive,
        "cryptoFunctions": crypto_functions or [],
    }

    if algorithm_family is not None:
        algorithm_properties["algorithmFamily"] = algorithm_family
    if parameter_set is not None:
        algorithm_properties["parameterSetIdentifier"] = str(parameter_set)
    if elliptic_curve is not None:
        algorithm_properties["ellipticCurve"] = elliptic_curve

    return {
        "name": name,
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "evidence": {
            "occurrences": [
                {
                    "line": line,
                    "offset": 1,
                    "location": SOURCE_PATH,
                    "additionalContext": name,
                }
            ]
        },
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": algorithm_properties,
        },
    }


def rego_validation_cbom():
    """
    CBOM-shaped fixture for ECCG section 5.4 Rego validation.

    The fixture intentionally uses CycloneDX registry-style primitives:
    - key-agree for DH/ECDH/J-PAKE
    - kem for ML-KEM/FrodoKEM
    - pke plus ECIES naming for ECIES-KEM, matching the registry taxonomy

    It only emits algorithmProperties keys shown in the CycloneDX schema:
    primitive, algorithmFamily, parameterSetIdentifier, ellipticCurve, and
    cryptoFunctions.
    """
    components = [
        key_establishment_component(
            "ECDH-nist/P-256",
            "ecdh-p256",
            10,
            "key-agree",
            algorithm_family="ECDH",
            elliptic_curve="nist/P-256",
            crypto_functions=["keygen", "keyderive"],
        ),
        key_establishment_component(
            "ML-KEM-768",
            "ml-kem-768-hybrid",
            10,
            "kem",
            algorithm_family="ML-KEM",
            parameter_set=768,
            crypto_functions=["keygen", "encapsulate", "decapsulate"],
        ),
        key_establishment_component(
            "ML-KEM-512",
            "ml-kem-512-standalone",
            30,
            "kem",
            algorithm_family="ML-KEM",
            parameter_set=512,
            crypto_functions=["keygen", "encapsulate", "decapsulate"],
        ),
        key_establishment_component(
            "FrodoKEM-640",
            "frodokem-640-standalone",
            40,
            "kem",
            algorithm_family="FrodoKEM",
            parameter_set=640,
            crypto_functions=["keygen", "encapsulate", "decapsulate"],
        ),
        key_establishment_component(
            "DH-ffdhe3072",
            "dh-ffdhe3072",
            50,
            "key-agree",
            algorithm_family="FFDH",
            parameter_set=3072,
            crypto_functions=["keygen", "keyderive"],
        ),
        key_establishment_component(
            "FrodoKEM-976",
            "frodokem-976-hybrid",
            50,
            "kem",
            algorithm_family="FrodoKEM",
            parameter_set=976,
            crypto_functions=["keygen", "encapsulate", "decapsulate"],
        ),
        key_establishment_component(
            "ECIES-KEM-nist/P-256",
            "ecies-kem",
            70,
            "pke",
            algorithm_family="ECIES",
            elliptic_curve="nist/P-256",
            crypto_functions=["keygen", "encrypt", "decrypt", "keyderive"],
        ),
        key_establishment_component(
            "DLIES-KEM-ffdhe3072",
            "dlies-kem",
            80,
            "kem",
            algorithm_family="DLIES",
            parameter_set=3072,
            crypto_functions=["keygen", "encapsulate", "decapsulate"],
        ),
        key_establishment_component(
            "J-PAKE-P-256",
            "j-pake",
            90,
            "key-agree",
            algorithm_family="J-PAKE",
            elliptic_curve="nist/P-256",
            crypto_functions=["keygen", "keyderive"],
        ),
    ]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "component": {
                "name": "eccg-key-establishment-key-encapsulation-rego-fixture",
                "type": "application",
            }
        },
        "components": components,
    }


EXPECTED_REGO_FINDINGS = {
    "ECCG-KEE-002|ecdh-p256": {
        "severity": "warning",
        "status": "authentication_required",
    },
    "ECCG-KEE-001|ml-kem-768-hybrid": {
        "severity": "critical",
        "status": "not_recommended",
    },
    "ECCG-KEE-001|ml-kem-512-standalone": {
        "severity": "critical",
        "status": "not_recommended",
    },
    "ECCG-KEE-001|frodokem-640-standalone": {
        "severity": "critical",
        "status": "not_recommended",
    },
    "ECCG-KEE-002|dh-ffdhe3072": {
        "severity": "warning",
        "status": "authentication_required",
    },
    "ECCG-KEE-001|frodokem-976-hybrid": {
        "severity": "critical",
        "status": "not_recommended",
    },
    "ECCG-KEE-002|ecies-kem": {
        "severity": "warning",
        "status": "authentication_required",
    },
    "ECCG-KEE-002|dlies-kem": {
        "severity": "warning",
        "status": "authentication_required",
    },
    "ECCG-KEE-001|j-pake": {
        "severity": "critical",
        "status": "not_recommended",
    },
}


def run_opa_eval(cbom_path, policies_path):
    if shutil.which("opa") is None:
        raise RuntimeError("opa is not installed or is not on PATH")

    command = [
        "opa",
        "eval",
        "-d",
        str(policies_path),
        "-i",
        str(cbom_path),
        "data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.findings",
        "--format",
        "json",
    ]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)


def summarize_opa_result(opa_result):
    values = opa_result.get("result", [])
    if not values:
        return []
    return values[0].get("expressions", [])[0].get("value", [])


def finding_key(finding):
    return f"{finding.get('ruleId')}|{finding.get('bomRef')}"


def assert_rego_findings(findings):
    by_key = {finding_key(finding): finding for finding in findings}

    missing = sorted(set(EXPECTED_REGO_FINDINGS) - set(by_key))
    unexpected = sorted(set(by_key) - set(EXPECTED_REGO_FINDINGS))

    mismatched = []
    for key, expected in EXPECTED_REGO_FINDINGS.items():
        finding = by_key.get(key)
        if finding is None:
            continue

        actual = {
            "severity": finding.get("severity"),
            "status": finding.get("status"),
        }
        if actual != expected:
            mismatched.append({"finding": key, "expected": expected, "actual": actual})

    return {
        "ok": not missing and not unexpected and not mismatched,
        "missing": missing,
        "unexpected": unexpected,
        "mismatched": mismatched,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-cbom", type=Path)
    parser.add_argument("--run-opa", action="store_true")
    parser.add_argument("--run-pyca-examples", action="store_true")
    parser.add_argument("--run-expensive-dh", action="store_true")
    parser.add_argument("--policies", type=Path, default=Path("policies/eccg"))
    args = parser.parse_args()

    if args.run_pyca_examples:
        pyca_results = pyca_key_establishment_examples(
            run_expensive_dh=args.run_expensive_dh,
        )
        print("pyca/cryptography key establishment and KEM examples")
        print(json.dumps(pyca_results, indent=2, sort_keys=True, default=str))

    cbom = rego_validation_cbom()
    if args.write_cbom:
        args.write_cbom.parent.mkdir(parents=True, exist_ok=True)
        args.write_cbom.write_text(json.dumps(cbom, indent=2, sort_keys=True) + "\n")
        cbom_path = args.write_cbom
        print(f"Wrote Rego CBOM fixture to {cbom_path}")
    else:
        cbom_path = None
        print(json.dumps(cbom, indent=2, sort_keys=True))

    print("\nExpected Rego findings")
    print(json.dumps(EXPECTED_REGO_FINDINGS, indent=2, sort_keys=True))

    if args.run_opa:
        if cbom_path is None:
            raise SystemExit("--run-opa requires --write-cbom")
        opa_result = run_opa_eval(cbom_path, args.policies)
        findings = summarize_opa_result(opa_result)
        check = assert_rego_findings(findings)
        print("\nActual Rego findings")
        print(json.dumps(findings, indent=2, sort_keys=True))
        print("\nRego check")
        print(json.dumps(check, indent=2, sort_keys=True))
        if not check["ok"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()

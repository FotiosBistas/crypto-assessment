import argparse
import json
import shutil
import subprocess
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    CRYPTOGRAPHY_IMPORT_ERROR = None
except ModuleNotFoundError as error:
    hashes = None
    dsa = None
    ec = None
    ed25519 = None
    ed448 = None
    padding = None
    rsa = None
    Prehashed = None
    CRYPTOGRAPHY_IMPORT_ERROR = error


MESSAGE = b"CBOMkit ECCG digital signature scheme example"


def rsa_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def sign_rsassa_pss():
    private_key = rsa_private_key()
    public_key = private_key.public_key()
    signature = private_key.sign(
        MESSAGE,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    public_key.verify(
        signature,
        MESSAGE,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def sign_rsa_pss_registry_name_variant():
    """
    Same pyca primitive as RSASSA-PSS, named to mirror the CycloneDX registry
    shape: RSA-PSS[-{hashAlgorithm}][-{maskGenAlgorithm}][-saltLength][-keyLength].
    """
    return sign_rsassa_pss()


def sign_rsassa_pkcs1_v1_5():
    private_key = rsa_private_key()
    public_key = private_key.public_key()
    signature = private_key.sign(
        MESSAGE,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    public_key.verify(
        signature,
        MESSAGE,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return signature


def sign_rsa_pkcs1_registry_name_variant():
    """
    Same pyca primitive as RSASSA-PKCS1-v1_5, named to mirror the CycloneDX
    registry shape: RSA-PKCS1_1.5[-{hashAlgorithm}]-[{keyLength}].
    """
    return sign_rsassa_pkcs1_v1_5()


def sign_dsa():
    private_key = dsa.generate_private_key(key_size=3072)
    public_key = private_key.public_key()
    signature = private_key.sign(MESSAGE, hashes.SHA256())
    public_key.verify(signature, MESSAGE, hashes.SHA256())
    return signature


def sign_ecdsa():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    signature = private_key.sign(MESSAGE, ec.ECDSA(hashes.SHA256()))
    public_key.verify(signature, MESSAGE, ec.ECDSA(hashes.SHA256()))
    return signature


def sign_ecdsa_prehashed():
    digest = hashes.Hash(hashes.SHA256())
    digest.update(MESSAGE)
    message_digest = digest.finalize()

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    signature = private_key.sign(message_digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    public_key.verify(signature, message_digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    return signature


def sign_ed25519_non_agreed_negative_control():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    signature = private_key.sign(MESSAGE)
    public_key.verify(signature, MESSAGE)
    return signature


def sign_ed448_non_agreed_negative_control():
    private_key = ed448.Ed448PrivateKey.generate()
    public_key = private_key.public_key()
    signature = private_key.sign(MESSAGE)
    public_key.verify(signature, MESSAGE)
    return signature


def pyca_signature_examples():
    """
    pyca/cryptography can generate the classical RSA, DSA, ECDSA, Ed25519,
    and Ed448 signatures below. It does not expose KCDSA, Schnorr, EC-KCDSA,
    EC-GDSA, EC-Schnorr, ML-DSA, XMSS, LMS, or SLH-DSA signing APIs.
    """
    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        return {
            "available": False,
            "error": str(CRYPTOGRAPHY_IMPORT_ERROR),
            "installHint": "Install pyca/cryptography, then rerun this file to generate and verify signatures.",
        }

    examples = {
        "RSASSA-PSS": {
            "status": "recommended",
            "signature": sign_rsassa_pss(),
        },
        "RSA-PSS[-SHA256][-MGF1][-MAX][-3072]": {
            "status": "recommended",
            "signature": sign_rsa_pss_registry_name_variant(),
        },
        "RSASSA-PKCS1-v1_5": {
            "status": "legacy",
            "signature": sign_rsassa_pkcs1_v1_5(),
        },
        "RSA-PKCS1_1.5[-SHA256]-[3072]": {
            "status": "legacy",
            "signature": sign_rsa_pkcs1_registry_name_variant(),
        },
        "DSA": {
            "status": "recommended",
            "signature": sign_dsa(),
        },
        "ECDSA": {
            "status": "recommended",
            "signature": sign_ecdsa(),
        },
        "EC-DSA": {
            "status": "recommended",
            "signature": sign_ecdsa_prehashed(),
        },
        "Ed25519": {
            "status": "notAgreed",
            "signature": sign_ed25519_non_agreed_negative_control(),
        },
        "Ed448": {
            "status": "notAgreed",
            "signature": sign_ed448_non_agreed_negative_control(),
        },
    }

    return {
        name: {
            "status": value["status"],
            "signatureLength": len(value["signature"]),
            "verified": True,
        }
        for name, value in examples.items()
    }


def signature_component(name, bom_ref, line):
    return {
        "name": name,
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "evidence": {
            "occurrences": [
                {
                    "line": line,
                    "offset": 1,
                    "location": "configs/asymmetric-constructions/tests/digital_signature.py",
                    "additionalContext": name,
                }
            ]
        },
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "signature",
                "cryptoFunctions": ["sign", "verify"],
            },
        },
    }


def rego_validation_cbom():
    """
    CBOM-shaped fixture for the Rego policy.

    The recommended entries should produce no ECCG-DG-001 finding.
    The legacy entries should produce warning findings.
    The non-agreed entries should produce critical findings.
    """
    recommended = [
        "RSASSA-PSS",
        "RSA-PSS[-SHA256][-MGF1][-MAX][-3072]",
        "KCDSA",
        "Schnorr",
        "DSA",
        "EC-KCDSA",
        "ECDSA",
        "EC-DSA",
        "EC-GDSA",
        "EC-Schnorr",
        "ML-DSA-65",
        "XMSS-SHA2_20_256",
        "LMS",
        "SLH-DSA-SHA2-128s",
    ]
    legacy = [
        "RSASSA-PKCS1-v1_5",
        "RSA-PKCS1_1.5[-SHA256]-[3072]",
    ]
    not_agreed = [
        "EdDSA",
        "Ed25519",
        "Ed448",
        "Falcon-512",
    ]

    components = []
    line = 1
    for index, name in enumerate(recommended, start=1):
        components.append(signature_component(name, f"recommended-signature-{index}", line))
        line += 1
    for index, name in enumerate(legacy, start=1):
        components.append(signature_component(name, f"legacy-signature-{index}", line))
        line += 1
    for index, name in enumerate(not_agreed, start=1):
        components.append(signature_component(name, f"not-agreed-signature-{index}", line))
        line += 1

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": components,
        "metadata": {
            "component": {
                "name": "eccg-digital-signature-rego-fixture",
                "type": "application",
            }
        },
    }


EXPECTED_REGO_FINDINGS = {
    "RSASSA-PKCS1-v1_5": {"severity": "warning", "status": "legacy"},
    "RSA-PKCS1_1.5[-SHA256]-[3072]": {"severity": "warning", "status": "legacy"},
    "EdDSA": {"severity": "critical", "status": "notAgreed"},
    "Ed25519": {"severity": "critical", "status": "notAgreed"},
    "Ed448": {"severity": "critical", "status": "notAgreed"},
    "Falcon-512": {"severity": "critical", "status": "notAgreed"},
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
        "data.cbom.eccg.asymmetric_constructions.digital_signature.findings",
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


def assert_rego_findings(findings):
    by_component = {finding["component"]: finding for finding in findings}

    missing = sorted(set(EXPECTED_REGO_FINDINGS) - set(by_component))
    unexpected = sorted(set(by_component) - set(EXPECTED_REGO_FINDINGS))

    mismatched = []
    for component, expected in EXPECTED_REGO_FINDINGS.items():
        finding = by_component.get(component)
        if finding is None:
            continue
        actual = {
            "severity": finding.get("severity"),
            "status": finding.get("status"),
        }
        if actual != expected:
            mismatched.append({"component": component, "expected": expected, "actual": actual})

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
    parser.add_argument("--policies", type=Path, default=Path("policies/eccg"))
    args = parser.parse_args()

    pyca_results = pyca_signature_examples()
    print("pyca/cryptography signature generation")
    print(json.dumps(pyca_results, indent=2, sort_keys=True))

    cbom = rego_validation_cbom()
    if args.write_cbom:
        args.write_cbom.parent.mkdir(parents=True, exist_ok=True)
        args.write_cbom.write_text(json.dumps(cbom, indent=2, sort_keys=True) + "\n")
        cbom_path = args.write_cbom
        print(f"\nWrote Rego CBOM fixture to {cbom_path}")
    else:
        cbom_path = None

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

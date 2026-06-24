package cbom.eccg.asymmetric_constructions.asymmetric_encryption

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.get_note

import data.cbom.eccg.asymmetric_constructions.helpers.LEGACY_ASYMMETRIC_ENCRYPTION_SCHEME
import data.cbom.eccg.asymmetric_constructions.helpers.RECOMMENDED_ASYMMETRIC_ENCRYPTION_SCHEME
import data.cbom.eccg.asymmetric_constructions.helpers.is_identifiable_asymmetric_encryption_scheme
import data.cbom.eccg.asymmetric_constructions.helpers.is_rsaes_oaep_scheme
import data.cbom.eccg.asymmetric_constructions.helpers.is_rsaes_pkcs1_v1_5_scheme
import data.cbom.eccg.asymmetric_constructions.helpers.is_unknown_rsa_encryption_scheme

SECTION := "Asymmetric-Constructions"
SUBSECTION := "Asymmetric-Encryption-Schemes"

#
# ---------------------------------------------------------
# ECCG-AS-ENC-001
# RSAES-OAEP (PKCS #1 v2.2 / RFC 8017) is the only recommended
# asymmetric encryption scheme.
#
# ECCG table:
# - RSAES-OAEP:        R
# - RSAES-PKCS1-v1_5:  L
#
# Classification:
# - R: RSAES-OAEP
# - L: RSAES-PKCS1-v1_5
# - non_compliant: other identifiable asymmetric encryption schemes
# - inconclusive: RSA encryption where padding/scheme is not exposed
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_identifiable_asymmetric_encryption_scheme(component)
    is_rsaes_oaep_scheme(component)

    random_padding_note := get_note(SECTION, SUBSECTION, "42-RandomPadding")
    oaep_padding_note := get_note(SECTION, SUBSECTION, "44-OAEP-PaddingAttack")
    quantum_note := get_note(SECTION, SUBSECTION, "45-QuantumThreat")

    finding := build_finding(
        "ECCG-AS-ENC-001",
        "info",
        sprintf(
            "%s detected. Classified as the recommended asymmetric encryption scheme.",
            [RECOMMENDED_ASYMMETRIC_ENCRYPTION_SCHEME],
        ),
        component,
        {
            "primitive": "RSA",
            "scheme": RECOMMENDED_ASYMMETRIC_ENCRYPTION_SCHEME,
            "status": "recommended",
            "classification": "R",
            "notes": {
                "randomPadding": random_padding_note,
                "oaepPaddingAttack": oaep_padding_note,
                "quantumThreat": quantum_note,
            },
        },
    )
}

findings contains finding if {
    component := input.components[_]

    is_identifiable_asymmetric_encryption_scheme(component)
    is_rsaes_pkcs1_v1_5_scheme(component)
    not is_rsaes_oaep_scheme(component)

    random_padding_note := get_note(SECTION, SUBSECTION, "42-RandomPadding")
    padding_attack_note := get_note(SECTION, SUBSECTION, "43-PaddingAttack")
    quantum_note := get_note(SECTION, SUBSECTION, "45-QuantumThreat")

    finding := build_finding(
        "ECCG-AS-ENC-001",
        "warning",
        sprintf(
            "%s detected. This asymmetric encryption scheme is legacy; %s is the only recommended asymmetric encryption scheme.",
            [LEGACY_ASYMMETRIC_ENCRYPTION_SCHEME, RECOMMENDED_ASYMMETRIC_ENCRYPTION_SCHEME],
        ),
        component,
        {
            "primitive": "RSA",
            "scheme": LEGACY_ASYMMETRIC_ENCRYPTION_SCHEME,
            "status": "legacy",
            "classification": "L",
            "recommendedScheme": RECOMMENDED_ASYMMETRIC_ENCRYPTION_SCHEME,
            "notes": {
                "randomPadding": random_padding_note,
                "paddingAttack": padding_attack_note,
                "quantumThreat": quantum_note,
            },
        },
    )
}

findings contains finding if {
    component := input.components[_]

    is_identifiable_asymmetric_encryption_scheme(component)
    not is_rsaes_oaep_scheme(component)
    not is_rsaes_pkcs1_v1_5_scheme(component)
    not is_unknown_rsa_encryption_scheme(component)

    finding := build_finding(
        "ECCG-AS-ENC-001",
        "critical",
        sprintf(
            "Asymmetric encryption scheme '%s' is not listed in the ECCG agreed asymmetric encryption scheme table. %s is the only recommended asymmetric encryption scheme.",
            [object.get(component, "name", "unknown"), RECOMMENDED_ASYMMETRIC_ENCRYPTION_SCHEME],
        ),
        component,
        {
            "scheme": object.get(component, "name", "unknown"),
            "status": "not_agreed",
            "classification": "non_compliant",
            "decision": "reject",
            "recommendedScheme": RECOMMENDED_ASYMMETRIC_ENCRYPTION_SCHEME,
            "complianceImpact": "The scheme is not RSAES-OAEP and is not the legacy RSAES-PKCS1-v1_5 scheme listed in the ECCG table.",
        },
    )
}

findings contains finding if {
    component := input.components[_]

    is_unknown_rsa_encryption_scheme(component)

    finding := build_finding(
        "ECCG-AS-ENC-001",
        "warning",
        sprintf(
            "RSA asymmetric encryption was detected, but the padding/scheme could not be determined from the CBOM. %s is the only recommended asymmetric encryption scheme.",
            [RECOMMENDED_ASYMMETRIC_ENCRYPTION_SCHEME],
        ),
        component,
        {
            "primitive": "RSA",
            "scheme": "unknown",
            "status": "unknown",
            "classification": "inconclusive",
            "recommendedScheme": RECOMMENDED_ASYMMETRIC_ENCRYPTION_SCHEME,
            "complianceImpact": "Unable to verify whether the RSA encryption scheme is RSAES-OAEP.",
        },
    )
}

package cbom.eccg.asymmetric_constructions.digital_signature

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.get_note

import data.cbom.eccg.asymmetric_constructions.helpers.eccg_recommended_signature_scheme_display_names
import data.cbom.eccg.asymmetric_constructions.helpers.eccg_recommended_signature_schemes
import data.cbom.eccg.asymmetric_constructions.helpers.get_eccg_canonical_signature_scheme_or_original
import data.cbom.eccg.asymmetric_constructions.helpers.is_digital_signature_algorithm
import data.cbom.eccg.asymmetric_constructions.helpers.is_eccg_legacy_signature_scheme
import data.cbom.eccg.asymmetric_constructions.helpers.is_eccg_recommended_signature_scheme

default compliant := true

compliant if count(findings) == 0

SECTION = "Asymmetric-Constructions"
SUBSECTION = "Digital-Signature-Schemes"

#
# ---------------------------------------------------------
# ECCG-DG-001
# Digital signature schemes must be one of the ECCG agreed
# recommended digital signature schemes.
#
# Recommended schemes:
# - RSASSA-PSS
# - KCDSA
# - Schnorr
# - DSA
# - EC-KCDSA
# - ECDSA / EC-DSA
# - EC-GDSA
# - EC-Schnorr
# - ML-DSA
# - XMSS
# - LMS
# - SLH-DSA
#
# Legacy:
# - RSASSA-PKCS1-v1_5
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_digital_signature_algorithm(component)
    is_eccg_legacy_signature_scheme(component)

    scheme := get_eccg_canonical_signature_scheme_or_original(component)

    note_ids := ["48-PKCSFormatCheck", "50-QuantumThreat"]
    notes := [
        {"noteId": id, "noteTitle": note.title, "noteText": note.text} |
        id := note_ids[_]
        note := get_note(SECTION, SUBSECTION, id)
    ]

    finding := build_finding(
        "ECCG-DG-001",
        "warning",
        sprintf(
            "Digital signature scheme '%s' is legacy in the ECCG digital signature table and is not one of the recommended schemes. The recommended digital signature schemes are %s.",
            [scheme, eccg_recommended_signature_schemes]
        ),
        component,
        {
            "scheme": scheme,
            "status": "legacy",
            "classification": "L",
            "recommendedSchemes": eccg_recommended_signature_scheme_display_names,
            "notes": notes
        }
    )
}

findings contains finding if {
    component := input.components[_]

    is_digital_signature_algorithm(component)
    not is_eccg_recommended_signature_scheme(component)
    not is_eccg_legacy_signature_scheme(component)

    scheme := get_eccg_canonical_signature_scheme_or_original(component)

    finding := build_finding(
        "ECCG-DG-001",
        "critical",
        sprintf(
            "Digital signature scheme '%s' is not listed as an ECCG recommended digital signature scheme. The recommended digital signature schemes are %s.",
            [scheme, eccg_recommended_signature_schemes]
        ),
        component,
        {
            "scheme": scheme,
            "status": "notAgreed",
            "classification": "non_compliant",
            "recommendedSchemes": eccg_recommended_signature_scheme_display_names,
            "complianceImpact": "The detected digital signature scheme is not listed in the ECCG agreed digital signature scheme table."
        }
    )
}

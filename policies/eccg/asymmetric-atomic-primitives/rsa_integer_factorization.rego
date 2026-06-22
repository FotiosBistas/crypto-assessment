package cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.evaluation_year
import data.cbom.eccg.helpers.get_parameter_set_identifier_to_number_or_unknown

import data.cbom.eccg.asymmetric_atomic_primitives.helpers.RSA_LEGACY_MARKER
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.rsa_modulus_message
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.rsa_modulus_notes
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.rsa_modulus_severity
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.rsa_modulus_status
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.is_rsa_primitive

#
# ---------------------------------------------------------
# ECCG-RSA-001
# RSA primitive has a non-recommended modulus size.
#
# ECCG classification:
# - R for n >= 3000 and log2(e) > 16
# - L[2025] for 1900 <= n < 3000 and log2(e) > 16
#
# Limitation:
# - CycloneDX data does not reliably expose RSA public exponent e.
# - Therefore log2(e) > 16 cannot be verified from the CBOM.
# - This rule checks only the available modulus size n.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_rsa_primitive(component)

    n := get_parameter_set_identifier_to_number_or_unknown(component)
    n != "unknown"
    n < 3000

    status := rsa_modulus_status(n)
    severity := rsa_modulus_severity(n)
    message := rsa_modulus_message(n, status)
    note := rsa_modulus_notes(n)

    finding := build_finding(
        "ECCG-RSA-001",
        severity,
        message,
        component,
        {
            "scheme": "RSA",
            "modulusBits": n,
            "minimumModulusBits": 3000,
            "status": status,
            "legacyMarker": RSA_LEGACY_MARKER,
            "evaluationYear": evaluation_year,
            "classification": "non_compliant",
            "publicExponent": "unknown",
            "exponentCheck": "not_verifiable",
            "note": note
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-RSA-001
# RSA primitive detected, but the modulus size could not be
# determined from the CBOM.
#
# The RSA size requirement cannot be verified without n.
# The public exponent condition log2(e) > 16 also cannot be
# reliably verified from the current CBOM fields.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_rsa_primitive(component)

    n := get_parameter_set_identifier_to_number_or_unknown(component)
    n == "unknown"

    finding := build_finding(
        "ECCG-RSA-001",
        "warning",
        "RSA primitive detected, but the modulus size n could not be determined from the CBOM. The ECCG requirements n >= 3000 and log2(e) > 16 could not be verified.",
        component,
        {
            "scheme": "RSA",
            "modulusBits": "unknown",
            "minimumModulusBits": 3000,
            "status": "unknown",
            "classification": "inconclusive",
            "publicExponent": "unknown",
            "exponentCheck": "not_verifiable",
            "complianceImpact": "Unable to verify the ECCG RSA modulus-size and exponent requirements."
        }
    )
}

package data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization

import data.cbom.eccg.getter_helpers.get_note

import data.cbom.eccg.general_helpers.build_finding

import data.cbom.eccg.classifying_helpers.is_public_key_eccg_primitive

import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.helpers.rsa_scheme_metadata
import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.helpers.is_agreed_rsa_scheme

RSA_SECTION := "Assymetric-Atomic-Primitives"
RSA_SUBSECTION := "RSA-Integer-Factorization"

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
    
    is_public_key_eccg_primitive(component)
    not is_agreed_rsa_scheme(component)

    note := get_note(RSA, RSA_SUBSECTION, "30-LegacyRSA")

    finding := build_finding(
        "ECCG-RSA-001",
        "critical",
        message,
        component,
        object.union(
            rsa_scheme_metadata(component),
            note, 
        )
    )
}

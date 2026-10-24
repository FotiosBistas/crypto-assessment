package cbom.eccg.symmetric_constructions.key_derivation

import data.cbom.eccg.general_helpers.build_finding

import data.cbom.eccg.getter_helpers.get_note
import data.cbom.eccg.getter_helpers.get_component_name_or_empty

import data.cbom.eccg.classifying_helpers.is_kdf_primitive

import data.cbom.eccg.symmetric_constructions.key_derivation.helpers.is_kdf_scheme_metadata
import data.cbom.eccg.symmetric_constructions.key_derivation.helpers.is_agreed_kdf_scheme
import data.cbom.eccg.symmetric_constructions.key_derivation.helpers.is_pbkdf2_scheme

default compliant := true

compliant if count(findings) == 0

SECTION = "Symmetric-Constructions"
SUBSECTION = "Key-Derivation-Functions"

#
# ---------------------------------------------------------
# ECCG-KDF-001
# HKDF, PBKDF2, ANSI-X9.63-KDF, and NIST SP800-56A/B/C
# are the only recommended symmetric key derivation mechanisms.
#
# ECCG classification: non-agreed KDF usage
#
# This rule detects KDF schemes that are not one of:
# - NIST SP800-56A/B/C
# - ANSI-X9.63-KDF
# - PBKDF2
# - HKDF
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_kdf_primitive(component)
    not is_agreed_kdf_scheme(component)

    finding := build_finding(
        "ECCG-KDF-001",
        "critical",
        sprintf(
            "%s KDF scheme detected. HKDF, PBKDF2, ANSI-X9.63-KDF, and derivation methods defined in NIST SP800-56A/B/C are the only recommended symmetric key derivation mechanisms.",
            [get_component_name_or_empty(component)]
        ),
        component,
        is_kdf_scheme_metadata(component)
    )
}

#
# ---------------------------------------------------------
# ECCG-KDF-002
# With PBKDF2, HMAC is used as pseudo random function. The master
# secret length should be equal to the hash function message block length.
#
# Relevant notes:
# - Note 26 (PBKDF2-PRF)
#
# This rule detects PBKDF2 use where the master secret length is known
# and does not match the underlying hash function message block length.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_kdf_primitive(component)
    is_pbkdf2_scheme(component)

    note := get_note(SECTION, SUBSECTION, "26-PBKDF2-PRF")

    finding := build_finding(
        "ECCG-KDF-002",
        "warning",
        sprintf(
            "PBKDF2 scheme detected: %s. Ensure that the underlying pseudo-random function (PRF) is an agreed cryptographic mechanism. If HMAC is used, verify that the HMAC key length does not exceed the underlying hash function's message block length without considering the security implications. Longer keys are pre-hashed, which may reduce the effective entropy of the key derived using PBKDF2. Note that this might overlap with password-hashing, since they mostly use the same underlying primitives.",
            [get_component_name_or_empty(component)]
        ),
        component,
        object.union(
            is_kdf_scheme_metadata(component),
            {
                "notes": note
            }
        )
    )
}

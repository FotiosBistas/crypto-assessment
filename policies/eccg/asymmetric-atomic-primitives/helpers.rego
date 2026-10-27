package cbom.eccg.asymmetric_atomic_primitives.helpers

import data.cbom.eccg.classifying_helpers.is_asymmetric_algorithm
import data.cbom.eccg.classifying_helpers.is_public_key_primitive
import data.cbom.eccg.general_helpers.legacy_marker_status
import data.cbom.eccg.general_helpers.legacy_status_message
import data.cbom.eccg.general_helpers.legacy_status_severity
import data.cbom.eccg.general_helpers.normalize_crypto_identifier
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_to_number_or_negative_one
import data.cbom.eccg.getter_helpers.get_note

is_rsa_primitive(component) if {
    is_public_key_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "rsa")
} else if {
    component.cryptoProperties.assetType == "algorithm"

    props := component.cryptoProperties.algorithmProperties
    family := object.get(props, "algorithmFamily", "")
    normalized_family := normalize_crypto_identifier(family)

    contains(normalized_family, "rsa")
} else if {
    component.cryptoProperties.assetType == "algorithm"

    props := component.cryptoProperties.algorithmProperties
    primitive := lower(object.get(props, "primitive", ""))
    primitive == "signature"

    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "rsa")
} else if {
    is_asymmetric_algorithm(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "rsa")
}



RSA_SECTION := "Asymmetric-Atomic-Primitives"
RSA_SUBSECTION := "RSA-Integer-Factorization"
RSA_LEGACY_MARKER := "L[2025]"

rsa_legacy_modulus_size(n) if {
    n >= 1900
    n < 3000
}

rsa_recommended_modulus_size(n) if {
    n >= 3000
}

classify_rsa_modulus(n) = "recommended" if {
    rsa_recommended_modulus_size(n)
} else = "legacy" if {
    rsa_legacy_modulus_size(n)
} else = "not_agreed" if {
    true
}

rsa_modulus_status(n) := status if {
    rsa_legacy_modulus_size(n)
    status := legacy_marker_status(RSA_LEGACY_MARKER)
} else := "not_agreed"

rsa_modulus_severity(n) := severity if {
    rsa_legacy_modulus_size(n)
    status := legacy_marker_status(RSA_LEGACY_MARKER)
    severity := legacy_status_severity(status)
} else := "critical"

rsa_modulus_message(n, status) := message if {
    rsa_legacy_modulus_size(n)
    legacy_message := legacy_status_message("RSA modulus size", RSA_LEGACY_MARKER, status)
    message := sprintf(
        "RSA modulus size must be >=3000 bits and must satisfy log2(e) > 16. Detected n=%d bits. The public exponent condition could not be verified from CycloneDX data. %s",
        [n, legacy_message],
    )
} else := message if {
    message := sprintf(
        "RSA modulus size must be >=3000 bits and must satisfy log2(e) > 16. Detected non-agreed modulus size n=%d bits. The public exponent condition could not be verified from CycloneDX data.",
        [n],
    )
}

rsa_modulus_notes(n) := note if {
    rsa_legacy_modulus_size(n)
    note := get_note(RSA_SECTION, RSA_SUBSECTION, "30-LegacyRSA")
} else := {} if {
    true
}

#
# ---------------------------------------------------------
# Helper: is_ffdlog_primitive
#
# Purpose:
# Detect finite-field discrete logarithm (FF-DLOG) primitives
# and closely related finite-field Diffie-Hellman groups.
#
# ECCG context:
# - FF-DLOG refers to the finite-field discrete logarithm
#   hardness assumption.
# - MODP groups [RFC3526] and FFDHE groups [RFC7919] are
#   finite-field groups used by Diffie-Hellman-style schemes.
#
# Key clarification:
# - FFDHE (Finite Field Diffie-Hellman Ephemeral) operates in
#   the multiplicative group of a finite field:
#       X = g^x mod p
# - Therefore:
#       FFDHE ⇒ FF-DLOG primitive
#
# Detection strategy:
# - Prefer explicit FF-DLOG indicators when present.
# - Detect standardized group names such as:
#     • FFDH / FFDHE (CycloneDX pattern: FFDH(E)-{parameterSetIdentifier})
#     • FFDHE (including TLS named groups like ffdhe2048)
#     • MODP
# - Fall back to finite-field Diffie-Hellman naming:
#     • DH
#
# Rationale:
# CycloneDX / CBOM tools may not emit "FF-DLOG" directly.
# In practice, finite-field DH components represent usage of
# the FF-DLOG primitive/assumption.
#
# Notes:
# - This helper explicitly treats FFDH/FFDHE as FF-DLOG.
# - This helper must NOT match elliptic-curve Diffie-Hellman:
#     • ECDH, ECDHE
#     • X25519, X448
# - Name matching is normalized to tolerate formatting differences.
# ---------------------------------------------------------
#
is_ffdlog_primitive(component) if {
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)

    # Explicit FF-DLOG naming
    contains(normalized_name, "ffdlog")
} else if {
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)

    # CycloneDX FFDH family / FFDHE groups (e.g., FFDH-ffdhe3072)
    # → Direct mapping to FF-DLOG
    contains(normalized_name, "ffdh")
} else if {
    props := component.cryptoProperties.algorithmProperties

    family := object.get(props, "algorithmFamily", "")
    normalized_family := normalize_crypto_identifier(family)

    # CycloneDX cryptography registry family.
    normalized_family == "ffdh"
} else if {
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)

    # FFDHE groups (e.g., ffdhe2048, ffdhe3072)
    # → Direct mapping to FF-DLOG
    contains(normalized_name, "ffdhe")
} else if {
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)

    # MODP groups (RFC3526)
    contains(normalized_name, "modp")
} else if {
    props := component.cryptoProperties.algorithmProperties

    family := object.get(props, "algorithmFamily", "")
    normalized_family := normalize_crypto_identifier(family)

    contains(normalized_family, "ffdlog")
} else if {
    props := component.cryptoProperties.algorithmProperties

    primitive := object.get(props, "primitive", "")
    normalized_primitive := normalize_crypto_identifier(primitive)

    contains(normalized_primitive, "ffdlog")
} else if {
    #
    # Fallback: finite-field Diffie-Hellman.
    #
    # Only match DH after excluding elliptic-curve variants.
    #
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)

    not contains(normalized_name, "ecdh")
    not contains(normalized_name, "ecdhe")
    not contains(normalized_name, "x25519")
    not contains(normalized_name, "x448")

    contains(normalized_name, "dh")
} else if {
    #
    # Fallback: finite-field Diffie-Hellman.
    #
    # Only match DH after excluding elliptic-curve variants.
    #
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)

    not contains(normalized_name, "ecdh")
    not contains(normalized_name, "ecdhe")
    not contains(normalized_name, "x25519")
    not contains(normalized_name, "x448")

    contains(normalized_name, "dhe")
}

#
# ---------------------------------------------------------
# Helper: get_ffdlog_group_family_or_unknown
#
# Purpose:
# Identify whether an FF-DLOG component is one of the ECCG
# agreed standardized finite-field parameter families.
#
# ECCG agrees:
# - MODP groups from RFC3526
# - FFDHE groups from RFC7919
#
# Detection order:
# - component.name
# - algorithmProperties.algorithmFamily
# - algorithmProperties.parameterSetIdentifier, for registry-style values
#   that include the family name, such as "ffdhe3072".
# ---------------------------------------------------------
#
get_ffdlog_group_family_or_unknown(component) := "MODP" if {
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "modp")
} else := "FFDHE" if {
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "ffdhe")
} else := "MODP" if {
    props := component.cryptoProperties.algorithmProperties
    family := object.get(props, "algorithmFamily", "")
    normalized_family := normalize_crypto_identifier(family)
    contains(normalized_family, "modp")
} else := "FFDHE" if {
    props := component.cryptoProperties.algorithmProperties
    family := object.get(props, "algorithmFamily", "")
    normalized_family := normalize_crypto_identifier(family)
    contains(normalized_family, "ffdhe")
} else := "FFDHE" if {
    props := component.cryptoProperties.algorithmProperties
    family := object.get(props, "algorithmFamily", "")
    normalized_family := normalize_crypto_identifier(family)
    normalized_family == "ffdh"

    parameter_set := object.get(props, "parameterSetIdentifier", "")
    normalized_parameter_set := normalize_crypto_identifier(parameter_set)
    contains(normalized_parameter_set, "ffdhe")
} else := "MODP" if {
    props := component.cryptoProperties.algorithmProperties
    parameter_set := object.get(props, "parameterSetIdentifier", "")
    normalized_parameter_set := normalize_crypto_identifier(parameter_set)
    contains(normalized_parameter_set, "modp")
} else := "FFDHE" if {
    props := component.cryptoProperties.algorithmProperties
    parameter_set := object.get(props, "parameterSetIdentifier", "")
    normalized_parameter_set := normalize_crypto_identifier(parameter_set)
    contains(normalized_parameter_set, "ffdhe")
} else := "unknown"

is_eccg_agreed_ffdlog_group_family(component) if {
    family := get_ffdlog_group_family_or_unknown(component)
    family == "MODP"
} else if {
    family := get_ffdlog_group_family_or_unknown(component)
    family == "FFDHE"
}

#
# ---------------------------------------------------------
# Helper: get_ffdlog_group_bits_or_unknown
#
# Purpose:
# Extract the FF-DLOG group size in bits.
#
# Preferred source:
# - numeric algorithmProperties.parameterSetIdentifier
#
# Fallback:
# - known standardized group-size tokens in component.name or
#   algorithmProperties.parameterSetIdentifier, such as "ffdhe3072"
#   or "modp2048".
# ---------------------------------------------------------
#
get_ffdlog_group_bits_or_unknown(component) := bits if {
    bits := get_component_parameter_set_identifier_to_number_or_negative_one(component)
    bits != -1
} else := 2048 if {
    ffdlog_group_size_token_present(component, "2048")
} else := 3072 if {
    ffdlog_group_size_token_present(component, "3072")
} else := 4096 if {
    ffdlog_group_size_token_present(component, "4096")
} else := 6144 if {
    ffdlog_group_size_token_present(component, "6144")
} else := 8192 if {
    ffdlog_group_size_token_present(component, "8192")
} else := "unknown"

ffdlog_group_size_token_present(component, token) if {
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, token)
} else if {
    props := component.cryptoProperties.algorithmProperties
    parameter_set := object.get(props, "parameterSetIdentifier", "")
    normalized_parameter_set := normalize_crypto_identifier(parameter_set)
    contains(normalized_parameter_set, token)
}

FFDLOG_SECTION := "Asymmetric-Atomic-Primitives"
FFDLOG_SUBSECTION := "FF-DLOG"
FFDLOG_LEGACY_MARKER := "L[2025]"

ff_dlog_legacy_size(p_bits) if {
    p_bits > 1900
    p_bits < 3000
}

ff_dlog_size_status(p_bits) := status if {
    ff_dlog_legacy_size(p_bits)
    status := legacy_marker_status(FFDLOG_LEGACY_MARKER)
} else := "not_agreed"

ff_dlog_size_severity(p_bits) := severity if {
    ff_dlog_legacy_size(p_bits)
    status := legacy_marker_status(FFDLOG_LEGACY_MARKER)
    severity := legacy_status_severity(status)
} else := "critical"

ff_dlog_size_message(p_bits, status) := message if {
    ff_dlog_legacy_size(p_bits)
    legacy_message := legacy_status_message("FF-DLOG group size", FFDLOG_LEGACY_MARKER, status)
    message := sprintf(
        "MODP and FFDHE group size must be >=3072 bits. Detected p=%d bits. %s",
        [p_bits, legacy_message],
    )
} else := message if {
    message := sprintf(
        "MODP and FFDHE group size must be >=3072 bits. Detected non-agreed group size p=%d bits.",
        [p_bits],
    )
}

ff_dlog_size_notes(p_bits) := notes if {
    ff_dlog_legacy_size(p_bits)

    precomputation_note := get_note(FFDLOG_SECTION, FFDLOG_SUBSECTION, "33-Precomputation")
    legacy_note := get_note(FFDLOG_SECTION, FFDLOG_SUBSECTION, "34-LegacyFF-DLOG")

    notes := {
        "precomputation": precomputation_note,
        "legacy": legacy_note,
    }
} else := {}

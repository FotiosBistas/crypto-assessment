package cbom.eccg.asymmetric_constructions.helpers

import data.cbom.eccg.classifying_helpers.is_key_establishment_primitive

import data.cbom.eccg.general_helpers.normalize_crypto_identifier

import data.cbom.eccg.getter_helpers.get_component_algorithm_identifier_text
import data.cbom.eccg.getter_helpers.get_component_asset_type_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_primitive_or_empty

eccg_recommended_signature_scheme_display_names := [
    "RSASSA-PSS (PKCS#1 v2.1; RFC 8017, PKCS#1, ISO 9796-2)",
    "KCDSA (ISO 14888-3)",
    "Schnorr (ISO 14888-3)",
    "DSA (FIPS 186-4, ISO 14888-3)",
    "EC-KCDSA (ISO 14888-3)",
    "ECDSA / EC-DSA (FIPS 186-4, ISO 14888-3)",
    "EC-GDSA (TR-03111)",
    "EC-Schnorr (ISO 14888-3)",
    "ML-DSA (FIPS 204)",
    "XMSS (SP 800-208)",
    "LMS (SP 800-208)",
    "SLH-DSA (FIPS 205)"
]

eccg_recommended_signature_schemes := concat(", ", eccg_recommended_signature_scheme_display_names)

normalize_signature_scheme_name(name) := normalized if {
    base := normalize_crypto_identifier(name)
    no_slash := replace(base, "/", "")
    no_underscore := replace(no_slash, "_", "")
    no_hash := replace(no_underscore, "#", "")
    no_dot := replace(no_hash, ".", "")
    no_plus := replace(no_dot, "+", "")
    no_open_bracket := replace(no_plus, "[", "")
    no_close_bracket := replace(no_open_bracket, "]", "")
    no_open_brace := replace(no_close_bracket, "{", "")
    normalized := replace(no_open_brace, "}", "")
}

is_digital_signature_algorithm(component) if {
    get_component_asset_type_or_empty(component) == "algorithm"
    get_component_primitive_or_empty(component) == "signature"
} else if {
    get_component_asset_type_or_empty(component) == "algorithm"

    name := get_component_name_or_empty(component)
    normalized_name := normalize_signature_scheme_name(name)
    is_known_signature_scheme_name(normalized_name)
}

is_known_signature_scheme_name(normalized_name) if {
    is_eccg_recommended_signature_scheme_name(normalized_name)
} else if {
    is_eccg_legacy_signature_scheme_name(normalized_name)
} else if {
    normalized_name in {
        "eddsa",
        "ed25519",
        "ed448",
        "falcon",
        "gost",
        "sm2",
        "rsassa"
    }
}

is_eccg_recommended_signature_scheme(component) if {
    name := get_component_name_or_empty(component)
    normalized_name := normalize_signature_scheme_name(name)
    is_eccg_recommended_signature_scheme_name(normalized_name)
}

is_eccg_recommended_signature_scheme_name(normalized_name) if {
    normalized_name in {
        "rsassapss",
        "rsapss",
        "pss",
        "kcdsa",
        "schnorr",
        "dsa",
        "eckcdsa",
        "ecdsa",
        "ecdsaalgorithm",
        "ecgdsa",
        "ecschnorr",
        "xmss",
        "xmssmt",
        "lms",
        "hss",
        "lmshss",
        "dilithium",
        "crystalsdilithium",
        # EdDSA [RFC8032]
        "eddsa",
        "ed25519",
        "ed448",
        # RSA PKCS#1 v1.5 [RFC8017]
        "pkcs1v15",
        "rsapkcs1v15",
        "rsassapkcs1v15",
        
        # Deterministic ECDSA [FIPS186-5]
        "deterministicecdsa",
        "ecdsadeterministic",
        "rfc6979ecdsa",
    }
} else if {
    startswith(normalized_name, "rsassapss")
} else if {
    startswith(normalized_name, "rsapss")
} else if {
    startswith(normalized_name, "kcdsa")
} else if {
    startswith(normalized_name, "schnorr")
} else if {
    startswith(normalized_name, "dsa")
} else if {
    startswith(normalized_name, "eckcdsa")
} else if {
    startswith(normalized_name, "ecdsa")
} else if {
    startswith(normalized_name, "ecgdsa")
} else if {
    startswith(normalized_name, "ecschnorr")
} else if {
    startswith(normalized_name, "lms")
} else if {
    startswith(normalized_name, "mldsa")
} else if {
    startswith(normalized_name, "slhdsa")
} else if {
    startswith(normalized_name, "sphincs")
} else if {
    startswith(normalized_name, "xmss")
}

is_eccg_legacy_signature_scheme(component) if {
    name := get_component_name_or_empty(component)
    normalized_name := normalize_signature_scheme_name(name)
    is_eccg_legacy_signature_scheme_name(normalized_name)
}

is_eccg_legacy_signature_scheme_name(normalized_name) if {
    normalized_name in {
        "rsassapkcs1v15",
        "rsapkcs1v15",
        "rsapkcs115",
        "pkcs1v15",
        "pkcs1115",
        "rsassapkcs1"
    }
} else if {
    startswith(normalized_name, "rsassapkcs1v15")
} else if {
    startswith(normalized_name, "rsassapkcs1")
} else if {
    startswith(normalized_name, "rsapkcs1v15")
} else if {
    startswith(normalized_name, "rsapkcs115")
} else if {
    startswith(normalized_name, "pkcs1v15")
} else if {
    startswith(normalized_name, "pkcs1115")
}

get_eccg_canonical_signature_scheme_or_original(component) := scheme if {
    name := get_component_name_or_empty(component)
    canonical := get_eccg_canonical_signature_scheme_or_unknown(name)
    canonical != "unknown"
    scheme := canonical
} else := scheme if {
    scheme := get_component_name_or_empty(component)
}

get_eccg_canonical_signature_scheme_or_unknown(name) := "RSASSA-PSS" if {
    normalized_name := normalize_signature_scheme_name(name)
    normalized_name in {"rsassapss", "rsapss", "pss"}
} else := "RSASSA-PSS" if {
    normalized_name := normalize_signature_scheme_name(name)
    startswith(normalized_name, "rsassapss")
} else := "RSASSA-PSS" if {
    normalized_name := normalize_signature_scheme_name(name)
    startswith(normalized_name, "rsapss")
} else := "KCDSA" if {
    normalized_name := normalize_signature_scheme_name(name)
    startswith(normalized_name, "kcdsa")
} else := "EC-KCDSA" if {
    normalized_name := normalize_signature_scheme_name(name)
    startswith(normalized_name, "eckcdsa")
} else := "ECDSA / EC-DSA" if {
    normalized_name := normalize_signature_scheme_name(name)
    normalized_name in {"ecdsa", "ecdsaalgorithm"}
} else := "ECDSA / EC-DSA" if {
    normalized_name := normalize_signature_scheme_name(name)
    startswith(normalized_name, "ecdsa")
} else := "EC-GDSA" if {
    normalized_name := normalize_signature_scheme_name(name)
    startswith(normalized_name, "ecgdsa")
} else := "EC-Schnorr" if {
    normalized_name := normalize_signature_scheme_name(name)
    startswith(normalized_name, "ecschnorr")
} else := "Schnorr" if {
    normalized_name := normalize_signature_scheme_name(name)
    startswith(normalized_name, "schnorr")
} else := "DSA" if {
    normalized_name := normalize_signature_scheme_name(name)
    startswith(normalized_name, "dsa")
} else := "ML-DSA" if {
    normalized_name := normalize_signature_scheme_name(name)
    startswith(normalized_name, "mldsa")
} else := "ML-DSA" if {
    normalized_name := normalize_signature_scheme_name(name)
    normalized_name in {"dilithium", "crystalsdilithium"}
} else := "XMSS" if {
    normalized_name := normalize_signature_scheme_name(name)
    startswith(normalized_name, "xmss")
} else := "LMS" if {
    normalized_name := normalize_signature_scheme_name(name)
    normalized_name in {"lms", "hss", "lmshss"}
} else := "SLH-DSA" if {
    normalized_name := normalize_signature_scheme_name(name)
    startswith(normalized_name, "slhdsa")
} else := "SLH-DSA" if {
    normalized_name := normalize_signature_scheme_name(name)
    startswith(normalized_name, "sphincs")
} else := "RSASSA-PKCS1-v1_5" if {
    normalized_name := normalize_signature_scheme_name(name)
    is_eccg_legacy_signature_scheme_name(normalized_name)
} else := "unknown"

KEY_ESTABLISHMENT_SCHEME_DISPLAY_NAMES := [
    "DH (SP 800-56A, ISO 11770-3)",
    "DLIES-KEM (ISO 18033-2)",
    "EC-DH (SP 800-56A, ISO 11770-3)",
    "ECIES-KEM (ISO 18033-2)"
]

key_establishment_scheme_display_names := KEY_ESTABLISHMENT_SCHEME_DISPLAY_NAMES

key_establishment_scheme_display_names_text := concat(", ", KEY_ESTABLISHMENT_SCHEME_DISPLAY_NAMES)

is_key_establishment_or_key_encapsulation_scheme(component) if {
    is_key_establishment_primitive(component)
} else if {
    get_component_asset_type_or_empty(component) == "algorithm"
    scheme := get_eccg_canonical_key_establishment_scheme_or_unknown(component)
    scheme != "unknown"
}

is_eccg_agreed_key_establishment_scheme(component) if {
    scheme := get_eccg_canonical_key_establishment_scheme_or_unknown(component)
    scheme in {"DH", "DLIES-KEM", "EC-DH", "ECIES-KEM"}
}

get_eccg_canonical_key_establishment_scheme_or_unknown(component) := "DLIES-KEM" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "dlies")
} else := "ECIES-KEM" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "ecies")
} else := "ML-KEM" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "mlkem")
} else := "FrodoKEM" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "frodokem")
} else := "FrodoKEM" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "frodo")
    contains(normalized, "kem")
} else := "EC-DH" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "ecdh")
} else := "EC-DH" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "ecdhe")
} else := "EC-DH" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "ecdiffiehellman")
} else := "x25519" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "x25519")
} else := "x448" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "x448")
} else := "DH" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "ffdh")
} else := "DH" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "ffdhe")
} else := "DH" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "diffiehellman")
    not contains(normalized, "ecdiffiehellman")
} else := "DH" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    startswith(normalized, "dh")
    not contains(normalized, "ecdh")
} else := "DH" if {
    normalized := normalize_crypto_identifier(get_component_algorithm_identifier_text(component))
    contains(normalized, "dhe")
    not contains(normalized, "ecdhe")
} else := "unknown"

get_eccg_canonical_key_establishment_scheme_or_original(component) := scheme if {
    canonical := get_eccg_canonical_key_establishment_scheme_or_unknown(component)
    canonical != "unknown"
    scheme := canonical
} else := scheme if {
    scheme := get_component_name_or_empty(component)
}

get_key_establishment_scheme_display_name(component) := display_name if {
    display_name := get_eccg_canonical_key_establishment_scheme_or_original(component)
}

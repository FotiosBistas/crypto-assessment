package cbom.eccg.asymmetric_constructions.helpers

import data.cbom.eccg.helpers.normalize_crypto_name

RECOMMENDED_ASYMMETRIC_ENCRYPTION_SCHEME := "RSAES-OAEP (PKCS #1 v2.2 / RFC 8017)"
LEGACY_ASYMMETRIC_ENCRYPTION_SCHEME := "RSAES-PKCS1-v1_5 (PKCS #1 v1.5 / RFC 8017)"

#
# ---------------------------------------------------------
# Helper: normalize_asymmetric_encryption_text
#
# Purpose:
# Normalize scheme names emitted by scanners and libraries, including
# variants such as:
# - RSAES-OAEP
# - RSA/ECB/OAEPWithSHA-256AndMGF1Padding
# - PKCS1v15
# - PKCS#1 v1.5
# ---------------------------------------------------------
#
normalize_asymmetric_encryption_text(text) := normalized if {
    base := normalize_crypto_name(text)
    no_slash := replace(base, "/", "")
    no_hash := replace(no_slash, "#", "")
    no_dot := replace(no_hash, ".", "")
    normalized := replace(no_dot, "_", "")
}

asymmetric_encryption_text(component) := text if {
    props := object.get(component.cryptoProperties, "algorithmProperties", {})

    text := sprintf(
        "%v %v %v %v %v %v",
        [
            object.get(component, "name", ""),
            object.get(props, "algorithmFamily", ""),
            object.get(props, "scheme", ""),
            object.get(props, "padding", ""),
            object.get(props, "mode", ""),
            object.get(props, "parameterSetIdentifier", ""),
        ],
    )
}

normalized_asymmetric_encryption_text(component) := normalized if {
    text := asymmetric_encryption_text(component)
    normalized := normalize_asymmetric_encryption_text(text)
}

component_has_encrypt_or_decrypt_function(component) if {
    props := object.get(component.cryptoProperties, "algorithmProperties", {})
    some fn in object.get(props, "cryptoFunctions", [])

    normalized_fn := normalize_crypto_name(fn)
    normalized_fn == "encrypt"
} else if {
    props := object.get(component.cryptoProperties, "algorithmProperties", {})
    some fn in object.get(props, "cryptoFunctions", [])

    normalized_fn := normalize_crypto_name(fn)
    normalized_fn == "decrypt"
}

is_rsa_context(component) if {
    normalized := normalized_asymmetric_encryption_text(component)
    contains(normalized, "rsa")
}

is_rsaes_oaep_scheme(component) if {
    normalized := normalized_asymmetric_encryption_text(component)
    contains(normalized, "oaep")
} else if {
    normalized := normalized_asymmetric_encryption_text(component)
    contains(normalized, "rsaesoaep")
}

is_rsaes_pkcs1_v1_5_scheme(component) if {
    normalized := normalized_asymmetric_encryption_text(component)
    contains(normalized, "pkcs1v15")
} else if {
    normalized := normalized_asymmetric_encryption_text(component)
    contains(normalized, "pkcs1v1")
} else if {
    normalized := normalized_asymmetric_encryption_text(component)
    contains(normalized, "pkcs1padding")
} else if {
    normalized := normalized_asymmetric_encryption_text(component)
    contains(normalized, "rsaespkcs1")
}

is_identifiable_asymmetric_encryption_scheme(component) if {
    component.cryptoProperties.assetType == "algorithm"
    is_rsa_context(component)
    is_rsaes_oaep_scheme(component)
} else if {
    component.cryptoProperties.assetType == "algorithm"
    is_rsa_context(component)
    is_rsaes_pkcs1_v1_5_scheme(component)
} else if {
    component.cryptoProperties.assetType == "algorithm"
    component_has_encrypt_or_decrypt_function(component)
    is_rsa_context(component)
} else if {
    component.cryptoProperties.assetType == "algorithm"
    normalized := normalized_asymmetric_encryption_text(component)

    contains(normalized, "ecies")
} else if {
    component.cryptoProperties.assetType == "algorithm"
    normalized := normalized_asymmetric_encryption_text(component)

    contains(normalized, "elgamal")
}

is_unknown_rsa_encryption_scheme(component) if {
    component.cryptoProperties.assetType == "algorithm"
    component_has_encrypt_or_decrypt_function(component)
    is_rsa_context(component)
    not is_rsaes_oaep_scheme(component)
    not is_rsaes_pkcs1_v1_5_scheme(component)
}

package cbom.eccg.symmetric_constructions.key_derivation.helpers

import data.cbom.eccg.general_helpers.normalize_crypto_identifier

import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty

import data.cbom.eccg.classifying_helpers.is_kdf_primitive
import data.cbom.eccg.classifying_helpers.is_hash_primitive
import data.cbom.eccg.classifying_helpers.is_mac_primitive

import data.cbom.eccg.relationship_helpers.depends_on_component

import data.cbom.eccg.symmetric_constructions.key_derivation.constants.ANSI_X963_KDF_OID_VALUES
import data.cbom.eccg.symmetric_constructions.key_derivation.constants.ANSI_X963_KDF_FAMILIES
import data.cbom.eccg.symmetric_constructions.key_derivation.constants.NIST_SP800_56_KDF_OID_VALUES
import data.cbom.eccg.symmetric_constructions.key_derivation.constants.PBKDF2_KDF_OID_VALUES
import data.cbom.eccg.symmetric_constructions.key_derivation.constants.PBKDF2_KDF_FAMILIES
import data.cbom.eccg.symmetric_constructions.key_derivation.constants.HKDF_KDF_OID_VALUES
import data.cbom.eccg.symmetric_constructions.key_derivation.constants.HKDF_KDF_FAMILIES



is_kdf_scheme_metadata(component) := {
    "UnderlyingHashName": get_kdf_underlying_hash_name_or_empty(component),
    "UnderlyingHashSize": get_kdf_underlying_hash_parameter_size_or_empty(component),
}


# No family name in the CycloneDX specification
is_nist_sp800_scheme(component) if {
    is_kdf_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in NIST_SP800_56_KDF_OID_VALUES
} else if {
    is_kdf_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "sp80056")
}


is_ansi_x963_kdf(component) if {
    is_kdf_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in ANSI_X963_KDF_OID_VALUES
} else if {
    is_kdf_primitive(component)
    family := get_component_algorithm_family_or_empty(component)
    some known_family in ANSI_X963_KDF_FAMILIES
    family == lower(known_family)
} else if {
    is_kdf_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "ansi")
}

is_pbkdf2_scheme(component) if {
    is_kdf_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in PBKDF2_KDF_OID_VALUES
} else if {
    is_kdf_primitive(component)
    family := get_component_algorithm_family_or_empty(component)
    some known_family in PBKDF2_KDF_FAMILIES
    family == lower(known_family)
} else if {
    is_kdf_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "pbkdf2")
}

is_hkdf_scheme(component) if {
    is_kdf_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in HKDF_KDF_OID_VALUES
} else if {
    is_kdf_primitive(component)
    family := get_component_algorithm_family_or_empty(component)
    some known_family in HKDF_KDF_FAMILIES
    family == lower(known_family)
} else if {
    is_kdf_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "hkdf")
}

is_agreed_kdf_scheme(component) if {
    is_hkdf_scheme(component)
} else if {
    is_pbkdf2_scheme(component)
} else if {
    is_ansi_x963_kdf(component)
} else if {
    is_nist_sp800_scheme(component)
}

get_kdf_underlying_hash_name_or_empty(component) := hash_name if {
    # Direct KDF -> Hash dependency
    names := {name |
        some hash in input.components
        is_hash_primitive(hash)
        depends_on_component(component, hash)

        name := get_component_name_or_empty(hash)
        name != ""
    }

    count(names) == 1
    some hash_name in names

} else := hash_name if {
    # Indirect KDF -> MAC -> Hash dependency
    names := {name |
        some mac in input.components
        is_mac_primitive(mac)
        depends_on_component(component, mac)

        some hash in input.components
        is_hash_primitive(hash)
        depends_on_component(mac, hash)

        name := get_component_name_or_empty(hash)
        name != ""
    }

    count(names) == 1
    some hash_name in names

} else := hash_name if {
    # Fallback: infer from KDF name
    name := get_component_name_or_empty(component)
    normalized := normalize_crypto_identifier(name)

    hashes := {
        "SHA-1": "sha1",
        "SHA-224": "sha224",
        "SHA-256": "sha256",
        "SHA-384": "sha384",
        "SHA-512": "sha512",
        "SHA-512/224": "sha512224",
        "SHA-512/256": "sha512256",
        "SHA3-256": "sha3256",
        "SHA3-384": "sha3384",
        "SHA3-512": "sha3512"
    }

    matches := {candidate |
        some candidate, identifier in hashes
        contains(normalized, identifier)
    }

    lengths := {length |
        some candidate in matches
        length := count(hashes[candidate])
    }

    longest := max(lengths)

    some hash_name in matches
    count(hashes[hash_name]) == longest

} else := ""


get_kdf_underlying_hash_parameter_size_or_empty(component) := size if {
    hash_name := get_kdf_underlying_hash_name_or_empty(component)

    normalized := normalize_crypto_identifier(hash_name)

    hash_sizes := {
        "sha1": 160,
        "sha224": 224,
        "sha256": 256,
        "sha384": 384,
        "sha512": 512,
        "sha512224": 224,
        "sha512256": 256,
        "sha3256": 256,
        "sha3384": 384,
        "sha3512": 512
    }

    size := hash_sizes[normalized]

} else := ""



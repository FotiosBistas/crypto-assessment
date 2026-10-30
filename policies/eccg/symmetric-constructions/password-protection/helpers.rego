package cbom.eccg.symmetric_constructions.password_protection.helpers

import data.cbom.eccg.general_helpers.normalize_crypto_identifier

import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty

import data.cbom.eccg.classifying_helpers.is_kdf_primitive

import data.cbom.eccg.symmetric_constructions.password_protection.constants.ARGON2ID_PASSWORD_HASHING_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.password_protection.constants.ARGON2ID_PASSWORD_HASHING_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.password_protection.constants.PBKDF2_PASSWORD_HASHING_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.password_protection.constants.PBKDF2_PASSWORD_HASHING_SCHEME_FAMILIES

password_protection_scheme_metadata(_) := {
}


is_argon2id_scheme(component) if {
    is_kdf_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in ARGON2ID_PASSWORD_HASHING_SCHEME_OID_VALUES
} else if {
    is_kdf_primitive(component)
    family := get_component_algorithm_family_or_empty(component)
    some known_family in ARGON2ID_PASSWORD_HASHING_SCHEME_FAMILIES
    family == lower(known_family)
} else if {
    is_kdf_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "argon2")
}

is_pbkdf2_scheme(component) if {
    is_kdf_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in PBKDF2_PASSWORD_HASHING_SCHEME_OID_VALUES
} else if {
    is_kdf_primitive(component)
    family := get_component_algorithm_family_or_empty(component)
    some known_family in PBKDF2_PASSWORD_HASHING_SCHEME_FAMILIES
    family == lower(known_family)
} else if {
    is_kdf_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "pbkdf2")
}



is_agreed_password_protection_scheme(component) if {
    is_argon2id_scheme(component)
} else if {
    is_pbkdf2_scheme(component)
}


AGREED_PASSWORD_HASHING_SCHEMES := {
    PBKDF2_PASSWORD_HASHING_SCHEME_FAMILIES |
    ARGON2ID_PASSWORD_HASHING_SCHEME_FAMILIES
}

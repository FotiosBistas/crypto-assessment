package cbom.eccg.symmetric_constructions.key_protection.helpers 

import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_primitive_or_empty
import data.cbom.eccg.getter_helpers.get_component_mode_or_empty

import data.cbom.eccg.general_helpers.normalize_crypto_identifier

import data.cbom.eccg.classifying_helpers.is_key_wrap_or_ae_primitive

import data.cbom.eccg.symmetric_constructions.key_protection.constants.SIV_KEY_PROTECTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.key_protection.constants.AES_GCM_SIV_AE_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_constructions.key_protection.constants.AES_KEYWRAP_KEY_PROTECTION_SCHEME_OID_VALUES

key_protection_scheme_metadata(component) := {
    "mode": get_component_mode_or_empty(component),
    "primitive": get_component_primitive_or_empty(component),
}

is_siv_scheme(component) if {
    is_key_wrap_or_ae_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in SIV_KEY_PROTECTION_SCHEME_OID_VALUES
} else if {
    is_key_wrap_or_ae_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in AES_GCM_SIV_AE_ALGORITHM_OID_VALUES
} else if {
    is_key_wrap_or_ae_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "siv")
}

is_aeskw_scheme(component) if {
    is_key_wrap_or_ae_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in AES_KEYWRAP_KEY_PROTECTION_SCHEME_OID_VALUES
} else if {
    is_key_wrap_or_ae_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "kw")
} else if {
    is_key_wrap_or_ae_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "wrap")
}

is_agreed_key_protection_scheme(component) if {
    is_siv_scheme(component)
} else if {
    is_aeskw_scheme(component)
}

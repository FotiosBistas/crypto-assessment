package data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.helpers

import data.cbom.eccg.general_helpers.normalize_crypto_identifier

import data.cbom.eccg.classifying_helpers.is_public_key_eccg_primitive

import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty
import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_to_number_or_negative_one

import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.constants.RSA_PRIMITIVE_FAMILIES
import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.constants.RSA_PRIMITIVE_OID_VALUES
import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.constants.MINIMUM_RSA_MODULUS_LENGTH


rsa_scheme_metadata(component) := {
    "modulusBits": get_rsa_modulus_bits_or_negative_one(component),
    "minimumModulusBits": MINIMUM_RSA_MODULUS_LENGTH, 
}


is_rsa_scheme(component) if {
    is_public_key_eccg_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in RSA_PRIMITIVE_OID_VALUES
} else if {
    is_public_key_eccg_primitive(component)
    family := get_component_algorithm_family_or_empty(component)
    family in RSA_PRIMITIVE_FAMILIES
} else if {
    is_public_key_eccg_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "rsa")
}


get_rsa_modulus_bits_or_negative_one(component)  := parameter if {
    parameter := get_component_parameter_set_identifier_to_number_or_negative_one(component)
    is_number(parameter)
    parameter != -1 

    parameter > 0
} else := -1

is_agreed_rsa_scheme(component) if {
    is_rsa_scheme(component)
    modulus_bits := get_rsa_modulus_bits_or_negative_one(component)
    modulus_bits >= MINIMUM_RSA_MODULUS_LENGTH
}

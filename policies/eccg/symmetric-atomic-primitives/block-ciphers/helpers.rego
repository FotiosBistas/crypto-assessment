package cbom.eccg.symmetric_atomic_primitives.block_ciphers.helpers

import data.cbom.eccg.helpers.is_block_cipher_primitive
import data.cbom.eccg.helpers.is_block_cipher_or_ae_primitive
import data.cbom.eccg.helpers.is_ae_primitive
import data.cbom.eccg.helpers.get_mode_or_unknown
import data.cbom.eccg.helpers.get_primitive_or_unknown
import data.cbom.eccg.helpers.get_parameter_set_identifier_to_number_or_unknown
import data.cbom.eccg.helpers.get_component_oid_or_unknown
import data.cbom.eccg.helpers.get_component_algorithm_family_or_unknown
import data.cbom.eccg.helpers.normalize_crypto_identifier

import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.constants.AES_ALLOWED_KEY_SIZES
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.constants.AES_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.constants.AES_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.constants.TRIPLE_DES_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.constants.TRIPLE_DES_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.constants.MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_BLOCK_CIPHER

block_cipher_metadata(component) := {
    "primitive": get_primitive_or_unknown(component),
    # this is the max security of the algorithm not the actual key bits
    "keyBits": get_parameter_set_identifier_to_number_or_unknown(component),
    "mode": get_mode_or_unknown(component),
    "minimumRecommendedBitsForQuantumSensitiveContext": MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_BLOCK_CIPHER,
}

#
# Helper: identify AES components 
#
is_aes_component(component) if {
    is_block_cipher_or_ae_primitive(component)
    oid := get_component_oid_or_unknown(component) 
    oid in AES_ALGORITHM_OID_VALUES
} else if {
    is_block_cipher_or_ae_primitive(component)
    algorithm_family := get_component_algorithm_family_or_unknown(component) 
    algorithm_family in AES_ALGORITHM_FAMILIES
} else if {
    is_block_cipher_or_ae_primitive(component)
    algorithm_family := get_component_algorithm_family_or_unknown(component) 
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "aes")
}

#
# Helper: identify Triple-DES / 3DES
#
is_3des_component(component) if {
    is_block_cipher_primitive(component)
    oid := get_component_oid_or_unknown(component) 
    oid in TRIPLE_DES_ALGORITHM_OID_VALUES
} else if {
    is_block_cipher_primitive(component)
    algorithm_family := get_component_algorithm_family_or_unknown(component) 
    algorithm_family in TRIPLE_DES_ALGORITHM_FAMILIES
} else if {
    is_block_cipher_primitive(component)
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "3des")
} else if {
    is_block_cipher_primitive(component)
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "tripledes")
}

is_agreed_block_cipher_component(component) if {
    is_aes_component(component)
}

is_block_cipher_key_size_above_quantum_sensitive_threshold(component) if {
    is_block_cipher_or_ae_primitive(component)
    get_parameter_set_identifier_to_number_or_unknown(component) >= MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_BLOCK_CIPHER
}

is_allowed_aes_key_size(component) if {
    key_size_bits := get_parameter_set_identifier_to_number_or_unknown(component)
    key_size_bits in AES_ALLOWED_KEY_SIZES
    is_aes_component(component)
} 

package cbom.eccg.symmetric_atomic_primitives.helpers

import data.cbom.eccg.helpers.is_hash_primitive
import data.cbom.eccg.helpers.is_block_cipher_primitive
import data.cbom.eccg.helpers.get_mode_or_unknown
import data.cbom.eccg.helpers.get_primitive_or_unknown
import data.cbom.eccg.helpers.get_parameter_set_identifier_to_number_or_unknown
import data.cbom.eccg.helpers.get_component_oid_or_unknown
import data.cbom.eccg.helpers.get_component_algorithm_family_or_unknown
import data.cbom.eccg.helpers.normalize_crypto_identifier

import data.cbom.eccg.symmetric_atomic_primitives.constants.AES_ALLOWED_KEY_SIZES
import data.cbom.eccg.symmetric_atomic_primitives.constants.AES_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_atomic_primitives.constants.AES_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_atomic_primitives.constants.TRIPLE_DES_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_atomic_primitives.constants.TRIPLE_DES_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_atomic_primitives.constants.SHA1_HASH_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_atomic_primitives.constants.SHA1_HASH_ALGORITHM_OIDS
import data.cbom.eccg.symmetric_atomic_primitives.constants.SHA2_HASH_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_atomic_primitives.constants.SHA2_HASH_ALGORITHM_OIDS
import data.cbom.eccg.symmetric_atomic_primitives.constants.SHA3_HASH_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_atomic_primitives.constants.SHA3_HASH_ALGORITHM_OIDS
import data.cbom.eccg.symmetric_atomic_primitives.constants.MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_BLOCK_CIPHER
import data.cbom.eccg.symmetric_atomic_primitives.constants.MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_HASH


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
    is_block_cipher_primitive(component)
    oid := get_component_oid_or_unknown(component) 
    oid in AES_ALGORITHM_OID_VALUES
} else if {
    is_block_cipher_primitive(component)
    algorithm_family := get_component_algorithm_family_or_unknown(component) 
    algorithm_family in AES_ALGORITHM_FAMILIES
} else if {
    is_block_cipher_primitive(component)
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
    is_block_cipher_primitive(component)
    get_parameter_set_identifier_to_number_or_unknown(component) >= MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_BLOCK_CIPHER
}

is_allowed_aes_key_size(component) if {
    key_size_bits := get_parameter_set_identifier_to_number_or_unknown(component)
    key_size_bits in AES_ALLOWED_KEY_SIZES
    is_aes_component(component)
} 


hash_primitive_metadata(component) := {
    "hashBits": get_parameter_set_identifier_to_number_or_unknown(component),
    "minimumRecommendedHashBitsForQuantumSensitiveContext": MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_HASH,
}

#
# Helpers: identify SHA functions.
#
is_sha256(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_unknown(component)
    oid == SHA2_HASH_ALGORITHM_OIDS["SHA-256"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "sha256")
}


is_sha384(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_unknown(component)
    oid == SHA2_HASH_ALGORITHM_OIDS["SHA-384"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "sha384")
}

is_sha512(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_unknown(component)
    oid == SHA2_HASH_ALGORITHM_OIDS["SHA-512"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "sha512")
}

is_sha512_256(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_unknown(component)
    oid == SHA2_HASH_ALGORITHM_OIDS["SHA-512/256"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "sha512/256")
}

is_sha3_256(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_unknown(component)
    oid == SHA3_HASH_ALGORITHM_OIDS["SHA3-256"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "sha3256")
}

is_sha3_384(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_unknown(component)
    oid == SHA3_HASH_ALGORITHM_OIDS["SHA3-384"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "sha3384")
}

is_sha3_512(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_unknown(component)
    oid == SHA3_HASH_ALGORITHM_OIDS["SHA3-512"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "sha3512")
}

is_agreed_hash_component(component) if {
    is_sha256(component)
} else if {
    is_sha384(component)
} else if {
    is_sha512(component)
} else if {
    is_sha512_256(component)
} else if {
    is_sha3_256(component)
} else if {
    is_sha3_384(component)
} else if {
    is_sha3_512(component)
}

is_hash_output_size_above_quantum_sensitive_threshold(component) if {
    is_hash_primitive(component)
    get_parameter_set_identifier_to_number_or_unknown(component) >= MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_HASH
}

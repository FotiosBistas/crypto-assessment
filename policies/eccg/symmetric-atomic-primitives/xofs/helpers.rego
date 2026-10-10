package cbom.eccg.symmetric_atomic_primitives.xofs.helpers

import data.cbom.eccg.helpers.is_xof_primitive
import data.cbom.eccg.helpers.get_mode_or_unknown
import data.cbom.eccg.helpers.get_primitive_or_unknown
import data.cbom.eccg.helpers.get_parameter_set_identifier_to_number_or_unknown
import data.cbom.eccg.helpers.get_component_oid_or_unknown
import data.cbom.eccg.helpers.get_component_algorithm_family_or_unknown
import data.cbom.eccg.helpers.normalize_crypto_identifier

import data.cbom.eccg.symmetric_atomic_primitives.xofs.constants.SHAKE_XOF_ALGORITHM_OIDS
import data.cbom.eccg.symmetric_atomic_primitives.xofs.constants.CSHAKE_XOF_ALGORITHM_OIDS
import data.cbom.eccg.symmetric_atomic_primitives.xofs.constants.MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_XOF

xof_primitive_metadata(component) := {
    "xofBits": get_parameter_set_identifier_to_number_or_unknown(component),
    "minimumRecommendedXofBitsForQuantumSensitiveContext": MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_XOF,
}

is_shake256(component) if {
    is_xof_primitive(component)
    oid := get_component_oid_or_unknown(component)
    oid == SHAKE_XOF_ALGORITHM_OIDS["SHAKE256"]
} else if {
    is_xof_primitive(component)
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "shake256")
}

is_shake128(component) if {
    is_xof_primitive(component)
    oid := get_component_oid_or_unknown(component)
    oid == SHAKE_XOF_ALGORITHM_OIDS["SHAKE128"]
} else if {
    is_xof_primitive(component)
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "shake128")
}

is_cshake256(component) if {
    is_xof_primitive(component)
    oid := get_component_oid_or_unknown(component)
    oid == CSHAKE_XOF_ALGORITHM_OIDS["CSHAKE256"]
} else if {
    is_xof_primitive(component)
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "cshake256")
}

is_cshake128(component) if {
    is_xof_primitive(component)
    oid := get_component_oid_or_unknown(component)
    oid == CSHAKE_XOF_ALGORITHM_OIDS["CSHAKE128"]
} else if {
    is_xof_primitive(component)
    normalized_name := normalize_crypto_identifier(component.name)
    contains(normalized_name, "cshake128")
}


is_agreed_xof_component(component) if {
    is_shake256(component)
} else if {
    is_shake128(component)
} else if {
    is_cshake256(component)
} else if {
    is_cshake128(component)
} 

is_xof_output_size_above_quantum_sensitive_threshold(component) if {
    is_xof_primitive(component)
    get_parameter_set_identifier_to_number_or_unknown(component) >= MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_XOF
}

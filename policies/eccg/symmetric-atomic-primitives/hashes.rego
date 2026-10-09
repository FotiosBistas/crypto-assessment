package cbom.eccg.symmetric_atomic_primitives.hash_primitives

import data.cbom.eccg.helpers.is_hash_primitive
import data.cbom.eccg.helpers.get_parameter_set_identifier_to_number_or_unknown
import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.legacy_marker_status
import data.cbom.eccg.helpers.legacy_status_severity
import data.cbom.eccg.helpers.legacy_status_message
import data.cbom.eccg.helpers.evaluation_year

import data.cbom.eccg.symmetric_atomic_primitives.helpers.is_agreed_hash_component
import data.cbom.eccg.symmetric_atomic_primitives.helpers.is_hash_output_size_above_quantum_sensitive_threshold
import data.cbom.eccg.symmetric_atomic_primitives.helpers.hash_primitive_metadata

import data.cbom.eccg.symmetric_atomic_primitives.constants.AGREED_HASH_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_atomic_primitives.constants.MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_HASH

default compliant := true

compliant if count(findings) == 0

NOTE_SECTION := "Symmetric-Atomic-Primitives"
NOTE_SUBSECTION := "Hash-Functions"

#
# Rule ECCG-HASH-001
# Any hash not in the agreed list should be flagged.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_hash_primitive(component)
    not is_agreed_hash_component(component)
    finding := build_finding(
        "ECCG-HASH-001",
        "critical",
        sprintf("Hash function '%s' is not in the agreed hash function list. The agreed hash functions are the following %s.", [component.name, AGREED_HASH_ALGORITHM_NAMES]),
        component,
        hash_primitive_metadata(component),
    )
}

#
# Rule ECCG-HASH-002
# In quantum-sensitive contexts, hash output below 384 bits should be avoided.
# parameterSetIdentifier is not the actual hashSize but the maximum security bits
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_agreed_hash_component(component)
    not is_hash_output_size_above_quantum_sensitive_threshold(component)
    note := get_note(NOTE_SECTION, NOTE_SUBSECTION, "4-QuantumThreat")

    finding := build_finding(
        "ECCG-HASH-002",
        "medium",
        sprintf(
            "Hash function '%s' has output length %v bits, which is below the recommended %d bits for quantum-sensitive contexts",
            [component.name, get_parameter_set_identifier_to_number_or_unknown(component), MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_HASH]
        ),
        component,
        object.union(
            hash_primitive_metadata(component),
            {
                "notes": note,
            }
        )
    )
}


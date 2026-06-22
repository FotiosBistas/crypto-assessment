package cbom.eccg.asymmetric_atomic_primitives.ff_dlog

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.evaluation_year

import data.cbom.eccg.asymmetric_atomic_primitives.helpers.FFDLOG_LEGACY_MARKER
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.ff_dlog_size_message
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.ff_dlog_size_notes
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.ff_dlog_size_severity
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.ff_dlog_size_status
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.get_ffdlog_group_bits_or_unknown
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.get_ffdlog_group_family_or_unknown
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.is_eccg_agreed_ffdlog_group_family
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.is_ffdlog_primitive

#
# ---------------------------------------------------------
# ECCG-FFDLOG-001
# MODP (RFC3526) and FFDHE (RFC7919) are the only recommended
# finite-field discrete logarithm parameter families.
#
# This rule flags FF-DLOG components that are not identifiable as
# MODP or FFDHE. Generic finite-field DH parameters may be valid in
# other contexts, but they are not among the ECCG recommended
# FF-DLOG parameter families from the table.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_ffdlog_primitive(component)
    not is_eccg_agreed_ffdlog_group_family(component)

    finding := build_finding(
        "ECCG-FFDLOG-001",
        "critical",
        sprintf(
            "FF-DLOG primitive '%s' is not identifiable as an agreed MODP (RFC3526) or FFDHE (RFC7919) group.",
            [component.name],
        ),
        component,
        {
            "scheme": "FF-DLOG",
            "groupFamily": get_ffdlog_group_family_or_unknown(component),
            "status": "not_agreed",
            "classification": "non_compliant",
            "allowedFamilies": ["MODP (RFC3526)", "FFDHE (RFC7919)"],
            "complianceImpact": "MODP (RFC3526) and FFDHE (RFC7919) are the only ECCG recommended finite-field discrete logarithm parameter families.",
        },
    )
}

#
# ---------------------------------------------------------
# ECCG-FFDLOG-002
# MODP (RFC3526) and FFDHE (RFC7919) group size must be >= 3072 bits.
#
# ECCG classification:
# - R for 3072, 4096, 6144, and 8192-bit MODP/FFDHE groups
# - L[2025] for the 2048-bit MODP/FFDHE groups
#
# Applies to:
# - 2048-bit MODP Group
# - 2048-bit FFDHE Group
#
# ECCG notes:
# - 33-Precomputation
# - 34-LegacyFF-DLOG
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_ffdlog_primitive(component)
    is_eccg_agreed_ffdlog_group_family(component)

    p_bits := get_ffdlog_group_bits_or_unknown(component)
    p_bits != "unknown"
    p_bits < 3072

    status := ff_dlog_size_status(p_bits)
    severity := ff_dlog_size_severity(p_bits)
    message := ff_dlog_size_message(p_bits, status)
    notes := ff_dlog_size_notes(p_bits)

    finding := build_finding(
        "ECCG-FFDLOG-002",
        severity,
        message,
        component,
        {
            "scheme": "FF-DLOG",
            "groupFamily": get_ffdlog_group_family_or_unknown(component),
            "groupBits": p_bits,
            "minimumGroupBits": 3072,
            "status": status,
            "legacyMarker": FFDLOG_LEGACY_MARKER,
            "evaluationYear": evaluation_year,
            "classification": "non_compliant",
            "subgroupCondition": "r = q = (p - 1) / 2",
            "notes": notes,
        },
    )
}

#
# ---------------------------------------------------------
# ECCG-FFDLOG-002
# MODP/FFDHE group size could not be determined.
#
# The size requirement cannot be verified without a group-size
# value. This usually means the CBOM should be enriched with a
# numeric parameterSetIdentifier or a standardized group name such
# as ffdhe3072 or modp3072.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_ffdlog_primitive(component)
    is_eccg_agreed_ffdlog_group_family(component)

    p_bits := get_ffdlog_group_bits_or_unknown(component)
    p_bits == "unknown"

    finding := build_finding(
        "ECCG-FFDLOG-002",
        "warning",
        "MODP and FFDHE group size must be >=3072 bits, but the group size could not be determined from the CBOM.",
        component,
        {
            "scheme": "FF-DLOG",
            "groupFamily": get_ffdlog_group_family_or_unknown(component),
            "groupBits": "unknown",
            "minimumGroupBits": 3072,
            "status": "unknown",
            "classification": "inconclusive",
            "subgroupCondition": "r = q = (p - 1) / 2",
            "complianceImpact": "Unable to verify the ECCG FF-DLOG group-size requirement.",
        },
    )
}

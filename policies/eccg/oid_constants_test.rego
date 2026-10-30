package cbom.eccg.oid_constants_test

import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants as ff_constants
import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.oid_constants.NO_OID
import data.cbom.eccg.symmetric_atomic_primitives.xofs.constants as xof_constants
import data.cbom.eccg.symmetric_atomic_primitives.xofs.helpers as xofs

xof_component(name) := {
	"name": name,
	"cryptoProperties": {
		"assetType": "algorithm",
		"algorithmProperties": {"primitive": "xof"},
	},
}

with_oid(asset, oid) := object.union(asset, {
	"cryptoProperties": object.union(asset.cryptoProperties, {"oid": oid}),
})

test_placeholder_cannot_match_oid_getter_output if {
	get_component_oid_or_empty({}) != NO_OID
	every oid in [NO_OID, trim_space(NO_OID), "", " \t\n", null, 123, true, [], {}, "1.2.3.4"] {
		get_component_oid_or_empty(with_oid(xof_component("unknown"), oid)) != NO_OID
	}
}

test_unknown_xof_is_not_cshake_without_a_verified_oid if {
	asset := xof_component("unknown")
	not xofs.is_cshake128(asset)
	not xofs.is_cshake256(asset)
	every oid in [NO_OID, trim_space(NO_OID), "", " \t\n", null, 123, true, [], {}, "1.2.3.4"] {
		candidate := with_oid(asset, oid)
		not xofs.is_cshake128(candidate)
		not xofs.is_cshake256(candidate)
	}
}

test_cshake_name_fallback_without_oid if {
	xofs.is_cshake128(xof_component("cSHAKE128"))
	xofs.is_cshake256(xof_component("cSHAKE256"))
	not xofs.is_cshake256(xof_component("cSHAKE128"))
	not xofs.is_cshake128(xof_component("cSHAKE256"))
	every oid in [NO_OID, "", null, "1.2.3.4"] {
		xofs.is_cshake128(with_oid(xof_component("cSHAKE128"), oid))
		xofs.is_cshake256(with_oid(xof_component("cSHAKE256"), oid))
	}
}

test_shake_oid_detection_without_name if {
	asset := xof_component("unknown")
	xofs.is_shake128(with_oid(asset, "2.16.840.1.101.3.4.2.11"))
	xofs.is_shake256(with_oid(asset, "2.16.840.1.101.3.4.2.12"))
}

# Synthetic OIDs verify that both existing detection branches remain usable
# when verified OIDs replace the placeholders in the table.
test_cshake_oid_detection_is_preserved if {
	oids := {"CSHAKE128": "1.2.3.128", "CSHAKE256": "1.2.3.256"}
	asset128 := with_oid(xof_component("unknown"), oids.CSHAKE128)
	asset256 := with_oid(xof_component("unknown"), oids.CSHAKE256)
	xofs.is_cshake128(asset128) with xof_constants.CSHAKE_XOF_ALGORITHM_OIDS as oids
	xofs.is_cshake256(asset256) with xof_constants.CSHAKE_XOF_ALGORITHM_OIDS as oids
	not xofs.is_cshake128(asset256) with xof_constants.CSHAKE_XOF_ALGORITHM_OIDS as oids
	not xofs.is_cshake256(asset128) with xof_constants.CSHAKE_XOF_ALGORITHM_OIDS as oids
}

test_unassigned_finite_field_oids_remain_excluded if {
	ff_constants.MODP_FF_DLOG_SCHEME_OID_VALUES == set()
	ff_constants.FFDHE_FF_DLOG_SCHEME_OID_VALUES == set()
}

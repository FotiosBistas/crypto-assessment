package cbom.eccg.getter_helpers_test

import data.cbom.eccg.getter_helpers.get_ec_curve_from_text_or_empty
import data.cbom.eccg.getter_helpers.get_ec_curve_or_empty

ec_component(name, properties) := {
	"name": name,
	"cryptoProperties": {
		"assetType": "algorithm",
		"algorithmProperties": properties,
	},
}

test_ec_text_recognizes_curve_aliases_and_embedded_names if {
	every text, expected in {
		"ECDH-brainpool/brainpoolP256r1": "BrainpoolP256r1",
		"brainpool/brainpoolP384r1": "BrainpoolP384r1",
		"BRAINPOOLP512R1": "BrainpoolP512r1",
		"ECDH-anssi/FRP256v1": "FRP256v1",
		"ECDSA-P-256": "NIST P-256",
		"ECDH-P-384": "NIST P-384",
		"ECDSA-P-521": "NIST P-521",
		"NIST_p-256": "NIST P-256",
		"nist/P-384": "NIST P-384",
		"secp521r1": "NIST P-521",
		"secg/secp256r1": "NIST P-256",
		"secg/secp384r1": "NIST P-384",
		"x962/prime256v1": "NIST P-256",
		"ECDSA (P-256), SHA-256": "NIST P-256",
		"Curve25519": "Curve25519",
		"other/Curve448": "Curve448",
		"X25519": "X25519",
		"ECDH-X448": "X448",
		"Edwards25519": "Ed25519",
		"EdDSA-Edwards448": "Ed448",
		"other/Ed25519": "Ed25519",
		"Ed448": "Ed448",
	} {
		get_ec_curve_from_text_or_empty(text) == expected
	}
}

test_ec_text_preserves_recognized_non_agreed_curves if {
	every text, expected in {
		"ECDH-secp256k1": "secp256k1",
		"ECDH-secp224r1": "secp224r1",
		"ECDSA-nist/P-192": "secp192r1",
		"ECDSA-P-224": "secp224r1",
		"ECDH-brainpoolP160r1": "BrainpoolP160r1",
		"ECDH-brainpoolP256t1": "BrainpoolP256t1",
		"EC-NIST B-283": "NIST B-283",
		"EC-NIST K-283": "NIST K-283",
		"EC-SM2": "SM2",
	} {
		get_ec_curve_from_text_or_empty(text) == expected
	}
}

test_ec_text_rejects_partial_identifier_matches if {
	every text in [
		"secp256r10", "notsecp256r1", "secp256r1suffix", "NIST-P-2560",
		"Curve255190", "X4480", "Ed255190", "Edwards4480", "SM20",
		"brainpoolP256r10", "notbrainpoolP256r1", "FRP256v10",
	] {
		get_ec_curve_from_text_or_empty(text) == ""
	}
}

test_ec_text_rejects_ambiguous_curves_in_either_order if {
	every text in [
		"ECDH-secp256k1-NIST-P-256", "ECDH-NIST-P-256-secp256k1",
		"ECDSA-P-256/P-384", "ECDSA-P-384/P-256",
		"ECDH-brainpoolP256t1-brainpoolP256r1",
		"EdDSA-Edwards25519-Edwards448", "X25519-X448",
	] {
		get_ec_curve_from_text_or_empty(text) == ""
	}
}

test_ec_text_deduplicates_aliases_for_the_same_curve if {
	get_ec_curve_from_text_or_empty("ECDH-NIST-P-256-secp256r1-prime256v1") == "NIST P-256"
	get_ec_curve_from_text_or_empty("EdDSA-Edwards25519-Ed25519") == "Ed25519"
}

test_ec_text_missing_or_invalid_input_returns_empty if {
	every text in ["", "ECDH", "custom-curve", "256", null, 256, true, [], {}] {
		get_ec_curve_from_text_or_empty(text) == ""
	}
}

test_ec_curve_uses_parameter_set_before_name if {
	every parameter, expected in {
		"nist/P-256": "NIST P-256",
		"ECDSA-P-384": "NIST P-384",
		"Edwards25519": "Ed25519",
		"secp224r1": "secp224r1",
		"brainpoolP256t1": "BrainpoolP256t1",
	} {
		asset := ec_component("ECDH-P-521", {"parameterSetIdentifier": parameter})
		get_ec_curve_or_empty(asset) == expected
	}
}

test_ec_curve_preserves_explicit_curve_precedence if {
	asset := ec_component("ECDH-P-521", {"ellipticCurve": "secp256k1", "parameterSetIdentifier": "nist/P-256"})
	get_ec_curve_or_empty(asset) == "secp256k1"
	ambiguous := ec_component("ECDH-P-521", {"ellipticCurve": "nist/P-256", "parameterSetIdentifier": "P-256/P-384"})
	get_ec_curve_or_empty(ambiguous) == "nist/P-256"
}

test_ec_curve_ambiguous_parameter_does_not_fall_back_to_name if {
	asset := ec_component("ECDH-P-521", {"parameterSetIdentifier": "secp256k1/P-256"})
	get_ec_curve_or_empty(asset) == ""
}

test_ec_curve_non_curve_parameters_fall_back_to_name if {
	every parameter in ["", "256", "unknown", null, 256, true, [], {}] {
		asset := ec_component("ECDH-P-256", {"parameterSetIdentifier": parameter})
		get_ec_curve_or_empty(asset) == "NIST P-256"
	}
	get_ec_curve_or_empty(ec_component("ECDH-P-256", {})) == "NIST P-256"
	get_ec_curve_or_empty({}) == ""
}

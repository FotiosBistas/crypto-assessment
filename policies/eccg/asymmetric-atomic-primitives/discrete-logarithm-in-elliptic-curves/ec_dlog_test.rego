package cbom.eccg.asymmetric_atomic_primitives.ec_dlog_test

import data.cbom.eccg.asymmetric_atomic_primitives.ec_dlog.findings
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.get_eccg_canonical_ec_curve_or_empty
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.get_eccg_ec_curve_family_or_empty
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.get_ecdlog_curve_or_empty
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.is_ecdlog_primitive
import data.cbom.eccg.compliant as assessment_compliant
import data.cbom.eccg.findings as all_findings

# Use a valid key-agreement primitive unless a case supplies another category.
component(name, properties) := {
	"name": name,
	"bom-ref": "ec-test-component",
	"cryptoProperties": {
		"assetType": "algorithm",
		"algorithmProperties": object.union({"primitive": "key-agree"}, properties),
	},
}

with_oid(asset, oid) := object.union(asset, {
	"cryptoProperties": object.union(asset.cryptoProperties, {"oid": oid}),
})

curve_findings(asset) := result if {
	all := findings with input as {"components": [asset]}
	result := {finding |
		some finding in all
		finding.ruleId == "ECCG-ECDLOG-001"
	}
}

only_curve_finding(asset) := finding if {
	result := curve_findings(asset)
	count(result) == 1
	some finding in result
}

test_recommended_curves_and_aliases_are_allowed if {
	every curve in [
		"BrainpoolP256r1", "BrainpoolP384r1", "BrainpoolP512r1",
		"brainpool/brainpoolP256r1", "brainpool/brainpoolP384r1", "brainpool/brainpoolP512r1",
		"NIST P-256", "NIST P-384", "NIST P-521",
		"nist/P-256", "nist/P-384", "nist/P-521", "P-256", "P-384", "P-521",
		"secg/secp256r1", "secg/secp384r1", "secg/secp521r1",
		"secp256r1", "secp384r1", "secp521r1", "x962/prime256v1", "prime256v1",
		"FRP256v1", "anssi/FRP256v1", " NIST_p-256 ", "BRAINPOOLP512R1",
		"Curve25519", "other/Curve25519", "Curve448", "other/Curve448",
		"X25519", "X448", "Ed25519", "other/Ed25519", "Ed448", "other/Ed448",
		"Edwards25519", "Edwards448", " OTHER/ed25519 ",
	] {
		count(curve_findings(component("ECDH", {"ellipticCurve": curve}))) == 0
	}
}

test_curves_outside_the_allowlist_are_rejected if {
	every curve in [
		"secp256k1", "secg/secp256k1", "nist/P-192", "nist/P-224", "nist/B-283", "nist/K-283",
		"brainpoolP256t1", "brainpoolP160r1", "SM2", "unknown", "custom-curve",
		"Curve25519-extra", "Curve448-extra", "Ed25519-extra", "Ed448-extra",
		"secp256r1-extra", "brainpoolP256r1-extra",
	] {
		finding := only_curve_finding(component("ECDH", {"ellipticCurve": curve}))
		finding.severity == "critical"
		finding.classification == "non_compliant"
		finding.status == "not_agreed"
		finding.decision == "reject"
		finding.curve == curve
		{allowed | some allowed in finding.allowedCurves} == {
			"BrainpoolP256r1", "BrainpoolP384r1", "BrainpoolP512r1",
			"NIST P-256", "NIST P-384", "NIST P-521", "FRP256v1",
			"Curve25519", "Curve448",
		}
	}
}

test_missing_or_invalid_curve_data_is_inconclusive if {
	every curve in ["", null, 256, true, [], {}] {
		finding := only_curve_finding(component("ECDH", {"ellipticCurve": curve}))
		finding.severity == "warning"
		finding.classification == "inconclusive"
		finding.status == "unknown"
		finding.curve == ""
	}

	finding := only_curve_finding(component("ECDSA", {"primitive": "signature"}))
	finding.classification == "inconclusive"
}

test_explicit_curve_takes_precedence_over_component_name if {
	finding := only_curve_finding(component("ECDH-nist/P-256", {"ellipticCurve": "secp256k1"}))
	finding.curve == "secp256k1"
	finding.classification == "non_compliant"
	count(curve_findings(component("ECDH-secp256k1", {"ellipticCurve": "nist/P-256"}))) == 0
}

test_curve_name_fallback_uses_shared_getter if {
	every name in ["ECDH-BrainpoolP256r1", "ECDSA-nist/P-384", "ECDH-FRP256v1", "X25519", "X448", "Ed25519", "Ed448"] {
		count(curve_findings(component(name, {}))) == 0
	}
	every name in ["ECDH-secp256k1", "ECDSA-secp256k1"] {
		finding := only_curve_finding(component(name, {}))
		finding.classification == "non_compliant"
	}
}

test_family_classification_without_a_recognized_name if {
	finding := only_curve_finding(component("custom name", {"algorithmFamily": "ECDH", "ellipticCurve": "secp256k1"}))
	finding.classification == "non_compliant"
	every family in ["EC-DLOG", "ECDH", "ECDHE", "ECDSA", "EdDSA", "ECIES"] {
		missing_curve := only_curve_finding(component("custom name", {"algorithmFamily": family}))
		missing_curve.classification == "inconclusive"
	}
}

test_oid_classification_without_recognized_family_or_name if {
	every oid in [
		"1.2.840.10045.2.1", "1.3.132.1.12", "1.3.132.1.13",
		"1.2.840.10045.4.1", "1.2.840.10045.4.3.1", "1.2.840.10045.4.3.2",
		"1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4",
		"1.3.101.110", "1.3.101.111", "1.3.101.112", "1.3.101.113",
	] {
		asset := with_oid(component("custom name", {"algorithmFamily": "custom family", "ellipticCurve": "secp256k1"}), oid)
		finding := only_curve_finding(asset)
		finding.classification == "non_compliant"
	}
}

test_generic_ec_oid_does_not_imply_an_agreed_curve if {
	asset := with_oid(component("custom name", {}), "1.2.840.10045.2.1")
	finding := only_curve_finding(asset)
	finding.classification == "inconclusive"
	finding.curve == ""
}

test_family_fallback_for_missing_unknown_or_invalid_oid if {
	every oid in ["", "1.2.3.4.5", null, 123, true, [], {}] {
		asset := with_oid(component("custom name", {"algorithmFamily": "ec_dsa", "ellipticCurve": "secp256k1"}), oid)
		finding := only_curve_finding(asset)
		finding.classification == "non_compliant"
	}
	asset_without_name := object.remove(component("", {"algorithmFamily": "ECDH", "ellipticCurve": "secp256k1"}), {"name"})
	finding := only_curve_finding(asset_without_name)
	finding.classification == "non_compliant"
}

test_name_fallback_for_unknown_oid_and_family if {
	every name in [
		"EC-DLOG", "ECDH", "ECDHE", "ECMQV", "ECDSA", "EdDSA", "ECIES", "EC-ElGamal",
		"X25519", "X448", "Ed25519", "Ed448", "SHA256withECDSA", "ECDSAwithSHA384",
		"ECDH-secp256k1", "ECDSA_SHA256", "ECDSA/secp256k1", " ecdsa ",
	] {
		asset := with_oid(component(name, {"algorithmFamily": "custom family", "ellipticCurve": "secp256k1"}), "1.2.3.4.5")
		finding := only_curve_finding(asset)
		finding.classification == "non_compliant"
	}
}

test_curve_and_primitive_metadata_do_not_replace_algorithm_classification if {
	every properties in [
		{"ellipticCurve": "secp256k1"},
		{"ellipticCurve": "nist/P-256"},
		{"primitive": "EC-DLOG"},
		{"primitive": "key-agree", "ellipticCurve": "secp256k1"},
	] {
		result := findings with input as {"components": [component("custom name", properties)]}
		count(result) == 0
	}
}

test_partial_identifier_matches_and_non_crypto_assets_are_excluded if {
	every name in ["notECDSA", "myECDHprovider", "ECDSAish", "X4480", "prefix-ECIES"] {
		count(curve_findings(component(name, {}))) == 0
	}
	every asset in [
		{"name": "ECDH", "type": "library"},
		{"name": "ECDH", "cryptoProperties": {"assetType": "protocol", "oid": "1.2.840.10045.2.1"}},
	] {
		count(curve_findings(asset)) == 0
	}
}

test_unrelated_components_have_no_ec_curve_findings if {
	every name in ["RSA", "DH", "FFDHE", "DSA", "ML-KEM", "AES", "SHA-256"] {
		count(curve_findings(component(name, {}))) == 0
	}
	empty_result := findings with input as {}
	count(empty_result) == 0
}

test_nist_special_p_note_is_preserved if {
	result := findings with input as {"components": [component("ECDH", {"ellipticCurve": "secg/secp256r1"})]}
	count(result) == 1
	some finding in result
	finding.ruleId == "ECCG-ECDLOG-002"
	finding.severity == "info"
	finding.curve == "NIST P-256"
	finding.note.title == "Special P"
}

test_curve_violation_reaches_the_top_level if {
	assets := [component("ECDH", {"ellipticCurve": "secp256k1"})]
	result := all_findings with input as {"components": assets}
	violations := {finding |
		some finding in result
		finding.ruleId == "ECCG-ECDLOG-001"
	}
	count(violations) == 1
	some finding in violations
	finding.section == "Asymmetric Atomic Primitives"
	finding.subsection == "EC DLOG"
	finding.bomRef == "ec-test-component"
	finding.classification == "non_compliant"
	compliant := assessment_compliant with input as {"components": assets}
	compliant == false
}

test_edwards_identifiers_map_to_the_table_entries if {
	every canonical, names in {
		"Curve25519": ["Curve25519", "other/Curve25519", "X25519", "Ed25519", "other/Ed25519", "Edwards25519"],
		"Curve448": ["Curve448", "other/Curve448", "X448", "Ed448", "other/Ed448", "Edwards448"],
	} {
		every name in names {
			get_eccg_canonical_ec_curve_or_empty(name) == canonical
			get_eccg_ec_curve_family_or_empty(name) == "Edwards [RFC7748]"
			count(curve_findings(component(name, {}))) == 0
		}
	}
}

test_edwards_curve_is_resolved_from_oid_or_family if {
	every case in [
		{"oid": "1.3.101.110", "family": "X25519", "curve": "Curve25519"},
		{"oid": "1.3.101.111", "family": "X448", "curve": "Curve448"},
		{"oid": "1.3.101.112", "family": "Ed25519", "curve": "Curve25519"},
		{"oid": "1.3.101.113", "family": "Ed448", "curve": "Curve448"},
	] {
		by_oid := with_oid(component("custom name", {}), case.oid)
		get_ecdlog_curve_or_empty(by_oid) == case.curve
		count(curve_findings(by_oid)) == 0
		by_family := component("custom name", {"algorithmFamily": case.family})
		get_ecdlog_curve_or_empty(by_family) == case.curve
		count(curve_findings(by_family)) == 0
	}
}

test_edwards_curve_evidence_precedence if {
	asset := with_oid(component("Ed448", {"algorithmFamily": "Ed448"}), "1.3.101.112")
	get_ecdlog_curve_or_empty(asset) == "Curve25519"
	get_ecdlog_curve_or_empty(component("Ed448", {"algorithmFamily": "Ed25519"})) == "Curve25519"

	explicit := with_oid(component("Ed25519", {"algorithmFamily": "Ed25519", "ellipticCurve": "secp256k1"}), "1.3.101.112")
	finding := only_curve_finding(explicit)
	finding.classification == "non_compliant"
	finding.curve == "secp256k1"
}

test_supported_primitive_categories_use_oid_family_then_name if {
	every case in [
		{"primitive": "pke", "name": "ECIES"},
		{"primitive": "signature", "name": "ECDSA"},
		{"primitive": "signature", "name": "Ed25519"},
		{"primitive": "key-agree", "name": "ECDH"},
		{"primitive": "key-agree", "name": "X25519"},
		{"primitive": "kem", "name": "ECDH"},
	] {
		by_oid := with_oid(component("custom name", {
			"primitive": case.primitive,
			"ellipticCurve": "secp256k1",
		}), "1.2.840.10045.2.1")
		by_family := component("custom name", {
			"primitive": case.primitive,
			"algorithmFamily": case.name,
			"ellipticCurve": "secp256k1",
		})
		by_name := component(case.name, {
			"primitive": case.primitive,
			"ellipticCurve": "secp256k1",
		})
		every asset in [by_oid, by_family, by_name] {
			is_ecdlog_primitive(asset)
			finding := only_curve_finding(asset)
			finding.classification == "non_compliant"
		}
	}
}

test_non_ec_algorithms_in_supported_categories_are_excluded if {
	every case in [
		{"primitive": "pke", "name": "RSA"},
		{"primitive": "signature", "name": "RSA"},
		{"primitive": "signature", "name": "DSA"},
		{"primitive": "key-agree", "name": "FFDHE"},
		{"primitive": "kem", "name": "ML-KEM"},
	] {
		asset := component(case.name, {"primitive": case.primitive, "algorithmFamily": case.name})
		not is_ecdlog_primitive(asset)
		count(curve_findings(asset)) == 0
	}
}

test_unrelated_or_invalid_primitives_override_ec_identifier_evidence if {
	every primitive in [
		"drbg", "mac", "block-cipher", "stream-cipher", "hash", "xof",
		"kdf", "ae", "combiner", "key-wrap", "other", "unknown",
		"EC-DLOG", "", null, 256, true, [], {},
	] {
		asset := with_oid(component("ECDSA", {
			"primitive": primitive,
			"algorithmFamily": "ECDSA",
			"ellipticCurve": "secp256k1",
			"cryptoFunctions": ["sign"],
		}), "1.2.840.10045.2.1")
		not is_ecdlog_primitive(asset)
		result := findings with input as {"components": [asset]}
		count(result) == 0
	}
}

test_missing_primitive_does_not_pass_the_candidate_check if {
	missing_primitive := {
		"name": "ECDSA",
		"cryptoProperties": {
			"assetType": "algorithm",
			"oid": "1.2.840.10045.2.1",
			"algorithmProperties": {"algorithmFamily": "ECDSA", "ellipticCurve": "secp256k1"},
		},
	}
	not is_ecdlog_primitive(missing_primitive)
	result := findings with input as {"components": [missing_primitive]}
	count(result) == 0
}

test_name_extraction_distinguishes_non_agreed_and_unknown_curves if {
	every name in ["ECDH-secp224r1", "ECDH-brainpoolP256t1"] {
		finding := only_curve_finding(component(name, {}))
		finding.classification == "non_compliant"
	}
	every name in ["ECDH-secp256r10", "ECDH-Curve255190", "ECDH-secp256k1-NIST-P-256"] {
		finding := only_curve_finding(component(name, {}))
		finding.classification == "inconclusive"
		finding.curve == ""
	}
	every name in ["ECDSA-P-256", "ECDH-P-384", "ECDSA-P-521", "EdDSA-Edwards25519"] {
		asset := component(name, {})
		is_ecdlog_primitive(asset)
		get_ecdlog_curve_or_empty(asset) != ""
		count(curve_findings(asset)) == 0
	}
}

test_parameter_set_curves_are_enforced_before_component_names if {
	invalid := only_curve_finding(component("ECDH-P-256", {"parameterSetIdentifier": "secp224r1"}))
	invalid.classification == "non_compliant"
	invalid.curve == "secp224r1"

	ambiguous := only_curve_finding(component("ECDH-P-256", {"parameterSetIdentifier": "secp256k1/P-384"}))
	ambiguous.classification == "inconclusive"
	ambiguous.curve == ""

	approved := component("ECDH-secp256k1", {"parameterSetIdentifier": "nist/P-256"})
	get_ecdlog_curve_or_empty(approved) == "NIST P-256"
	count(curve_findings(approved)) == 0
}

test_edwards_curve_inference_does_not_hide_parameter_sets if {
	every asset in [
		component("Ed25519", {"parameterSetIdentifier": "secp256k1/P-384"}),
		component("custom name", {"algorithmFamily": "Ed25519", "parameterSetIdentifier": "secp256k1/P-384"}),
		with_oid(component("custom name", {"parameterSetIdentifier": "secp256k1/P-384"}), "1.3.101.112"),
	] {
		finding := only_curve_finding(asset)
		finding.classification == "inconclusive"
		finding.curve == ""
	}

	explicit_parameter := with_oid(component("Ed25519", {"parameterSetIdentifier": "secp224r1"}), "1.3.101.112")
	finding := only_curve_finding(explicit_parameter)
	finding.classification == "non_compliant"
	finding.curve == "secp224r1"
}

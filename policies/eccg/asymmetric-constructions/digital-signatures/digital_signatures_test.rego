package cbom.eccg.asymmetric_constructions.digital_signatures_test

import data.cbom.eccg.asymmetric_constructions.digital_signatures.compliant
import data.cbom.eccg.asymmetric_constructions.digital_signatures.findings
import data.cbom.eccg.asymmetric_constructions.digital_signatures.helpers.get_digital_signature_scheme_or_empty as scheme
import data.cbom.eccg.asymmetric_constructions.digital_signatures.helpers.is_digital_signature_component
import data.cbom.eccg.findings as all_findings

component(name, family, oid) := {
	"name": name,
	"bom-ref": "signature-test",
	"cryptoProperties": {
		"assetType": "algorithm",
		"oid": oid,
		"algorithmProperties": {"primitive": "signature", "algorithmFamily": family},
	},
}

with_properties(asset, properties) := object.union(asset, {"cryptoProperties": object.union(asset.cryptoProperties, {"algorithmProperties": object.union(asset.cryptoProperties.algorithmProperties, properties)})})

test_every_table_scheme_is_agreed_by_family_and_name if {
	every name in ["RSASSA-PSS", "KCDSA", "Schnorr", "DSA", "EC-KCDSA", "ECDSA", "EC-GDSA", "EC-Schnorr", "Deterministic ECDSA", "EdDSA", "ML-DSA", "XMSS", "LMS", "SLH-DSA", "RSASSA-PKCS1-v1_5"] {
		by_name := component(name, "", "")
		by_family := component("custom", name, "")
		scheme(by_name) == name
		scheme(by_family) == name
		findings == set() with input as {"components": [by_name, by_family]}
	}
}

test_signature_oids_override_family_and_name if {
	every case in [
		["1.2.840.113549.1.1.10", "RSASSA-PSS"],
		["1.2.840.113549.1.1.11", "RSASSA-PKCS1-v1_5"],
		["1.2.840.10040.4.3", "DSA"],
		["1.2.840.10045.4.3.2", "ECDSA"],
		["1.3.101.112", "EdDSA"],
		["1.3.101.113", "EdDSA"],
		["1.2.840.113549.1.9.16.3.17", "LMS"],
		["2.16.840.1.101.3.4.3.18", "ML-DSA"],
		["2.16.840.1.101.3.4.3.29", "SLH-DSA"],
	] {
		asset := component("Falcon", "SM2", case[0])
		scheme(asset) == case[1]
		findings == set() with input as {"components": [asset]}
	}
}

test_family_overrides_name_when_oid_is_unknown_or_malformed if {
	every oid in ["", "1.2.3.4.5", "not-an-oid", null, 7, [], {}] {
		asset := component("ML-DSA", "Falcon", oid)
		scheme(asset) == "Falcon"
		result := findings with input as {"components": [asset]}
		count(result) == 1
		some finding in result
		finding.ruleId == "ECCG-DG-001"
		finding.severity == "critical"
		finding.schemeIdentifier == "Falcon"
	}
}

test_generic_or_unrecognized_family_allows_name_fallback if {
	every family in ["", "RSA", "custom", null, 7, [], {}] {
		asset := component("RSA-PSS", family, "1.2.840.113549.1.1.1")
		scheme(asset) == "RSASSA-PSS"
		findings == set() with input as {"components": [asset]}
	}
}

test_normalization_and_metadata if {
	asset := with_properties(component(" custom ", " FaLcOn ", " \t1.3.101.112\n"), {"primitive": " Signature "})
	scheme(asset) == "EdDSA"
	unknown := component(" CustomSig ", " CUSTOM ", " 1.2.3.4 ")
	result := findings with input as {"components": [unknown]}
	count(result) == 1
	some finding in result
	finding.schemeIdentifier == "custom"
	finding.oid == "1.2.3.4"
	finding.algorithmFamily == "custom"
	finding.bomRef == "signature-test"
	finding.component == "customsig"
}

test_aliases_and_parameterized_names if {
	every case in [
		[" PkCs#1v1.5 ", "RSASSA-PKCS1-v1_5"],
		["RSA-PKCS1-1.5-3072", "RSASSA-PKCS1-v1_5"],
		["SHA256withRSA", "RSASSA-PKCS1-v1_5"],
		["SHA256withRSAandMGF1", "RSASSA-PSS"],
		["SHA512withRSA/PSS", "RSASSA-PSS"],
		["RSA-PSS-SHA-256-MGF1-3072", "RSASSA-PSS"],
		["RSA-PSS-SHA256-MGF1-MAX-3072", "RSASSA-PSS"],
		["ECDSA / EC-DSA", "ECDSA"],
		["SHA384withECDSA", "ECDSA"],
		["ECDSA-P256", "ECDSA"],
		["SHA256withDSA", "DSA"],
		["RFC6979-ECDSA", "Deterministic ECDSA"],
		["Ed25519ph", "EdDSA"],
		["Ed448", "EdDSA"],
		["ML_DSA_65", "ML-DSA"],
		["SLH-DSA-SHAKE-256s", "SLH-DSA"],
		["XMSS-SHA2_10_256", "XMSS"],
		["XMSSMT-SHA2_20/2_256", "XMSS"],
		["HSS/LMS", "LMS"],
		["LMS_SHA256_M32_H10", "LMS"],
	] {
		asset := component(case[0], "", "")
		scheme(asset) == case[1]
		findings == set() with input as {"components": [asset]}
	}
}

test_unknown_generic_and_misleading_signatures_are_rejected if {
	every name in ["", "CustomSig", "RSA", "RSASSA", "EC", "Falcon", "SM2", "Dilithium", "SPHINCS+", "not-ECDSA", "ECDSA-wrapper", "DSAnything", "ML-DSA-wrapper", "ML-DSA-650", "SLH-DSA-SHAKE-256s-custom", "RSA-PKCS1-1.50", "Ed25519+ML-DSA"] {
		result := findings with input as {"components": [component(name, "", "")]}
		count(result) == 1
		some finding in result
		finding.ruleId == "ECCG-DG-001"
		finding.severity == "critical"
	}
}

test_explicit_other_primitives_are_excluded if {
	every primitive in ["pke", "kem", "key-agree", "hash", "mac", "block-cipher"] {
		asset := with_properties(component("Falcon", "EdDSA", "1.3.101.112"), {"primitive": primitive})
		not is_digital_signature_component(asset)
		findings == set() with input as {"components": [asset]}
	}
}

test_key_material_and_non_crypto_components_are_excluded if {
	every asset_type in ["related-crypto-material", "certificate", "protocol", "", null] {
		base := component("Falcon", "", "")
		asset := object.union(base, {"cryptoProperties": object.union(base.cryptoProperties, {"assetType": asset_type})})
		not is_digital_signature_component(asset)
		findings == set() with input as {"components": [asset]}
	}
	findings == set() with input as {"components": [{"name": "Falcon"}, {}, null]}
}

test_missing_primitive_can_be_inferred_from_each_identifier if {
	every base in [component("", "", "1.3.101.112"), component("", "ECDSA", ""), component("KCDSA", "", "")] {
		asset := with_properties(base, {"primitive": ""})
		is_digital_signature_component(asset)
		findings == set() with input as {"components": [asset]}
	}
	unknown := with_properties(component("CustomSig", "", ""), {"primitive": "", "cryptoFunctions": [" Sign "]})
	is_digital_signature_component(unknown)
	result := findings with input as {"components": [unknown]}
	count(result) == 1
}

test_bare_keys_and_contradictory_encryption_context_are_not_inferred if {
	every base in [
		component("RSA", "RSA", "1.2.840.113549.1.1.1"),
		component("EC", "EC", "1.2.840.10045.2.1"),
		component("ECDSA", "ECDH", ""),
		component("ECDSA", "", "1.3.101.110"),
		component("RSA-PKCS1-1.5", "RSAES-PKCS1", ""),
		component("ML-DSA", "ML-KEM", ""),
		component("ML-DSA", "", "2.16.840.1.101.3.4.4.2"),
	] {
		asset := with_properties(base, {"primitive": ""})
		not is_digital_signature_component(asset)
	}
	every fn in ["encrypt", "decrypt", "encapsulate", "decapsulate"] {
		asset := with_properties(component("RSA-PKCS1-1.5", "", ""), {"primitive": "", "cryptoFunctions": [fn]})
		not is_digital_signature_component(asset)
	}
	asset := with_properties(component("custom", "RSAES-OAEP", "1.3.101.112"), {"primitive": ""})
	is_digital_signature_component(asset)
	scheme(asset) == "EdDSA"
}

test_compliance_and_aggregate_integration if {
	cbom := {"components": [component("CustomSig", "", "")]}
	not compliant with input as cbom
	result := all_findings with input as cbom
	matching := [finding | some finding in result; finding.ruleId == "ECCG-DG-001"]
	count(matching) == 1
	matching[0].section == "Asymmetric Constructions"
	matching[0].subsection == "Digital Signature Schemes"
	matching[0].schemeIdentifier == "customsig"
	compliant with input as {"components": [component("EdDSA", "", "")]}
	compliant with input as {"components": []}
}

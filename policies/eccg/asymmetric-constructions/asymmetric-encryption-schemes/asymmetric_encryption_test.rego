package cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes_test

import data.cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes.findings
import data.cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes.constants.ASYMMETRIC_ENCRYPTION_OIDS
import data.cbom.eccg.findings as all_findings

component(name, family, oid) := {
	"name": name,
	"bom-ref": "encryption-test",
	"cryptoProperties": {
		"assetType": "algorithm",
		"oid": oid,
		"algorithmProperties": {
			"primitive": "pke",
			"algorithmFamily": family,
			"parameterSetIdentifier": "3072",
		},
	},
}

with_properties(asset, properties) := object.union(asset, {"cryptoProperties": object.union(asset.cryptoProperties, {"algorithmProperties": object.union(asset.cryptoProperties.algorithmProperties, properties)})})

with_primitive(asset, primitive) := with_properties(asset, {"primitive": primitive})

# Violations and advisories are independent findings. Require exactly
# one finding for the requested rule, without suppressing the other rules.
rule_finding(asset, rule_id) := matching[0] if {
	result := findings with input as {"components": [asset]}
	matching := [finding | some finding in result; finding.ruleId == rule_id]
	count(matching) == 1
}

only_finding(asset) := rule_finding(asset, "ECCG-AS-ENC-001")

test_oaep_by_oid_family_and_name if {
	every asset in [
		component("", "", "1.2.840.113549.1.1.7"),
		component("custom", "RSAES-OAEP", ""),
		component("RSA-OAEP", "RSA", ""),
		component(" rsaes_oaep ", "", ""),
		component("OAEP", "", ""),
		component("RSA-OAEP-SHA-256-MGF1-3072", "", ""),
		component("RSA/ECB/OAEPPadding", "", ""),
		component("RSA/None/OAEPWithSHA-256AndMGF1Padding", "", ""),
	] {
		result := findings with input as {"components": [asset]}
		{finding.ruleId | some finding in result} == {"ECCG-AS-ENC-002", "ECCG-AS-ENC-004", "ECCG-AS-ENC-005"}
		count(result) == 3
		every finding in result {
			finding.severity == "warning"
			finding.schemeIdentifier == "RSAES-OAEP"
			finding.bomRef == "encryption-test"
		}
	}
}

test_pkcs1_v1_5_by_oid_family_and_name if {
	every asset in [
		component("", "", "1.2.840.113549.1.1.1"),
		component("custom", "RSAES-PKCS1", ""),
		component("custom", "RSAES-PKCS1-v1_5", ""),
		component("custom", "rsaes_pkcs1_v1_5", ""),
		component("RSAES-PKCS1-v1_5", "", ""),
		component("RSA-PKCS1-1.5-3072", "RSA", ""),
		component("PKCS1v15", "", ""),
		component("RSA/ECB/PKCS1Padding", "", ""),
	] {
		result := findings with input as {"components": [asset]}
		{finding.ruleId | some finding in result} == {"ECCG-AS-ENC-002", "ECCG-AS-ENC-003", "ECCG-AS-ENC-005"}
		count(result) == 3
		every finding in result {
			finding.severity == "warning"
			finding.schemeIdentifier == "RSAES-PKCS1-v1_5"
		}
	}
}

test_padded_identifiers_and_mixed_case_enums_preserve_oid_precedence if {
	asset := with_primitive(component(" ElGamal ", " ECIES ", " \t1.2.840.113549.1.1.7\n"), " PKE ")
	padded := object.union(asset, {"cryptoProperties": object.union(asset.cryptoProperties, {"assetType": " Algorithm "})})
	finding := rule_finding(padded, "ECCG-AS-ENC-004")
	finding.schemeIdentifier == "RSAES-OAEP"
	finding.oid == "1.2.840.113549.1.1.7"
	finding.component == "elgamal"
}

test_unknown_or_malformed_oids_allow_family_fallback if {
	every oid in ["", "1.2.3.4.5", "not-an-oid", null, 7, [], {}] {
		finding := rule_finding(component("unrecognized", "RSAES-OAEP", oid), "ECCG-AS-ENC-004")
		finding.schemeIdentifier == "RSAES-OAEP"
	}
}

test_oid_and_family_take_priority_over_names if {
	every case in [
		{"oid": "1.2.840.113549.1.1.7", "family": "RSAES-PKCS1", "name": "ElGamal", "scheme": "RSAES-OAEP"},
		{"oid": "1.2.840.113549.1.1.1", "family": "RSAES-OAEP", "name": "RSA-OAEP", "scheme": "RSAES-PKCS1-v1_5"},
		{"oid": "", "family": "RSAES-OAEP", "name": "RSA-PKCS1-1.5", "scheme": "RSAES-OAEP"},
		{"oid": "", "family": "RSAES-PKCS1", "name": "RSA-OAEP", "scheme": "RSAES-PKCS1-v1_5"},
	] {
		finding := rule_finding(component(case.name, case.family, case.oid), "ECCG-AS-ENC-002")
		finding.schemeIdentifier == case.scheme
	}
}

test_other_encryption_schemes_are_rejected if {
	every name in ["ECIES", "ElGamal", "RSA/ECB/NoPadding", "RSA-NoPadding", "CustomPKE", "not-RSA-OAEP", "OAEP-wrapper", "RSA-OAEPwrapper", "RSA-PKCS1-1.50"] {
		finding := only_finding(component(name, "", ""))
		finding.severity == "critical"
		contains(finding.message, lower(name))
		contains(finding.message, "RSAES-OAEP")
		contains(finding.message, "RSAES-PKCS1-v1_5")
	}
}

test_generic_rsa_family_does_not_hide_unpadded_encryption if {
	finding := only_finding(component("RSA/ECB/NoPadding", "RSA", ""))
	finding.severity == "critical"
}

test_unidentified_encryption_schemes_are_not_in_the_agreed_list if {
	every asset in [
		component("", "", ""),
		component("RSA", "", ""),
		component("RSA-3072", "RSA", ""),
		component("RSA3072", "", ""),
		component("custom", "RSA", ""),
		component("", "RSA", ""),
	] {
		finding := only_finding(asset)
		finding.severity == "critical"
	}
}

test_non_encryption_primitives_are_excluded if {
	every primitive in ["signature", "kem", "key-agree", "hash", "block-cipher"] {
		asset := with_primitive(component("RSA-OAEP", "RSAES-OAEP", "1.2.840.113549.1.1.7"), primitive)
		result := findings with input as {"components": [asset]}
		count(result) == 0
	}
}

test_key_material_is_excluded if {
	asset := component("RSA-OAEP", "RSAES-OAEP", "1.2.840.113549.1.1.7")
	key := object.union(asset, {"cryptoProperties": object.union(asset.cryptoProperties, {"assetType": "related-crypto-material"})})
	result := findings with input as {"components": [key]}
	count(result) == 0
}

test_padding_and_quantum_notes_are_separate_rules if {
	every case in [
		{"asset": component("RSA-OAEP", "", ""), "scheme": "RSAES-OAEP", "notes": {
			"ECCG-AS-ENC-002": "43-RandomPadding",
			"ECCG-AS-ENC-004": "45-OAEP-PaddingAttack",
			"ECCG-AS-ENC-005": "46-QuantumThreat",
		}},
		{"asset": component("RSA-PKCS1-1.5", "", ""), "scheme": "RSAES-PKCS1-v1_5", "notes": {
			"ECCG-AS-ENC-002": "43-RandomPadding",
			"ECCG-AS-ENC-003": "44-PaddingAttack",
			"ECCG-AS-ENC-005": "46-QuantumThreat",
		}},
	] {
		result := findings with input as {"components": [case.asset]}
		count(result) == 3
		every rule_id, note_title in case.notes {
			advisory := rule_finding(case.asset, rule_id)
			advisory.severity == "warning"
			advisory.notes.title == note_title
			advisory.notes.text != ""
			advisory.schemeIdentifier == case.scheme
			advisory.bomRef == "encryption-test"
		}
	}
}

test_violation_and_advisory_findings_reach_top_level if {
	assets := [component("RSA-OAEP", "", ""), component("RSA-PKCS1-1.5", "", ""), component("ElGamal", "", "")]
	result := all_findings with input as {"components": assets}
	encryption_findings := [finding | some finding in result; startswith(finding.ruleId, "ECCG-AS-ENC-")]
	count(encryption_findings) == 7
	count([finding | some finding in encryption_findings; finding.ruleId == "ECCG-AS-ENC-001"]) == 1
	every finding in encryption_findings {
		finding.section == "Asymmetric Constructions"
		finding.subsection == "Asymmetric Encryption Schemes"
		finding.bomRef == "encryption-test"
	}
}

test_empty_input_produces_no_findings if {
	every document in [{}, {"components": []}, {"components": [{}]}] {
		result := findings with input as document
		count(result) == 0
	}
}

test_metadata_contains_scheme_details_without_classification if {
	every asset in [
		component("", "", "1.2.840.113549.1.1.7"),
		component("custom", "rsaes_oaep", ""),
		component("RSA-OAEP", "unknown-family", ""),
		component("ElGamal", "", ""),
		component("", "", ""),
	] {
		result := findings with input as {"components": [asset]}
		count(result) > 0
		every finding in result {
			is_string(finding.schemeIdentifier)
			is_string(finding.oid)
			is_string(finding.algorithmFamily)
			not finding.classification
			not finding.status
			not finding.classificationMethod
			not finding.matchedIdentifier
		}
	}
}

test_missing_primitive_can_use_explicit_encryption_evidence if {
	every asset in [
		component("", "", "1.2.840.113549.1.1.7"),
		component("custom", "RSAES-OAEP", ""),
		component("RSA-OAEP", "", ""),
	] {
		inferred := with_primitive(asset, "")
		finding := rule_finding(inferred, "ECCG-AS-ENC-004")
		finding.schemeIdentifier == "RSAES-OAEP"
		result := findings with input as {"components": [inferred]}
		count(result) == 3
	}
	finding := only_finding(with_properties(component("RSA", "RSA", ""), {"primitive": "", "cryptoFunctions": ["decrypt"]}))
	finding.severity == "critical"
}

test_signature_functions_and_generic_keys_do_not_imply_encryption if {
	every asset in [
		with_properties(component("RSA-OAEP", "RSAES-OAEP", ""), {"primitive": "", "cryptoFunctions": ["sign"]}),
		with_properties(component("RSA-OAEP", "RSAES-OAEP", ""), {"primitive": "", "cryptoFunctions": ["verify"]}),
		with_primitive(component("RSA", "RSA", "1.2.840.113549.1.1.1"), ""),
		with_properties(component("AES", "AES", ""), {"primitive": "", "cryptoFunctions": ["encrypt"]}),
	] {
		result := findings with input as {"components": [asset]}
		count(result) == 0
	}
}

test_crypto_function_checks_use_the_shared_normalization if {
	every functions in [[" EnCrYpT ", null], [" DeCrYpT "], " DeCrYpT "] {
		asset := with_properties(component("RSA", "RSA", ""), {"primitive": "", "cryptoFunctions": functions})
		finding := only_finding(asset)
		finding.severity == "critical"
	}
	every functions in [[" SIGN "], [" VeRiFy "], [" ENCRYPT ", " SIGN "], " VeRiFy "] {
		asset := with_properties(component("RSA-OAEP", "RSAES-OAEP", ""), {"primitive": "", "cryptoFunctions": functions})
		findings == set() with input as {"components": [asset]}
	}
}

# Encryption evidence and scheme detection must use the same OID table. A synthetic entry
# exercises that relationship without relying on the registered OAEP OID.
test_encryption_evidence_uses_the_oid_constants if {
	oids := {"1.2.3.7": "RSAES-OAEP"}
	asset := with_primitive(component("", "", "1.2.3.7"), "")
	result := findings with input as {"components": [asset]} with ASYMMETRIC_ENCRYPTION_OIDS as oids
	count(result) == 3
	every finding in result {
		finding.severity == "warning"
		finding.schemeIdentifier == "RSAES-OAEP"
		finding.oid == "1.2.3.7"
	}
	unregistered := with_primitive(component("", "", "1.2.840.113549.1.1.7"), "")
	findings == set() with input as {"components": [unregistered]} with ASYMMETRIC_ENCRYPTION_OIDS as oids
}

test_signature_and_kem_families_disambiguate_names_without_a_primitive if {
	every asset in [
		component("RSA-PKCS1-1.5", "RSASSA-PKCS1", ""),
		component("RSA-OAEP", "RSASSA-PSS", ""),
		component("RSA-PKCS1-1.5", "RSA-X931", ""),
		component("ECIES", "ECIES-KEM", ""),
		component("RSA-OAEP", "RSA-KEM", ""),
		component("ECIES-KEM", "", ""),
	] {
		result := findings with input as {"components": [with_primitive(asset, "")]}
		count(result) == 0
	}
}

# Advisories follow the resolved scheme, even when the name contradicts it.
# This prevents an OAEP name from adding an OAEP decoding warning to a
# component detected as PKCS#1 v1.5 through its higher-priority OID.
test_advisories_follow_the_resolved_scheme if {
	every case in [
		{"asset": component("RSA-OAEP", "RSAES-OAEP", "1.2.840.113549.1.1.1"), "rules": {"ECCG-AS-ENC-002", "ECCG-AS-ENC-003", "ECCG-AS-ENC-005"}},
		{"asset": component("RSA-PKCS1-1.5", "RSAES-PKCS1", "1.2.840.113549.1.1.7"), "rules": {"ECCG-AS-ENC-002", "ECCG-AS-ENC-004", "ECCG-AS-ENC-005"}},
		{"asset": component("RSA-OAEP", "RSAES-PKCS1", ""), "rules": {"ECCG-AS-ENC-002", "ECCG-AS-ENC-003", "ECCG-AS-ENC-005"}},
		{"asset": component("RSA-OAEP", "ElGamal", ""), "rules": {"ECCG-AS-ENC-001"}},
	] {
		result := findings with input as {"components": [case.asset]}
		{finding.ruleId | some finding in result} == case.rules
		count(result) == count(case.rules)
	}
}

test_non_agreed_schemes_have_one_critical_finding_and_no_scheme_notes if {
	every asset in [
		component("", "", ""),
		component("custom", "RSA", ""),
		component("RSA-3072", "", ""),
		component("ElGamal", "", ""),
		component("ECIES", "", ""),
		component("RSA/ECB/NoPadding", "RSA", ""),
	] {
		result := findings with input as {"components": [asset]}
		count(result) == 1
		some finding in result
		finding.ruleId == "ECCG-AS-ENC-001"
		finding.severity == "critical"
		not finding.notes
	}
}

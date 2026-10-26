package cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization_test

import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.findings
import data.cbom.eccg.compliant as assessment_compliant
import data.cbom.eccg.findings as all_findings

component(name, primitive, family, parameter) := {
	"name": name,
	"bom-ref": "rsa-test-component",
	"cryptoProperties": {
		"assetType": "algorithm",
		"algorithmProperties": {
			"primitive": primitive,
			"algorithmFamily": family,
			"parameterSetIdentifier": parameter,
		},
	},
}

only_finding_for(asset) := finding if {
	result := findings with input as {"components": [asset]}
	count(result) == 1
	some finding in result
}

test_rsa_encryption_signatures_and_kems_are_detected if {
	every case in [
		{"name": "RSA", "primitive": "pke"},
		{"name": "RSA-2048", "primitive": "pke"},
		{"name": "RSA2048", "primitive": "pke"},
		{"name": "RSAES-OAEP", "primitive": "pke"},
		{"name": "RSA-PKCS1-1.5", "primitive": "pke"},
		{"name": "RSASSA-PSS", "primitive": "signature"},
		{"name": "SHA256withRSA", "primitive": "signature"},
		{"name": "SHA1withRSA", "primitive": "signature"},
		{"name": "rsa_pss", "primitive": "signature"},
		{"name": "RSA-PSS-SHA-256-MGF1-SHA-256-32-3072", "primitive": "signature"},
		{"name": "RSA-KEM", "primitive": "kem"},
	] {
		finding := only_finding_for(component(case.name, case.primitive, "", "2048"))
		finding.ruleId == "ECCG-RSA-001"
		finding.severity == "critical"
		finding.classification == "non_compliant"
		finding.modulusBits == 2048
		finding.exponentCheck == "not_verifiable"
	}
}

test_family_detection_without_recognized_name if {
	every family in ["RSA", "RSAES-OAEP", "RSAES-PKCS1", "RSASSA-PSS", "RSASSA-PKCS1", "RSA-X931", "rsassa_pss"] {
		finding := only_finding_for(component("custom name", "signature", family, "2048"))
		finding.ruleId == "ECCG-RSA-001"
		finding.classification == "non_compliant"
	}
	asset := object.remove(component("", "pke", "RSA", "2048"), {"name"})
	finding := only_finding_for(asset)
	finding.modulusBits == 2048
}

test_oid_detection_without_recognized_name_or_family if {
	every oid in ["1.2.840.113549.1.1.1", "1.2.840.113549.1.1.7", "1.2.840.113549.1.1.10", "1.2.840.113549.1.1.11"] {
		asset := component("custom name", "signature", "", "2048")
		asset_with_oid := object.union(asset, {"cryptoProperties": object.union(asset.cryptoProperties, {"oid": oid})})
		finding := only_finding_for(asset_with_oid)
		finding.modulusBits == 2048
		finding.classification == "non_compliant"
	}
}

test_undersized_moduli_produce_one_critical_finding if {
	every parameter in ["1", "1024", "2048", "2999"] {
		finding := only_finding_for(component("RSA", "pke", "RSA", parameter))
		finding.severity == "critical"
		finding.classification == "non_compliant"
		finding.modulusBits == to_number(parameter)
		finding.minimumModulusBits == 3000
		finding.parameterSetIdentifier == parameter
	}
}

test_modulus_minimum_is_inclusive if {
	every parameter in ["3000", "3071", "3072", "4096", "8192"] {
		result := findings with input as {"components": [component("RSA", "pke", "", parameter)]}
		count(result) == 0
	}
}

test_missing_or_invalid_moduli_are_inconclusive if {
	# The shared CycloneDX getter accepts parameterSetIdentifier strings.
	every parameter in ["", "unknown", "0", "-1", "2999.5", "3000.5", "RSA-3072", 0, 2048, null, true, [], {}] {
		finding := only_finding_for(component("RSA-8192", "pke", "RSA", parameter))
		finding.severity == "warning"
		finding.classification == "inconclusive"
		finding.modulusBits == ""
	}
	asset := {
		"name": "RSA-8192",
		"cryptoProperties": {
			"assetType": "algorithm",
			"algorithmProperties": {"primitive": "pke"},
		},
	}
	finding := only_finding_for(asset)
	finding.classification == "inconclusive"
}

test_parameter_set_takes_precedence_over_name if {
	finding := only_finding_for(component("RSA-8192", "pke", "RSA", "2048"))
	finding.modulusBits == 2048
	finding.severity == "critical"
}

test_non_rsa_public_key_algorithms_are_excluded if {
	every case in [
		{"name": "DH", "primitive": "pke"},
		{"name": "FFDHE", "primitive": "key-agree"},
		{"name": "ECIES", "primitive": "pke"},
		{"name": "DSA", "primitive": "signature"},
		{"name": "ECDSA", "primitive": "signature"},
		{"name": "EdDSA", "primitive": "signature"},
		{"name": "ML-KEM", "primitive": "kem"},
		{"name": "VersaCipher", "primitive": "pke"},
	] {
		result := findings with input as {"components": [component(case.name, case.primitive, case.name, "2048")]}
		count(result) == 0
	}
}

test_non_public_key_components_are_excluded if {
	every primitive in ["hash", "block-cipher", "mac"] {
		result := findings with input as {"components": [component("RSA", primitive, "RSA", "2048")]}
		count(result) == 0
	}
}

test_rsa_findings_reach_top_level_once if {
	assets := [component("RSA-2048", "pke", "RSA", "2048")]
	result := all_findings with input as {"components": assets}
	rsa_findings := {finding |
		some finding in result
		startswith(finding.ruleId, "ECCG-RSA-")
	}
	count(rsa_findings) == 1
	some finding in rsa_findings
	finding.section == "Asymmetric Atomic Primitives"
	finding.subsection == "RSA Integer Factorization"
	finding.classification == "non_compliant"
	finding.note.title == "Legacy RSA"
	compliant := assessment_compliant with input as {"components": assets}
	compliant == false
}

test_empty_input_has_no_rsa_findings if {
	result := findings with input as {}
	count(result) == 0
}

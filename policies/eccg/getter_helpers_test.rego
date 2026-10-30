package cbom.eccg.getter_helpers_test

import data.cbom.eccg.getter_helpers as getters
import data.cbom.eccg.getter_helpers.get_ec_curve_from_text_or_empty
import data.cbom.eccg.getter_helpers.get_ec_curve_or_empty

# Exercise all scalar string getters with the same value, including malformed
# input, so normalization cannot turn a defined fallback into an undefined rule.
string_getter_results(value) := [
	getters.get_component_name_or_empty(asset),
	getters.get_component_bom_ref_or_empty(asset),
	getters.get_component_additional_context_or_empty(asset),
	getters.get_related_crypto_material_type_or_empty(asset),
	getters.get_component_asset_type_or_empty(asset),
	getters.get_component_oid_or_empty(asset),
	getters.get_component_elliptic_curve_or_empty(asset),
	getters.get_component_algorithm_family_or_empty(asset),
	getters.get_component_primitive_or_empty(asset),
	getters.get_component_mode_or_empty(asset),
	getters.get_component_parameter_set_identifier_or_empty(asset),
	getters.get_component_occurrence_location_or_empty(occurrence),
	getters.get_component_occurrence_additional_context_or_empty(occurrence),
] if {
	asset := {
		"name": value,
		"bom-ref": value,
		"additionalContext": value,
		"relatedCryptoMaterialProperties": {"type": value},
		"cryptoProperties": {
			"assetType": value,
			"oid": value,
			"algorithmProperties": {
				"ellipticCurve": value,
				"algorithmFamily": value,
				"primitive": value,
				"mode": value,
				"parameterSetIdentifier": value,
			},
		},
	}
	occurrence := {"location": value, "additionalContext": value}
}

test_string_getters_lowercase_algorithms_and_preserve_case_sensitive_text if {
	string_getter_results("\u00a0\t Mixed Case/Value-01 \r\n") == [
		"mixed case/value-01", "Mixed Case/Value-01", "Mixed Case/Value-01",
		"mixed case/value-01", "mixed case/value-01", "Mixed Case/Value-01",
		"mixed case/value-01", "mixed case/value-01", "mixed case/value-01",
		"mixed case/value-01", "mixed case/value-01",
		"Mixed Case/Value-01", "Mixed Case/Value-01",
	]
}

test_string_getters_return_empty_for_blank_or_non_string_values if {
	every value in ["", " \t\r\n\u00a0", null, true, 256, [], {}, ["RSA"]] {
		results := string_getter_results(value)
		count(results) == 13
		every result in results {
			result == ""
		}
	}
	getters.get_component_name_or_empty({}) == ""
	getters.get_component_asset_type_or_empty({}) == ""
	getters.get_component_asset_type_or_empty({"cryptoProperties": null}) == ""
}

test_crypto_functions_getter_normalizes_arrays_and_legacy_strings if {
	every case in [
		{"value": [" SIGN ", "VeRiFy", "\t", null, 7, {}, []], "expected": ["sign", "verify"]},
		{"value": [" EnCrYpT ", " DeCrYpT "], "expected": ["encrypt", "decrypt"]},
		{"value": " DeCrYpT ", "expected": ["decrypt"]},
	] {
		asset := ec_component("RSA", {"cryptoFunctions": case.value})
		getters.get_component_crypto_function_or_empty(asset) == case.expected
	}
	every value in ["", " \t\n", null, true, 12, [], {}, [null, 12, " "]] {
		getters.get_component_crypto_function_or_empty(ec_component("RSA", {"cryptoFunctions": value})) == []
	}
	getters.get_component_crypto_function_or_empty({}) == []
}

test_signature_classifiers_consume_normalized_crypto_functions if {
	every functions in [[" SIGN ", " VERIFY "], " SiGn "] {
		asset := ec_component("RSA", {"cryptoFunctions": functions})
		data.cbom.eccg.classifying_helpers.is_sign_crypto_function(asset)
	}
	asset := ec_component("RSA", {"cryptoFunctions": [" SIGN ", " VERIFY "]})
	data.cbom.eccg.classifying_helpers.is_verify_crypto_function(asset)
	not data.cbom.eccg.classifying_helpers.is_sign_crypto_function(ec_component("RSA", {"cryptoFunctions": []}))
}

test_padded_parameter_set_can_be_converted_to_number if {
	asset := ec_component("RSA", {"parameterSetIdentifier": " \t3072\n"})
	getters.get_component_parameter_set_identifier_to_number_or_negative_one(asset) == 3072
	every value in [" \t", " 30 72 ", " nist/P-256 ", null, 3072] {
		getters.get_component_parameter_set_identifier_to_number_or_negative_one(ec_component("RSA", {"parameterSetIdentifier": value})) == -1
	}
}

test_algorithm_identifier_text_joins_only_present_fields if {
	asset := ec_component(" ECDH ", {"primitive": " KEY-AGREE ", "ellipticCurve": " NIST P-256 "})
	getters.get_component_algorithm_identifier_text(asset) == "ecdh key-agree nist p-256"
	getters.get_component_algorithm_identifier_text({}) == ""
	get_ec_curve_or_empty(ec_component("ECDH-P-521", {"ellipticCurve": " \t ", "parameterSetIdentifier": " nist/P-256 "})) == "nist p-256"
}

test_lowercase_getter_convention_matches_policy_family_constants if {
	every family in ["AES", "aes", " \taEs\n"] {
		asset := ec_component("unknown", {"primitive": " BLOCK-CIPHER ", "algorithmFamily": family, "mode": " CBC "})
		data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.helpers.is_aes_component(asset)
		data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.is_cbc_scheme(asset)
	}
	mac := ec_component("unknown", {"primitive": " MAC ", "algorithmFamily": " hMaC "})
	data.cbom.eccg.symmetric_constructions.macs.helpers.is_hmac_scheme(mac)
	kdf := ec_component("unknown", {"primitive": " KDF ", "algorithmFamily": " pBkDf2 "})
	data.cbom.eccg.symmetric_constructions.key_derivation.helpers.is_pbkdf2_scheme(kdf)
	data.cbom.eccg.symmetric_constructions.password_protection.helpers.is_pbkdf2_scheme(kdf)
	argon := ec_component("unknown", {"primitive": " KDF ", "algorithmFamily": " aRgOn2 "})
	data.cbom.eccg.symmetric_constructions.password_protection.helpers.is_argon2id_scheme(argon)
}

test_dependency_getters_trim_references_consistently if {
	key := {"bom-ref": " Key-1 ", "cryptoProperties": {"assetType": " RELATED-CRYPTO-MATERIAL "}}
	algorithm := object.union(ec_component(" RSA ", {}), {"bom-ref": " RSA-1\t"})
	dependency := {"ref": "\tKey-1", "dependsOn": [" RSA-1 ", "", " \t ", null, 7]}
	cbom := {"components": [key, algorithm, {"bom-ref": ""}], "dependencies": [dependency]}
	getters.get_component_dependency(key) == dependency with input as cbom
	getters.get_component_dependency_refs_or_empty(key) == ["RSA-1"] with input as cbom
	getters.get_component_dependency_components_or_empty(key) == [algorithm] with input as cbom
	getters.get_related_algorithm_for_key_material_or_empty(key) == algorithm with input as cbom
	getters.get_component_by_bomref("\nRSA-1 ") == algorithm with input as cbom
	not getters.get_component_by_bomref("rsa-1") with input as cbom
	not getters.get_component_by_bomref(" \t ") with input as cbom
	not getters.get_component_by_bomref(null) with input as cbom
}

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
		get_ec_curve_from_text_or_empty(text) == lower(expected)
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
		get_ec_curve_from_text_or_empty(text) == lower(expected)
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
	get_ec_curve_from_text_or_empty("ECDH-NIST-P-256-secp256r1-prime256v1") == "nist p-256"
	get_ec_curve_from_text_or_empty("EdDSA-Edwards25519-Ed25519") == "ed25519"
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
		get_ec_curve_or_empty(asset) == lower(expected)
	}
}

test_ec_curve_preserves_explicit_curve_precedence if {
	asset := ec_component("ECDH-P-521", {"ellipticCurve": "secp256k1", "parameterSetIdentifier": "nist/P-256"})
	get_ec_curve_or_empty(asset) == "secp256k1"
	ambiguous := ec_component("ECDH-P-521", {"ellipticCurve": "nist/P-256", "parameterSetIdentifier": "P-256/P-384"})
	get_ec_curve_or_empty(ambiguous) == "nist/p-256"
}

test_ec_curve_ambiguous_parameter_does_not_fall_back_to_name if {
	asset := ec_component("ECDH-P-521", {"parameterSetIdentifier": "secp256k1/P-256"})
	get_ec_curve_or_empty(asset) == ""
}

test_ec_curve_non_curve_parameters_fall_back_to_name if {
	every parameter in ["", "256", "unknown", null, 256, true, [], {}] {
		asset := ec_component("ECDH-P-256", {"parameterSetIdentifier": parameter})
		get_ec_curve_or_empty(asset) == "nist p-256"
	}
	get_ec_curve_or_empty(ec_component("ECDH-P-256", {})) == "nist p-256"
	get_ec_curve_or_empty({}) == ""
}

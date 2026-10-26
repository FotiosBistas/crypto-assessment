package cbom.eccg.general_helpers_test

import data.cbom.eccg.general_helpers.normalize_crypto_identifier

test_crypto_identifiers_normalize_without_collapsing_distinct_algorithms if {
	every original, expected in {
		"DSA": "dsa",
		"ECDSA": "ecdsa",
		"MODP-3072": "modp3072",
		" FFDHE_2048 ": "ffdhe2048",
		"SHA-512/256": "sha512256",
		"KMAC (256)": "kmac256",
		"RSA-PKCS1-1.5": "rsapkcs115",
		"": "",
	} {
		normalize_crypto_identifier(original) == expected
	}
}

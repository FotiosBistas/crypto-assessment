package cbom.eccg.symmetric_constructions.key_combiners.constants

#
# Source:
# - https://www.etsi.org/deliver/etsi_ts/103700_103799/103744/01.02.01_60/ts_103744v010201p.pdf
#
# CycloneDX primitive: combiner
# No dedicated CycloneDX algorithm family verified.
# ============================================================

CATKDF_KEY_COMBINER_SCHEME_NAMES := {
    "CatKDF",
    "CATKDF",
    "Cat-KDF",
    "Concatenate-KDF",
    "Concatenate-KeyCombiner",
    "Concatenate-Hybrid-KeyCombiner",
    "ETSI-CatKDF",
}

CATKDF_KEY_COMBINER_SCHEME_FAMILIES := set()

# No standalone CatKDF OID verified
CATKDF_KEY_COMBINER_SCHEME_OIDS := {
    "CatKDF": null,
    "CATKDF": null,
    "Cat-KDF": null,
    "Concatenate-KDF": null,
    "Concatenate-KeyCombiner": null,
    "Concatenate-Hybrid-KeyCombiner": null,
    "ETSI-CatKDF": null,
}

CATKDF_KEY_COMBINER_SCHEME_OID_VALUES := {
    oid | oid := CATKDF_KEY_COMBINER_SCHEME_OIDS[_]
}


#
# Source:
# - https://www.etsi.org/deliver/etsi_ts/103700_103799/103744/01.02.01_60/ts_103744v010201p.pdf
#
# CycloneDX primitive: combiner
# No dedicated CycloneDX algorithm family verified.
# ============================================================

CASKDF_KEY_COMBINER_SCHEME_NAMES := {
    "CasKDF",
    "CASKDF",
    "Cas-KDF",
    "Cascade-KDF",
    "Cascade-KeyCombiner",
    "Cascade-Hybrid-KeyCombiner",
    "ETSI-CasKDF",
}

CASKDF_KEY_COMBINER_SCHEME_FAMILIES := set()

# No standalone CasKDF OID verified
CASKDF_KEY_COMBINER_SCHEME_OIDS := {
    "CasKDF": null,
    "CASKDF": null,
    "Cas-KDF": null,
    "Cascade-KDF": null,
    "Cascade-KeyCombiner": null,
    "Cascade-Hybrid-KeyCombiner": null,
    "ETSI-CasKDF": null,
}

CASKDF_KEY_COMBINER_SCHEME_OID_VALUES := {
    oid | oid := CASKDF_KEY_COMBINER_SCHEME_OIDS[_]
}


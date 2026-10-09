package cbom.eccg.symmetric_atomic_primitives.constants 

MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_BLOCK_CIPHER := 192
MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_HASH := 384

TRIPLE_DES_REQUIRED_KEY_BITS := 168
TRIPLE_DES_LEGACY_MARKER := "L[2027]"
# ============================================================
# Triple DES (3DES / TDEA)
# ============================================================
#
# Sources:
# - RFC 3370, Section 5.1:
#   https://www.rfc-editor.org/rfc/rfc3370.html#section-5.1
# - RFC 8018, Appendix B.2.2:
#   https://www.rfc-editor.org/rfc/rfc8018.html
# - LAN Crypto private OID registry:
#   https://www.alvestrand.no/cgi-bin/hta/oidwordsearch?text=1.3.6.1.4.1
#
TRIPLE_DES_ALGORITHM_OIDS := { 
    "1.2.840.113549.3.7",   # DES-EDE3-CBC
    "1.3.6.1.4.1.4929.1.6",   # 3Des
}

TRIPLE_DES_ALGORITHM_FAMILIES := { 
    "3DES",
}

TRIPLE_DES_ALGORITHM_OID_VALUES := {oid | oid := TRIPLE_DES_ALGORITHM_OIDS[_]}

# ============================================================
# AES (Advanced Encryption Standard)
# ============================================================
#
# Authoritative source:
# - NIST Computer Security Objects Register (CSOR):
#   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
#
# Additional standards:
# - RFC 3565: AES-CBC
#   https://www.rfc-editor.org/rfc/rfc3565.html
# - RFC 5084: AES-GCM and AES-CCM
#   https://www.rfc-editor.org/rfc/rfc5084.html
#
# AES base OID: 2.16.840.1.101.3.4.1
#
# Each OID identifies an AES key size and specific mode.
# Recognition does not imply security or policy approval.
#
AES_ALGORITHM_NAMES := {
    "AES",
}

AES_ALGORITHM_FAMILIES := {
    "AES",
}

AGREED_BLOCK_CIPHER_ALGORITHM_NAMES :=
    AES_ALGORITHM_NAMES 

AES_ALLOWED_KEY_SIZES := {128, 192, 256}

# AES OIDs identify both key size and mode of operation.
# Base AES arc: 2.16.840.1.101.3.4.1
# NOTE: Recognition of an AES OID does not imply that
# its mode of operation is secure or approved by policy.
AES_ALGORITHM_OIDS := {
    # AES-128
    "AES-128-CBC": "2.16.840.1.101.3.4.1.2",
    "AES-128-OFB": "2.16.840.1.101.3.4.1.3",
    "AES-128-CFB": "2.16.840.1.101.3.4.1.4",
    "AES-128-GCM": "2.16.840.1.101.3.4.1.6",
    "AES-128-CCM": "2.16.840.1.101.3.4.1.7",

    # AES-192
    "AES-192-CBC": "2.16.840.1.101.3.4.1.22",
    "AES-192-OFB": "2.16.840.1.101.3.4.1.23",
    "AES-192-CFB": "2.16.840.1.101.3.4.1.24",
    "AES-192-GCM": "2.16.840.1.101.3.4.1.26",
    "AES-192-CCM": "2.16.840.1.101.3.4.1.27",

    # AES-256
    "AES-256-CBC": "2.16.840.1.101.3.4.1.42",
    "AES-256-OFB": "2.16.840.1.101.3.4.1.43",
    "AES-256-CFB": "2.16.840.1.101.3.4.1.44",
    "AES-256-GCM": "2.16.840.1.101.3.4.1.46",
    "AES-256-CCM": "2.16.840.1.101.3.4.1.47",
}

AES_ALGORITHM_OID_VALUES := {oid | oid := AES_ALGORITHM_OIDS[_]}

#
# Sources:
# - NIST Computer Security Objects Register (CSOR):
#   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
# - RFC 8017, Appendix B.1:
#   https://www.rfc-editor.org/rfc/rfc8017.html#appendix-B.1
#
# Base OID: 2.16.840.1.101.3.4.2
#

SHA2_HASH_ALGORITHM_NAMES := {
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA-512/256",
}

SHA2_HASH_ALGORITHM_FAMILIES := {
    "SHA-2",
}

SHA2_HASH_ALGORITHM_OIDS := {
    "SHA-256": "2.16.840.1.101.3.4.2.1",  # SHA-256
    "SHA-384": "2.16.840.1.101.3.4.2.2",  # SHA-384
    "SHA-512": "2.16.840.1.101.3.4.2.3",  # SHA-512
    "SHA-512/256": "2.16.840.1.101.3.4.2.6",  # SHA-512/256
}

SHA2_HASH_ALGORITHM_OID_VALUES := {oid | oid := SHA2_HASH_ALGORITHM_OIDS[_]}

#
# Source:
# - NIST Computer Security Objects Register (CSOR):
#   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
#
# Base OID: 2.16.840.1.101.3.4.2
#
SHA3_HASH_ALGORITHM_NAMES := {
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
}

SHA3_HASH_ALGORITHM_FAMILIES := {
    "SHA-3",
}

SHA3_HASH_ALGORITHM_OIDS := {
    "SHA3-256": "2.16.840.1.101.3.4.2.8",   # SHA3-256
    "SHA3-384": "2.16.840.1.101.3.4.2.9",   # SHA3-384
    "SHA3-512": "2.16.840.1.101.3.4.2.10",  # SHA3-512
}

SHA3_HASH_ALGORITHM_OID_VALUES := {oid | oid := SHA3_HASH_ALGORITHM_OIDS[_]}


AGREED_HASH_ALGORITHM_NAMES :=
    SHA2_HASH_ALGORITHM_NAMES |
    SHA3_HASH_ALGORITHM_NAMES 

package cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.helpers

import data.cbom.eccg.general_helpers.normalize_crypto_identifier

import data.cbom.eccg.classifying_helpers.is_block_cipher_primitive
import data.cbom.eccg.classifying_helpers.is_ae_primitive
import data.cbom.eccg.classifying_helpers.is_hash_primitive
import data.cbom.eccg.classifying_helpers.is_stream_cipher_or_block_cipher_primitive

import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_mode_or_empty
import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty

import data.cbom.eccg.relationship_helpers.components_share_evidence_window

import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CTR_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CTR_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.OFB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.OFB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CBC_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CBC_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CBC_CS_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CFB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CFB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.XTS_DISK_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.ECB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.ECB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CBC_ESSIV_DISK_ENCRYPTION_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CBC_ESSIV_DISK_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CCM_AE_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CCM_AE_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.GCM_AE_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.GCM_AE_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.EAX_AE_ALGORITHM_OID_VALUES


is_ecb_scheme(component) if {
    is_stream_cipher_or_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in ECB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    family in ECB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
    mode := get_component_mode_or_empty(component)
    mode == "ecb"
} else if {
    mode := get_component_mode_or_empty(component)
    mode == "ecb"
    is_stream_cipher_or_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "ecb")
}

is_ctr_scheme(component) if {
    is_stream_cipher_or_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in CTR_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    family in CTR_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
    mode := get_component_mode_or_empty(component)
    mode == "ctr"
} else if {
    mode := get_component_mode_or_empty(component)
    mode == "ctr"
    is_stream_cipher_or_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "ctr")
}

is_ofb_scheme(component) if {
    is_stream_cipher_or_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in OFB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    family in OFB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
    mode := get_component_mode_or_empty(component)
    mode == "ofb"
} else if {
    mode := get_component_mode_or_empty(component)
    mode == "ofb"
    is_stream_cipher_or_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "ofb")
}

is_cbc_scheme(component) if {
    is_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in CBC_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    family in CBC_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
    mode := get_component_mode_or_empty(component)
    mode == "cbc"
} else if {
    mode := get_component_mode_or_empty(component)
    mode == "cbc"
    is_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "cbc")
}

# there is no supported mode for cbs-cs
is_cbc_cs_scheme(component) if {
    is_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in CBC_CS_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    is_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "cbccs")
} else if {
    is_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "cts")
}


is_cfb_scheme(component) if {
    is_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in CFB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    family in CFB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
    mode := get_component_mode_or_empty(component)
    mode == "cfb"
} else if {
    mode := get_component_mode_or_empty(component)
    mode == "cfb"
    is_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "cfb")
}

is_agreed_symmetric_encryption_scheme(component) if {
    is_ctr_scheme(component) 
} else if {
    is_ofb_scheme(component)
} else if {
    is_cbc_scheme(component)
} else if {
    is_cbc_cs_scheme(component)
} else if {
    is_cfb_scheme(component)
}

is_xts_scheme(component) if {
    is_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in XTS_DISK_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    is_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "xts")
}

is_cbc_essiv(component) if {
    is_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in CBC_ESSIV_DISK_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    family in CBC_ESSIV_DISK_ENCRYPTION_SCHEME_FAMILIES
    mode := get_component_mode_or_empty(component)
    mode == "cbc"
} else if {
    mode := get_component_mode_or_empty(component)
    mode == "cbc"
    is_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "cbcessiv")
} else if {
    is_cbc_essiv_heuristic(component)
}

is_cbc_essiv_heuristic(cbc) if {
    is_block_cipher_primitive(cbc)
    get_component_mode_or_empty(cbc) == "cbc"

    family := get_component_algorithm_family_or_empty(cbc)
    family != ""

    # Hash function
    some hash in input.components
    is_hash_primitive(hash)

    # IV-generation cipher
    some iv_block_cipher in input.components
    is_block_cipher_primitive(iv_block_cipher)

    # Distinct cryptographic assets
    iv_block_cipher["bom-ref"] != cbc["bom-ref"]

    # Same underlying block cipher family
    family == get_component_algorithm_family_or_empty(iv_block_cipher)

    # Evidence proximity
    components_share_evidence_window(
        [hash, iv_block_cipher, cbc],
        15
    )
}


is_disk_encryption(component) if {
    is_xts_scheme(component)
} else if {
    is_cbc_essiv(component)
}

is_ccm_scheme(component) if {
    is_ae_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in CCM_AE_ALGORITHM_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    family in CCM_AE_ALGORITHM_FAMILIES
    mode := get_component_mode_or_empty(component)
    mode == "ccm"
} else if {
    mode := get_component_mode_or_empty(component)
    mode == "ccm"
    is_ae_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "ccm")
}

is_gcm_scheme(component) if {
    is_ae_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in GCM_AE_ALGORITHM_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    family in GCM_AE_ALGORITHM_FAMILIES
    mode := get_component_mode_or_empty(component)
    mode == "gcm"
} else if {
    mode := get_component_mode_or_empty(component)
    mode == "gcm"
    is_ae_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "gcm")
}

is_eax_scheme(component) if {
    is_ae_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in EAX_AE_ALGORITHM_OID_VALUES
} else if {
    is_ae_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "eax")
}

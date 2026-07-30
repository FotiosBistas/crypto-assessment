package cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.get_note

import data.cbom.eccg.asymmetric_constructions.helpers.get_key_establishment_scheme_display_name
import data.cbom.eccg.asymmetric_constructions.helpers.is_eccg_agreed_key_establishment_scheme
import data.cbom.eccg.asymmetric_constructions.helpers.is_key_establishment_or_key_encapsulation_scheme
import data.cbom.eccg.asymmetric_constructions.helpers.key_establishment_scheme_display_names
import data.cbom.eccg.asymmetric_constructions.helpers.key_establishment_scheme_display_names_text

default compliant := true

compliant if count(findings) == 0

SECTION := "Asymmetric-Constructions"
SUBSECTION := "Key-Establishment-and-Key-Encapsulation-Schemes"

#
# ---------------------------------------------------------
# ECCG-KEE-001
# DH, DLIES-KEM, EC-DH, and ECIES-KEM are the only
# recommended key establishment and key encapsulation schemes.
#
# This rule flags any identifiable key-establishment or KEM component
# that is not one of those four schemes.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_key_establishment_or_key_encapsulation_scheme(component)
    not is_eccg_agreed_key_establishment_scheme(component)

    detected_scheme := get_key_establishment_scheme_display_name(component)

    finding := build_finding(
        "ECCG-KEE-001",
        "critical",
        sprintf(
            "Key establishment or key encapsulation scheme '%s' is not one of the ECCG recommended schemes. The recommended schemes are %s.",
            [detected_scheme, key_establishment_scheme_display_names_text]
        ),
        component,
        {
            "detectedScheme": detected_scheme,
            "status": "not_recommended",
            "classification": "non_compliant",
            "decision": "reject",
            "recommendedSchemes": key_establishment_scheme_display_names,
            "complianceImpact": "DH, DLIES-KEM, EC-DH, and ECIES-KEM are the only recommended key establishment and key encapsulation schemes."
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-KEE-002
# The parties that participate in a key establishment scheme
# must be authenticated.
#
# CBOM data does not currently prove that the parties, exchanged
# public values/ciphertexts, and identities are authenticated. Emit an
# implementation-obligation finding for each recommended scheme so the
# review does not miss the authentication requirement.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_eccg_agreed_key_establishment_scheme(component)

    detected_scheme := get_key_establishment_scheme_display_name(component)
    note := get_note(SECTION, SUBSECTION, "57-KE-Auth")

    finding := build_finding(
        "ECCG-KEE-002",
        "warning",
        sprintf(
            "%s is a recommended key establishment or key encapsulation scheme, but participating parties and exchanged key-establishment data must be authenticated.",
            [detected_scheme]
        ),
        component,
        {
            "detectedScheme": detected_scheme,
            "status": "authentication_required",
            "classification": "R",
            "note": note,
            "complianceImpact": "The CBOM identifies the scheme, but does not prove the party-authentication requirement."
        }
    )
}

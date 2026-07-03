# ECCG Detection Notes

This document explains how ECCG rule findings should be interpreted when they
depend on CBOMkit output, Rego policy evaluation, independent Semgrep
source-code findings, and manual review.

## General CBOM Limitations

### Size and Parameter Data

Rules that depend on key size, hash output size, RSA modulus size, finite-field
group size, or MAC key size are only reliable when the relevant size is present
and correctly represented in the CBOM.

The current policies often fall back to:

`cryptoProperties.algorithmProperties.parameterSetIdentifier`

This field is not always the actual key size or output size. If it is missing,
non-numeric, or semantically ambiguous, the rule should be treated as
inconclusive. Separate Semgrep source-code findings may add evidence when
explicit source-level sizes are visible, such as hard-coded key lengths or
key-generation arguments, but they do not cover imported or runtime-generated
keys.

### Runtime and Data-Flow Properties

CBOMkit generally does not prove:

- whether an IV/nonce is unique, random, unpredictable, or reused;
- whether a MAC/tag is truncated after generation;
- whether encryption is followed by MAC verification in the correct order;
- whether Encrypt-then-MAC, MAC-then-Encrypt, or Encrypt-and-MAC is used;
- how much plaintext is processed under one key/IV domain;
- whether a KDF is being used specifically for password hashing, password
  verification, or general key derivation;
- whether peers and exchanged values are authenticated in a key exchange;
- which TLS version or cipher suite is negotiated at runtime.

Separate Semgrep source rules may flag some visible source-code patterns, but
dynamic values, configuration loaded from outside the source tree, wrappers,
generated code, and runtime negotiation may still require manual review. Runtime
and dynamic operations may be impossible to detect statically, even with
Semgrep.

## Missing or Weak ECCG Coverage in the Deliverable

These are gaps in the mappings created in the deriverable when compared with rules with the ECCG document. 

### Stream-Mode Keystream Overlap

ECCG note 7-StreamMode says CTR and OFB must be used so that generated keystreams do not overlap under the same key/IV domain. The current policies
mention IV/nonce uniqueness, but there is no clear standalone CBOM/Rego rule mentioned in the deriverable for CTR/OFB keystream-overlap risk. CBOM also cannot prove keystream non-overlap because it requires key/IV lifecycle and message-domain reasoning.

### Padding-Sensitive Schemes

ECCG note 8-Padding is not surfaced as an active finding for CBC/CFB-style padding-sensitive usage in the deriverable. The helper exists, but the Rego finding is currently commented out in `aes_modes.rego`. The missing review point is padding-oracle
behavior and plaintext format validation during decryption.

Also note that it might not be possible to detect through CBOM alone.


### GMAC Tag-Length Rule Shape

`ECCG-GMAC-003` exists, but GMAC is not handled in exactly the same shape as the
general MAC truncation rule `ECCG-MAC-003`. This is intentional only if the
GMAC-specific bound is documented clearly: GMAC/GCM agreed options require a
128-bit tag, so the general "not below 96 bits" MAC rule is not sufficient.
CBOM does not expose final tag length or verification bounds.

### Symmetric Entity Authentication Schemes

The ECCG-SEAS agreed schemes are not currently represented as a clear CBOM/Rego
allowlist in the deliverablefor agreed symmetric entity-authentication schemes. Challenge freshness
and challenge length are visible only in limited source-code patterns and are
not CBOM properties. These rules need explicit policy design and likely manual
review for protocol context.

### Asymmetric Encryption and Quantum Notes

The asymmetric-encryption notes are skipped in the deliverable. OAEP and PKCS#1
v1.5 findings should include random-padding and quantum-threat notes. 

### FF-DLOG Notes and Parameter Generation

FF-DLOG parameter generation, subgroup correctness, and manipulated-value checks are completely missing from the deriverable.
They also cannot be detected from CBOM. General ECCG notes such as
31-CorrectSubgroup and 32-QuantumThreat are not fully surfaced in every relevant
finding, and parameter-generation assurance remains outside CBOM/Rego coverage.

### EC-DLOG Notes

`ECCG-ECDLOG-002` does attach 39-SpecialP for NIST curves, so this note is not
entirely missing. However, EC-DLOG general notes such as point-on-curve,
point-in-subgroup, prime-order conditions, and quantum-threat guidance are not
fully represented as findings. CBOM can often identify a curve, but it cannot
prove point validation or subgroup validation in the implementation.

### Lattice and Post-Quantum Mechanisms

The current policy set does not clearly document lattice-based mechanisms as a
separate coverage area. Recommended stuff is missing from the ECCG document aswell.

### Digital Signature Notes

`ECCG-DG-001` currently attaches only a subset of the ECCG digital-signature
notes, and only for the legacy branch. Notes about agreed hash functions,
underlying mathematical parameters, DSA/ECDSA per-signature randomness,
quantum threat, hybridization, stateful signature state management, and
ML-DSA/SLH-DSA parameters are not consistently represented in the CBOM policy
findings.

### Random Generators, Key Management, and Person Authentication

Random-bit generation, key-management process requirements, and person or user
authentication requirements are not represented as complete CBOM/Rego policy
rules in the deriverable. 


# CBOM ( due to runtime constraints or complex mutli-line code ) and CBOMkit analyzer limitations

## Symmetric Encryption

### CCM and GCM 

CCM is not reliably detected through CBOMkit and the same goes GCM. Might need Semgrep rules.

### ECCG-SYM-ENC-002

CTR, CBC, OFB, CFB, and CBC-CS are conditionally recommended because standalone
confidentiality-only use is legacy unless additional integrity is provided.

CBOM can classify the mode, but it cannot prove that the implementation uses
Encrypt-then-MAC or an equivalent authenticated construction. Separate Semgrep
source-code findings may add evidence for visible encryption-only usage or
nearby MAC/AEAD APIs, but they do not prove the composition order. Manual source
review is still required when the order or data flow matters.

### ECCG-SYM-ENC-003

CBC, CFB, OFB, and GCM require IV/nonce handling. CBC and CFB additionally
require unpredictability.

CBOM can identify that a mode falls under the IV/nonce rule, but it cannot prove
uniqueness, randomness, unpredictability, or non-reuse. Separate Semgrep
source-code findings may flag visible bad patterns such as literals, zero
values, constants, reused variables, or predictable construction patterns. They
do not prove correct IV lifecycle management.

### ECCG-SYM-ENC-004

For GCM, the IV must be a random 96-bit value or be generated with the
deterministic construction from NIST SP 800-38D section 8.2.

CBOM can identify GCM, but it does not expose enough IV construction metadata to
prove compliance. Separate Semgrep source-code findings may identify visible
fixed, non-96-bit, or obviously predictable GCM nonce/IV values. Dynamic IV
generation may remain inconclusive.

### ECCG-SYM-ENC-005

For GCM, the plaintext length for one invocation must be at most `2^32 - 2`
blocks.

CBOM does not know the amount of plaintext processed under a single key/IV usage
domain. Separate Semgrep source-code findings may point to obvious
bulk-encryption patterns, but they do not prove the GCM invocation bound. This
is mostly an implementation and operational review requirement.

## MAC, HMAC, KMAC, and GMAC

### ECCG-MAC-002

CBC-MAC is agreed only when every input authenticated under the same key has the
same length.

CBOM cannot reliably distinguish CBC encryption from a manually implemented
CBC-MAC construction. The current policy therefore treats CBC-based MAC
detection as heuristic. Separate Semgrep source-code findings may add evidence
for CBC-MAC-like code, especially CBC encryption where the last ciphertext block
is returned as the tag. The fixed message-length condition usually remains a
manual review point.

### ECCG-MAC-003

CMAC, CBC-MAC, HMAC, KMAC128, and KMAC256 outputs must not be truncated below
96 bits.

CBOM does not expose the final emitted MAC/tag length after source-level
truncation. Separate Semgrep source-code findings may flag visible digest/tag
slicing below 12 bytes, or hexdigest truncation below 24 hex characters. If
truncation length is computed dynamically or hidden in a helper, the result may
remain inconclusive.

### ECCG-HMAC-001

HMAC key size must be at least 125 bits.

CBOMkit does not reliably expose runtime HMAC key size. Rego can only use
`parameterSetIdentifier` when it is present and meaningful. Separate Semgrep
source-code findings may add evidence for explicit key byte lengths, short
literals, and obvious weak key construction. Imported, generated, or externally
configured keys need manual review.

### ECCG-KMAC-001

KMAC128 key size must be at least 125 bits.

The same key-size limitation applies: CBOM can only support this rule when
`parameterSetIdentifier` or equivalent metadata actually represents the KMAC key
size. Separate Semgrep source-code findings may flag explicit short keys, but
dynamic keys remain review items.

### ECCG-KMAC-002

KMAC256 key size must be at least 250 bits.

CBOMkit does not reliably expose the runtime key size. Treat the Rego result as
reliable only when the parameter identifier is populated correctly. Use separate
Semgrep source-code findings only as supplementary evidence for visible short
keys. Generated or external keys require manual review.

### ECCG-GMAC-001

GMAC requires an IV that is not reused with the same key for different input
data.

CBOMkit may report authentication-only GMAC usage as GCM, and may not preserve a
clear distinction between GMAC and normal GCM/AEAD usage. The policy therefore
treats GCM as GMAC-like in some contexts. Separate Semgrep source-code findings
may identify visible nonce-reuse risks or fixed nonce values, but true non-reuse
is a runtime/key-lifecycle property.

### ECCG-GMAC-002

GMAC requires a 96-bit random IV or the deterministic construction from NIST
SP 800-38D section 8.2.1.

CBOM can identify GCM/GMAC-like components but does not prove IV length or
construction. Separate Semgrep source-code findings may flag visible
non-96-bit nonce lengths, literals, constant values, and suspicious construction
patterns.

### ECCG-GMAC-003

GMAC output must not be truncated without validating GMAC-specific security
bounds. The agreed GCM/GMAC options require a 128-bit tag, so truncation to
96 bits is not acceptable for this rule.

CBOM does not expose final tag length, verification counts, key lifetime, or
security-bound assumptions. Separate Semgrep source-code findings may flag tag
slicing, `mac_len`, `min_tag_length`, and similar API parameters where present.
Remaining cases need manual review.

## Secret Sharing

### ECCG-SS-001

Shamir secret sharing is the only recommended secret sharing scheme.

CBOMkit does not reliably model secret sharing as a first-class cryptographic
component. Separate Semgrep source-code findings may provide supplementary
evidence for ad-hoc splitting, slicing, chunking, XOR sharing, and share
list/dictionary construction. Findings should be suppressed when an approved
Shamir API such as `Crypto.Protocol.SecretSharing.Shamir` is used.

This rule should be treated as heuristic because string/byte splitting can be
non-cryptographic.

## Password Hashing

### ECCG-PWH-001, ECCG-PWH-002, and ECCG-PWH-003

PBKDF2 is the recommended password protection/hashing mechanism. PBKDF2 must
use a random salt of at least 128 bits and a sufficiently large iteration count.

CBOMkit usually represents PBKDF2 as a generic KDF and does not say whether the
KDF is being used for password hashing, password verification, or general key
derivation. This makes password hashing difficult to implement as a pure CBOM
policy.

Separate Semgrep source-code findings may add evidence for visible
password-hashing API usage, explicit salt length, iteration count, and weak
underlying hashes such as SHA-1. Dynamic configuration, framework wrappers, and
password-vs-KDF intent may still require manual review.

## Asymmetric Atomic Primitives

### ECCG-RSA-001

RSA modulus size must be at least 3000 bits and the public exponent must satisfy
`log2(e) > 16`.

CBOM can sometimes expose RSA modulus size through `parameterSetIdentifier`, but
it does not reliably expose the public exponent. Therefore the exponent
condition cannot be verified from CBOM alone. Separate Semgrep source-code
findings may add evidence when source-level key generation exposes
`public_exponent` and `key_size` arguments, but imported keys, certificates, and
keys loaded from external stores remain inconclusive.

### ECCG-FFDLOG-001

MODP groups from RFC 3526 and FFDHE groups from RFC 7919 are the only
recommended finite-field discrete logarithm parameter families.

CBOMkit may not emit finite-field DH, MODP, or FFDHE parameters at all. When it
does, the family may appear only in the component name, algorithm family, or
`parameterSetIdentifier`. If no family signal is present, this rule cannot be
decided from CBOM alone.

### ECCG-FFDLOG-002

MODP and FFDHE group size must be at least 3072 bits.

This rule is actionable only when the group size is visible as a numeric
`parameterSetIdentifier` or as a standardized token such as `ffdhe3072` or
`modp3072`. Generic DH without group-size metadata should be reported as
inconclusive rather than treated as a proven pass or fail.

## Asymmetric Constructions

### Asymmetric Encryption

CBOMkit has limited direct detection for asymmetric encryption constructions.
The Rego policy relies on available primitive fields, component names, padding
fields, and crypto functions. Separate Semgrep source-code findings may add
evidence for library/API patterns that are visible in source code.

For `ECCG-AS-ENC-001`, separate Semgrep source-code findings may identify
RSAES-OAEP when APIs such as `padding.OAEP(...)` are visible. They may also
identify RSAES-PKCS1-v1_5 when that API usage is visible. If CBOM only says
"RSA encryption" without padding/scheme metadata, the Rego result should be
inconclusive.

### Digital Signatures

CBOMkit may provide little or no reliable direct detection for digital
signature schemes. The Rego policy therefore relies on primitive values,
signature crypto functions, and name-based matching.

For `ECCG-DG-001`, separate Semgrep source-code findings may add evidence for
concrete APIs such as PSS, PKCS1v15, ECDSA, EdDSA, DSA, and post-quantum
signature APIs where present. If no signature component appears in the CBOM,
that should not be interpreted as proof that the code does not use digital
signatures.

### Asymmetric Authentication

If CBOMkit does not detect digital signatures reliably, it will also be weak for
asymmetric authentication schemes that depend on signatures or public-key
credentials. Treat absence of CBOM findings as lack of evidence, not evidence of
absence. Separate Semgrep source-code findings and protocol/source review are
required.

## Key Establishment and Key Encapsulation

### ECCG-KEE-001

DH, DLIES-KEM, EC-DH, and ECIES-KEM are the recommended key establishment and
key encapsulation schemes.

CBOM/Rego can classify schemes only when component names, primitive fields, or
algorithm identifiers expose enough information. Some constructions may appear
as lower-level DH/ECDH plus KDF plus AEAD building blocks rather than as a
single ECIES-KEM or DLIES-KEM component.

### ECCG-KEE-002

The parties participating in key establishment must be authenticated.

This cannot be proven from CBOM alone. Authentication is a protocol property: it
depends on peer identity validation, certificate or signature checks, binding of
public values/ciphertexts to identities, and long-term authentication material.

Separate Semgrep source-code findings may flag obvious risky patterns, such as
disabled certificate validation or unauthenticated key exchange wrappers. Full
compliance requires source and design review.

There are no reliable Rego-only findings for asymmetric key encapsulation and
establishment authentication because the necessary evidence is not present in
the CBOM.

## TLS

### ECCG-TLS-001

TLS 1.3 is the recommended TLS version.

TLS configuration is often more visible to separate Semgrep source-code rules
than to CBOM/Rego because it is usually expressed through Python `ssl`,
pyOpenSSL, urllib3, aiohttp, httpx, asyncio, and framework configuration code.
PyCA `cryptography` is not a TLS implementation, so it does not expose TLS
protocol negotiation or TLS cipher-suite selection.

Semgrep source-code findings may flag visible legacy TLS/SSL constants, min/max
version settings, TLS 1.3 being disabled, and contexts that do not visibly
enforce TLS 1.3. Runtime negotiation and externally loaded configuration may
still need review.

### ECCG-TLS-002

Only the approved TLS 1.3 cipher suites are recommended:

- `TLS_AES_128_GCM_SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_AES_128_CCM_SHA256`

Accessing the underlying implementations and effective cipher-suite behavior of
each TLS library is difficult or impossible from CBOM alone. Python/OpenSSL also
distinguishes legacy cipher strings from TLS 1.3 cipher-suite configuration, and
runtime OpenSSL defaults may affect what is actually negotiated.

Semgrep source-code findings may flag visible legacy cipher strings, TLS
versions below 1.3, and obvious non-approved cipher-suite configuration.
Proving that only the approved TLS 1.3 cipher suites are enabled may require
runtime inspection of the TLS library, server/client configuration, and
negotiated handshake behavior.

When checking TLS algorithms for legacy status, assess the underlying primitives
as well. For example, TLS suites using legacy hashes, RSA key exchange, CBC
modes, or non-approved groups should be reviewed even if the TLS wrapper itself
is detected through Semgrep.

# CBOM specification limitations 
- EAX does not seem to be defined in the cryptography registry of CBOM at all. 
- CBC-MAC is not defined as a seperate scheme in the cryptography registry 
- CBC-ESSIV >> 
- Shamir Secret Sharing >> 
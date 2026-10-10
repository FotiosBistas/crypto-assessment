"""SHAKE XOF examples using PyCA/cryptography.

Designed as small, separately callable examples for CycloneDX CBOM / ECCG
policy testing. An XOF's output length is specified in *bytes*.

PyCA/cryptography supports SHAKE128 and SHAKE256, but does not currently
expose cSHAKE128 or cSHAKE256 in its hashes API.
"""

from cryptography.hazmat.primitives import hashes


def fire_eccg_xof_quantum_threat_shake128():
    """SHAKE128 with a 256-bit (32-byte) output, below 384 bits.

    SHAKE128 also has a lower intrinsic security strength than SHAKE256,
    regardless of how many output bytes are requested.
    """
    digest = hashes.Hash(hashes.SHAKE128(32))
    digest.update(b"Example input for SHAKE128")
    return digest.finalize()


def fire_eccg_xof_quantum_threat_shake256_short_output():
    """SHAKE256 with a 256-bit (32-byte) output, below 384 bits."""
    digest = hashes.Hash(hashes.SHAKE256(32))
    digest.update(b"Example input for SHAKE256")
    return digest.finalize()


def use_eccg_xof_shake256_long_output():
    """SHAKE256 with a 512-bit (64-byte) output, above 384 bits."""
    digest = hashes.Hash(hashes.SHAKE256(64))
    digest.update(b"Example input for SHAKE256")
    return digest.finalize()


if __name__ == "__main__":
    shake128_output = fire_eccg_xof_quantum_threat_shake128()
    shake256_short_output = fire_eccg_xof_quantum_threat_shake256_short_output()
    shake256_long_output = use_eccg_xof_shake256_long_output()

    print("SHAKE128 (256-bit output):", shake128_output.hex())
    print("SHAKE256 (256-bit output):", shake256_short_output.hex())
    print("SHAKE256 (512-bit output):", shake256_long_output.hex())


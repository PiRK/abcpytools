import ecdsa


def public_key_from_private_key(privkey: bytes, compressed: bool) -> bytes:
    """Compute a public key from a private key.

    The private key must be 32 bytes long.

    Uncompressed public keys are 65 bytes long:
        0x04 + 32-byte X-coordinate + 32-byte Y-coordinate

    Compressed keys are 33 bytes long:
        <sign> <x> where <sign> is 0x02 if y is even and 0x03 if y is odd
    """
    assert len(privkey) == 32
    secret = int(privkey.hex(), 16)
    pubkey = ecdsa.ecdsa.Public_key(
        ecdsa.ecdsa.generator_secp256k1, ecdsa.ecdsa.generator_secp256k1 * secret)

    if compressed:
        if pubkey.point.y() & 1:
            key = '03' + '%064x' % pubkey.point.x()
        else:
            key = '02' + '%064x' % pubkey.point.x()
    else:
        key = '04' + \
              '%064x' % pubkey.point.x() + \
              '%064x' % pubkey.point.y()

    return bytes.fromhex(key)

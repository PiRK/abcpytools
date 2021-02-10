import struct
from typing import Optional, Tuple

from hash import sha256d


MAINNET_WIF_PREFIX = 0x80

b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'


def base_decode(v: str, base: int) -> Optional[bytes]:
    """ decode v into a string of len bytes. May raise ValueError on bad chars
    in string."""
    if base not in (58, 43):
        raise ValueError(f'not supported base: {base}')
    v = v.encode('ascii')
    chars = b58chars if base == 58 else b43chars
    long_value = 0
    power_of_base = 1
    for c in v[::-1]:
        digit = chars.find(bytes((c,)))
        if digit < 0:
            raise ValueError("Forbidden character '{}' for base {}".format(chr(c), base))
        # naive but slow variant:   long_value += digit * (base**i)
        long_value += digit * power_of_base
        power_of_base *= base
    result = bytearray()
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result.append(mod)
        long_value = div
    result.append(long_value)
    nPad = 0
    for c in v:
        if c == chars[0]:
            nPad += 1
        else:
            break
    result.extend(b'\x00' * nPad)
    result.reverse()
    return bytes(result)


class DecodeError(Exception):
    pass


class InvalidChecksum(DecodeError):
    pass


def decode_base58_check(psz: str) -> bytes:
    vchRet = base_decode(psz, base=58)
    payload = vchRet[0:-4]
    csum_found = vchRet[-4:]
    csum_calculated = sha256d(payload)[0:4]
    if csum_calculated != csum_found:
        raise InvalidChecksum(
            f'calculated {csum_calculated.hex()}, found {csum_found.hex()}')
    return payload


def deserialize_privkey(key: str) -> Tuple[str, bytes, bool]:
    """Returns the deserialized key if key is a WIF key, raises
    otherwise."""
    try:
        vch = decode_base58_check(key)
    except Exception as e:
        neutered_privkey = str(key)[:3] + '..' + str(key)[-2:]
        raise DecodeError(f"cannot deserialize privkey {neutered_privkey}") from e

    script_type = vch[0] - MAINNET_WIF_PREFIX
    if script_type == 0:
        txin_type = 'p2pkh'
    elif script_type == 5:
        txin_type = 'p2sh'
    else:
        raise DecodeError(f'Unknow script type {script_type}')
    if len(vch) not in (33, 34):
        raise DecodeError(f'Key {key} has invalid length')
    compressed = len(vch) == 34
    if compressed and vch[33] != 0x1:
        raise DecodeError(f'Invalid WIF key. Length suggests compressed pubkey, '
                          f'but last byte is 0x{vch[33]} != 0x01')
    return txin_type, vch[1:33], compressed


def write_compact_size(nsize: int) -> bytes:
    """Serialize a size. Values lower than 253 are serialized using 1 byte.
    For larger values, the first byte indicates how many additional bytes to
    read when decoding (253: 2 bytes, 254: 4 bytes, 255: 8 bytes)

    :param nsize: value to serialize
    :return:
    """
    assert nsize >= 0
    if nsize < 253:
        return struct.pack("B", nsize)
    if nsize < 0x10000:
        return struct.pack("BH", 253, nsize)
    if nsize < 0x100000000:
        return struct.pack("BL", 254, nsize)
    assert nsize < 0x10000000000000000
    return struct.pack("BQ", 255, nsize)

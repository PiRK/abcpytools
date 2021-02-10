"""This module deals with Eliptical Curve Operations:
keys, signing
"""
import base64
import binascii
import ecdsa
import hashlib
import hmac
import pyaes

from .hash import sha256d
from .serialize import write_compact_size


def msg_magic(message):
    return b"\x18Bitcoin Signed Message:\n" + write_compact_size(len(message)) + message


def public_key_from_private_key(privkey: bytes, compressed: bool) -> bytes:
    """Compute a public key from a private key.

    The private key must be 32 bytes long.

    Uncompressed public keys are 65 bytes long:
        0x04 + 32-byte X-coordinate + 32-byte Y-coordinate

    Compressed keys are 33 bytes long:
        <sign> <x> where <sign> is 0x02 if y is even and 0x03 if y is odd
    """
    key = ECKey(privkey)
    return key.get_public_key(compressed)


# from http://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python/
def modular_sqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
    must be an odd prime.

    Solve the congruence of the form:
    x^2 = a (mod p)
    And returns x. Note that p - x is also a root.

    0 is returned is no square root exists for
    these a and p.

    The Tonelli-Shanks algorithm is used (except
    for some simple cases in which the solution
    is known from an identity). This algorithm
    runs in polynomial time (unless the
    generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
    Euler's criterion. p is a prime, a is
    relatively prime to p (if p divides
    a, then a|p = 0)

    Returns 1 if a has a square root modulo
    p, -1 otherwise.
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


class MySigningKey(ecdsa.SigningKey):
    """Enforce low S values in signatures"""

    def sign_number(self, number, entropy=None, k=None):
        curve = ecdsa.curves.SECP256k1
        G = curve.generator
        order = G.order()
        r, s = ecdsa.SigningKey.sign_number(self, number, entropy, k)
        if s > order//2:
            s = order - s
        return r, s


class MyVerifyingKey(ecdsa.VerifyingKey):
    @classmethod
    def from_signature(klass, sig, recid, h, curve):
        """ See http://www.secg.org/download/aid-780/sec1-v2.pdf, chapter 4.1.6 """
        curveFp = curve.curve
        G = curve.generator
        order = G.order()
        # extract r,s from signature
        r, s = ecdsa.util.sigdecode_string(sig, order)
        # 1.1
        x = r + (recid//2) * order
        # 1.3
        alpha = (x * x * x + curveFp.a() * x + curveFp.b()) % curveFp.p()
        beta = modular_sqrt(alpha, curveFp.p())
        y = beta if (beta - recid) % 2 == 0 else curveFp.p() - beta
        # 1.4 the constructor checks that nR is at infinity
        R = ecdsa.ellipticcurve.Point(curveFp, x, y, order)
        # 1.5 compute e from message:
        e = int(h.hex(), 16)
        minus_e = -e % order
        # 1.6 compute Q = r^-1 (sR - eG)
        inv_r = ecdsa.numbertheory.inverse_mod(r, order)
        Q = inv_r * (s * R + minus_e * G)
        return klass.from_public_point(Q, curve)


def pubkey_from_signature(sig, h):
    if len(sig) != 65:
        raise Exception("Wrong encoding")
    nV = sig[0]
    if nV < 27 or nV >= 35:
        raise Exception("Bad encoding")
    if nV >= 31:
        compressed = True
        nV -= 4
    else:
        compressed = False
    recid = nV - 27
    return MyVerifyingKey.from_signature(
        sig[1:], recid, h, curve=ecdsa.curves.SECP256k1), compressed


def number_to_string(num: int, order: int) -> bytes:
    l = ecdsa.util.orderlen(order)
    fmt_str = "%0" + str(2 * l) + "x"
    string = binascii.unhexlify((fmt_str % num).encode())
    assert len(string) == l, (len(string), l)
    return string


class InvalidPadding(Exception):
    pass


class InvalidPassword(Exception):
    def __str__(self):
        return "Incorrect password"


def append_PKCS7_padding(data: bytes) -> bytes:
    padlen = 16 - (len(data) % 16)
    return data + bytes([padlen]) * padlen


def strip_PKCS7_padding(data: bytes) -> bytes:
    if len(data) % 16 != 0 or len(data) == 0:
        raise InvalidPadding("invalid length")
    padlen = data[-1]
    if padlen > 16:
        raise InvalidPadding("invalid padding byte (large)")
    for i in data[-padlen:]:
        if i != padlen:
            raise InvalidPadding("invalid padding byte (inconsistent)")
    return data[0:-padlen]


def aes_encrypt_with_iv(key: bytes, iv: bytes, data: bytes):
    data = append_PKCS7_padding(data)
    aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
    aes = pyaes.Encrypter(aes_cbc, padding=pyaes.PADDING_NONE)
    e = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    return e


def aes_decrypt_with_iv(key: bytes, iv:  bytes, data: bytes) -> bytes:
    aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
    aes = pyaes.Decrypter(aes_cbc, padding=pyaes.PADDING_NONE)
    data = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    try:
        return strip_PKCS7_padding(data)
    except InvalidPadding:
        raise InvalidPassword()


class ECKey(object):

    def __init__(self, k: bytes):
        assert len(k) == 32
        secret = int(k.hex(), 16)
        self.pubkey = ecdsa.ecdsa.Public_key(
            ecdsa.ecdsa.generator_secp256k1,
            ecdsa.ecdsa.generator_secp256k1 * secret)
        self.privkey = ecdsa.ecdsa.Private_key(self.pubkey, secret)
        self.secret = secret

    def get_public_key(self, compressed: bool) -> bytes:
        if compressed:
            if self.pubkey.point.y() & 1:
                key = '03' + '%064x' % self.pubkey.point.x()
            else:
                key = '02' + '%064x' % self.pubkey.point.x()
        else:
            key = '04' + \
                  '%064x' % self.pubkey.point.x() + \
                  '%064x' % self.pubkey.point.y()

        return bytes.fromhex(key)

    def sign(self, msg_hash):
        private_key = MySigningKey.from_secret_exponent(
            self.secret, curve=ecdsa.curves.SECP256k1)
        public_key = private_key.get_verifying_key()
        signature = private_key.sign_digest_deterministic(
            msg_hash, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_string)
        assert public_key.verify_digest(
            signature, msg_hash, sigdecode=ecdsa.util.sigdecode_string)
        return signature

    def sign_message(self, message: bytes, is_compressed: bool):
        signature = self.sign(sha256d(msg_magic(message)))
        for i in range(4):
            sig = bytes([27 + i + (4 if is_compressed else 0)]) + signature
            try:
                self.verify_message(sig, message)
                return sig
            except Exception as e:
                continue
        else:
            raise Exception("error: cannot sign message")

    def verify_message(self, sig, message: bytes):
        h = sha256d(msg_magic(message))
        public_key, compressed = pubkey_from_signature(sig, h)
        # check public key
        if point_to_ser(public_key.pubkey.point, compressed) != point_to_ser(self.pubkey.point, compressed):
            raise Exception("Bad signature")
        # check message
        public_key.verify_digest(sig[1:], h, sigdecode=ecdsa.util.sigdecode_string)

    # ECIES encryption/decryption methods;
    # AES-128-CBC with PKCS7 is used as the cipher;
    # hmac-sha256 is used as the mac
    @classmethod
    def encrypt_message(self, message: bytes, pubkey):
        pk = ser_to_point(pubkey)
        if not ecdsa.ecdsa.point_is_valid(
                ecdsa.ecdsa.generator_secp256k1, pk.x(), pk.y()):
            raise Exception('invalid pubkey')

        ephemeral_exponent = number_to_string(
            ecdsa.util.randrange(pow(2, 256)),
            ecdsa.ecdsa.generator_secp256k1.order())
        ephemeral = ECKey(ephemeral_exponent)
        ecdh_key = point_to_ser(pk * ephemeral.privkey.secret_multiplier)
        key = hashlib.sha512(ecdh_key).digest()
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]
        ciphertext = aes_encrypt_with_iv(key_e, iv, message)
        ephemeral_pubkey = ephemeral.get_public_key(compressed=True)
        encrypted = b'BIE1' + ephemeral_pubkey + ciphertext
        mac = hmac.new(key_m, encrypted, hashlib.sha256).digest()

        return base64.b64encode(encrypted + mac)

    def decrypt_message(self, encrypted):
        encrypted = base64.b64decode(encrypted)
        if len(encrypted) < 85:
            raise Exception('invalid ciphertext: length')
        magic = encrypted[:4]
        ephemeral_pubkey = encrypted[4:37]
        ciphertext = encrypted[37:-32]
        mac = encrypted[-32:]
        if magic != b'BIE1':
            raise Exception('invalid ciphertext: invalid magic bytes')
        try:
            ephemeral_pubkey = ser_to_point(ephemeral_pubkey)
        except AssertionError as e:
            raise Exception('invalid ciphertext: invalid ephemeral pubkey')
        if not ecdsa.ecdsa.point_is_valid(
                ecdsa.ecdsa.generator_secp256k1,
                ephemeral_pubkey.x(), ephemeral_pubkey.y()):
            raise Exception('invalid ciphertext: invalid ephemeral pubkey')
        ecdh_key = point_to_ser(ephemeral_pubkey * self.privkey.secret_multiplier)
        key = hashlib.sha512(ecdh_key).digest()
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]
        if mac != hmac.new(key_m, encrypted[:-32], hashlib.sha256).digest():
            raise InvalidPassword()
        return aes_decrypt_with_iv(key_e, iv, ciphertext)


def ECC_YfromX(x, odd=True):
    _p = ecdsa.ecdsa.curve_secp256k1.p()
    _a = ecdsa.ecdsa.curve_secp256k1.a()
    _b = ecdsa.ecdsa.curve_secp256k1.b()
    for offset in range(128):
        Mx = x + offset
        My2 = pow(Mx, 3, _p) + _a * pow(Mx, 2, _p) + _b % _p
        My = pow(My2, (_p + 1) // 4, _p)

        if ecdsa.ecdsa.curve_secp256k1.contains_point(Mx, My):
            if odd == bool(My & 1):
                return [My, offset]
            return [_p - My, offset]
    raise Exception('ECC_YfromX: No Y found')


def ser_to_point(Aser) -> ecdsa.ellipticcurve.Point:
    curve = ecdsa.ecdsa.curve_secp256k1
    generator = ecdsa.ecdsa.generator_secp256k1
    _r = generator.order()
    assert Aser[0] in [0x02, 0x03, 0x04]
    if Aser[0] == 0x04:
        return ecdsa.ellipticcurve.Point(
            curve, ecdsa.util.string_to_number(Aser[1:33]),
            ecdsa.util.string_to_number(Aser[33:]), _r)
    Mx = ecdsa.util.string_to_number(Aser[1:])
    My = ECC_YfromX(Mx, Aser[0] == 0x03)[0]
    return ecdsa.ellipticcurve.Point(curve, Mx, My, _r)


def point_to_ser(P: ecdsa.ellipticcurve.Point, comp: bool = True) -> bytes:
    if comp:
        return bytes.fromhex(('%02x' % (2 + (P.y() & 1))) + ('%064x' % P.x()))
    return bytes.fromhex('04'+('%064x' % P.x()) + ('%064x' % P.y()))
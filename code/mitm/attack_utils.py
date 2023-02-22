# Based on attack_utils.py of the original Mega PoC code

import base64
import binascii
import pickle
from secrets import token_bytes

# PyCryptodome
from Crypto.Cipher import AES
import Crypto.Util.number

# mega parameters 
       
BYTELEN_D = 256
BYTELEN_P = BYTELEN_Q = BYTELEN_U = 128

BLOCK_BITLEN = 128
BLOCK_BYTELEN = BLOCK_BITLEN // 8

PK_EXP = 257  # e used by Mega
PK_N_BITLEN = 2048

#
# Generic
#

# conversions

def int_to_bytes(i):
    return i.to_bytes(ceil_int_div(i.bit_length(), 8), byteorder="big")

def bytes_to_int(b):
    return int.from_bytes(b, byteorder="big")

def int_to_str(i):
    return int_to_bytes(i).decode()

def str_to_int(s):
    return bytes_to_int(s.encode())

def int_to_urlb64_str(n):
    return url_encode(int_to_bytes(n)).decode("utf-8")

def int_to_b64(n):
    return base64.b64encode(int_to_bytes(n)).decode("utf-8")

def b64_to_int(b64_str):
    return int.from_bytes(base64.b64decode(b64_str), byteorder="big")

def ceil_int_div(numerator, denominator):
    return (numerator + denominator - 1) // denominator

def floor_int_div(numerator, denominator):
    return numerator // denominator

def long_to_bytes(n, blen):
    assert bytelen(n) <= blen
    return Crypto.Util.number.long_to_bytes(n, blen)

# lengths

def bitlen(n):
    return Crypto.Util.number.size(n)

def bytelen(n):
    return Crypto.Util.number.ceil_div(bitlen(n), 8)

def blocklen(s: bytes):
    assert len(s) % BLOCK_BYTELEN == 0
    
    return len(s) // BLOCK_BYTELEN

def pad_len(x, l):
    """
    Return the length of padding that must be appended to a message of length x
    to make it a multiple of l.
    """
    if x % l == 0:
        return 0
    return l - (x % l)

# load-able class

class Attack:
    @classmethod
    def load(cls, filename):
        """
        Load object data from file storage.
        """
        with open(filename, 'rb') as f:
            return pickle.load(f)

    def save(self):
        """
        Save object as a binary file, so that precomputed values can be reused in later runs.
        """
        print("writing object data to {}...".format(self.file_b))
        with open(self.file_b, 'wb') as f:
            pickle.dump(self, f)

#
# Mega-specific
#

def is_2nd_byte_zero(x, nlen):
    return is_ith_byte_zero(2, x, nlen)

def is_ith_byte_zero(i, x, nlen):
    assert i > 0
    assert bytelen(x) <= nlen
    ith_byte = (x >> (8 * (nlen - i))) & 0xff
    return ith_byte == 0

# encoding

# URL-safe Base64 encoding used to transmit ciphertexts in JSON

def url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")

def url_decode(s):
    for pad_len in range(3):
        try:
            return base64.urlsafe_b64decode(s + "=" * pad_len)
        except binascii.Error:
            pass
    return None

# length encoding prefixes the data with 2-byte length field
# RSA private key values are length-encoded in the ECB plaintext (on the inside)
# RSA ciphertext containing the session id is also length-encoded (on the outside) 

def len_encode(b, l=None):
    if l is None:
        b_bit_len = len(b) * 8
    else:
        b_bit_len = l * 8
    len_enc = int_to_bytes(b_bit_len).rjust(2, b"\x00")
    return len_enc + b

def len_decode(l):
    l_bit_len = bytes_to_int(l[:2])
    l_end = 2 + (l_bit_len // 8)
    return l[2 : l_end], l[l_end:]

# RSA private key format encoding for the ECB plaintext

def encode_privk(p, q, d, u=None):
    enc_q = len_encode(Crypto.Util.number.long_to_bytes(q, bytelen(q)))
    enc_p = len_encode(Crypto.Util.number.long_to_bytes(p, bytelen(p)))
    enc_d = len_encode(Crypto.Util.number.long_to_bytes(d, bytelen(d)))

    if u is None:
        u = Crypto.Util.number.inverse(q, p)
        assert (u * q) % p == 1
    enc_u = len_encode(Crypto.Util.number.long_to_bytes(u, bytelen(u)))

    # padding
    block_bytelen = BLOCK_BITLEN // 8
    remaining = - (len(enc_q) + len(enc_p) + len(enc_d) + len(enc_u)) % block_bytelen
    pad = b'\x00' * remaining

    enc_privk = enc_q + enc_p + enc_d + enc_u + pad
    assert len(enc_privk) % block_bytelen == 0
    return enc_privk

# RSA ciphertext encodings

def encode_int_to_bytes(c):
    return url_encode(len_encode(int_to_bytes(c)))

def decode_bytes_to_int(c_bytes):
    c_bytes, _ = len_decode(url_decode(c_bytes.decode("utf-8")))
    return bytes_to_int(c_bytes)

def encode_int_to_str(c):
    return url_encode(len_encode(int_to_bytes(c))).decode("utf-8")

def decode_str_to_int(c_str):
    c_bytes, _ = len_decode(url_decode(c_str))
    return bytes_to_int(c_bytes)

def encode_long_to_str(c, blen):
    return url_encode(len_encode(long_to_bytes(c, blen))).decode("utf-8")

# encryption

# AES

def aes_encrypt(m, km):
    """
    :param m: plaintext to encrypt
    :param km: Master key (16B for AES-ECB)
    """
    cipher = AES.new(km, AES.MODE_ECB)
    return cipher.encrypt(m)

def aes_decrypt(c, km):
    """
    :param c: ciphertext to decrypt
    :param km: Master key (16B for AES-ECB)
    """
    cipher = AES.new(km, AES.MODE_ECB)
    return cipher.decrypt(c)

# RSA

def gen_rsa_keys(modulus_size, e):
    assert modulus_size % 2 == 0
    while True:
        p = Crypto.Util.number.getPrime(modulus_size//2)
        q = Crypto.Util.number.getPrime(modulus_size//2)
        n = p * q

        if n.bit_length() != modulus_size:
          continue

        phi = (p-1) * (q-1)

        try:
            d = Crypto.Util.number.inverse(e, phi)
        except:
            continue
        break

    u = Crypto.Util.number.inverse(q, p)

    assert n == p * q
    assert (u * q) % p == 1
    assert (e * d) % phi == 1

    sk = (q, p, d, u)
    pk = (n, e)

    return sk, pk

def rsa_pad(m, modulus_byte_size):
    # XXX: This is just one possible server implementations, e.g., a zeri padding
    # would also be possible for some uses (but it is deterministic!)
    return b"\x00" * 2 + m + token_bytes(modulus_byte_size - 2 - len(m))

def rsa_encrypt(m, pk, do_pad=True, do_ct_len_encode=False):
    """
    Compute m^e mod n (RSA encryption)

    :param m: plaintext in bytes
    :param pub: RSA public key, format: (n, e)
    :param do_pad: do pad the message before encryption
    :param do_ct_len_encode: if True, length encode the ciphertext
    :returns c: ciphertext in bytes
    """
    n, e = pk
    if do_pad:
        m_padded = rsa_pad(m, ceil_int_div(n.bit_length(), 8))
    else:
        m_padded = m
    c = pow(bytes_to_int(m_padded), e, n)

    c_bytes = int_to_bytes(c)
    if do_ct_len_encode:
        return len_encode(c_bytes)
    else:
        return c_bytes

def rsa_decrypt(c, sk, do_unpad=True, do_ct_len_decode=False):
    """
    Compute c^d mod n (RSA decryption)

    :param c: ciphertext in bytes
    :param sk: RSA private key, format: (n, e, d, p, q, dp, dq, u)
    :param do_unpad: do unpad the plaintext
    :param do_ct_len_encode: if True, length decode the ciphertext
    """

    if do_ct_len_decode:
        c, _ = len_decode(c)

    c = bytes_to_int(c)
    if len(sk) > 4:
        n, e, d, p, q, dp, dq, u = sk

        # Decrypt using CRT and Garner's formula
        mp = pow(c, dp, p)
        mq = pow(c, dq, q)

        # Garner's formula for CRT
        t = (mp - mq) % p
        h = (u * t) % p
        m = (h * q + mq) % n
    elif len(sk) == 2:
        n, d = sk
        m = pow(c, d, n)
    else:
        raise ValueError(f"Decryption with {len(sk)}-component private key" \
            + "not implemented.")

    if do_unpad:
        m_pad = int_to_bytes(m).rjust(ceil_int_div(n.bit_length(), 8), b"\x00")
        if m_pad[1] != 0:
            print("rsa_decrypt: 2nd byte is not 0x00")
            m_pad = b"\x00" + m_pad
        m = m_pad[2:]

    return m

# 
# Other
#

def list_product(list):
    product = 1
    for item in list:
        product *= item
    return product

def getBlocks(ciphertext, start, count=None):
    """
    :param ciphertext: in byte form
    :param start: indexed from 0
    :param count: (optional) how many blocks, if count is not provided return 1 block

    :returns bytes: 1 or "count" number of blocks of ciphertext from start
    """
    assert len(ciphertext) % BLOCK_BYTELEN == 0

    if count is None:
        count = 1

    if start >= 0:
        result = ciphertext[start * BLOCK_BYTELEN:(start + count) * BLOCK_BYTELEN]
    elif start == -1:
        result = ciphertext[start * BLOCK_BYTELEN:]
        if count > 1:
            result = ciphertext[(start - count + 1) * BLOCK_BYTELEN:start * BLOCK_BYTELEN] + result
    else:
        result = ciphertext[(start - count + 1) * BLOCK_BYTELEN:(start + 1) * BLOCK_BYTELEN]

    assert len(result) % BLOCK_BYTELEN == 0
    assert len(result) // BLOCK_BYTELEN == count

    return result

def rand_str(blen):
    return token_bytes(blen)


# for bigint testing

def random_int_str(bitlen):
    n = Crypto.Util.number.getRandomNBitInteger(bitlen)
    return n, hex(n), base64.b64encode(int_to_bytes(n)).decode("utf-8")

def random_prime_str(bitlen):
    n = Crypto.Util.number.getPrime(bitlen)
    return n, hex(n), base64.b64encode(int_to_bytes(n)).decode("utf-8")

def random_prime_mult_str(bitlen, mult):
    n = Crypto.Util.number.getPrime(bitlen) * mult
    return n, hex(n), base64.b64encode(int_to_bytes(n)).decode("utf-8")

# utf-8 stuff

def is_uh_utf8(n, blen):
    b = long_to_bytes(int(n), blen)

    found = False
    i = 0
    while not found and i < 5:
        uh = b[17:28 + i]
        try:
            s = uh.decode("utf-8")
            found = len(s) == 11
        except UnicodeDecodeError:
            s = None
        i += 1

    return s

def get_uh_utf8(n, blen):
    b = long_to_bytes(int(n), blen)
    uh = b[17:28]

    return uh.decode("utf-8")
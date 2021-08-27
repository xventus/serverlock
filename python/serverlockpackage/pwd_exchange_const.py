# -*-  Cryptographic settings -*-
# -*-  Copyright (c) 2021 Petr Vanek fotoventus.cz -*-
# -*-  @author Petr Vanek (petr@fotoventus.cz) -*-

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import sys


# --------------------------------------------------------------------------------------------------------------------


AES_KEY_SIZE_BYTES = 32  # 256bits AES key
HKDF_HASH_SIZE = hashes.SHA256()  # Digest and HKDF(SHA256), rfc5869
HKDF_INFO = b''  # HKDF optional context and application specific information rfc5869
E_CURVE_TYPE = ec.SECP256R1()  # http://www.secg.org/sec2-v2.pdf
CODE_LENGTH = 6  # 2nd channel code


# --------------------------------------------------------------------------------------------------------------------


def hash_to_number(code_base):
    power10 = [10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 1000000000]
    hash_len = len(code_base)
    offset = code_base[hash_len - 1] & 0x0f;
    value = ((code_base[offset] & 0x7f) << 24) | ((code_base[offset + 1] & 0xff) << 16) | (
            (code_base[offset + 2] & 0xff) << 8) | (code_base[offset + 3] & 0xff)

    auth_code = value % power10[(CODE_LENGTH - 1)]
    return auth_code

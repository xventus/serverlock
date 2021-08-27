# -*-  Key derivation form ECC key pair -*-
# -*-  Copyright (c) 2021 Petr Vanek fotoventus.cz -*-
# -*-  @author Petr Vanek (petr@fotoventus.cz) -*-

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec


class KeyExchange:

    def __init__(self, key_length=32, hashes_alg=hashes.SHA256(), info=b''):
        """define key size in bytes and hash type"""
        self.info = info
        self.hashes = hashes_alg
        self.keyLen = key_length

    def get_two_party_key(self, key_material_a, key_material_b):
        """derive symmetric key from private key of A side and public key of B """
        shared_key = key_material_a.get_instnace_private().exchange(ec.ECDH(), key_material_b.get_instnace_public())
        derived_key = HKDF(algorithm=self.hashes, length=self.keyLen, salt=None, info=self.info,
                           backend=default_backend()).derive(shared_key)
        return derived_key

    def get_one_party_key(self, key_material):
        """derive symmetric key from private key and public key of ECC """
        shared_key = key_material.get_instnace_private().exchange(ec.ECDH(), key_material.get_instnace_public())
        derived_key = HKDF(algorithm=self.hashes, length=self.keyLen, salt=None, info=self.info,
                           backend=default_backend()).derive(shared_key)
        return derived_key

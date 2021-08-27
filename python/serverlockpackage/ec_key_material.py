# -*-  ECC key wrapper -*-
# -*-  Copyright (c) 2021 Petr Vanek fotoventus.cz -*-
# -*-  @author Petr Vanek (petr@fotoventus.cz) -*-

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from .pwd_exchange_const import AES_KEY_SIZE_BYTES, HKDF_HASH_SIZE, E_CURVE_TYPE, hash_to_number

class ECKeyMaterial:

    def __init__(self, curve):
        """auto generate key with predefined curve name"""
        self.curve = curve
        self.private_key = ec.generate_private_key(self.curve, default_backend())
        self.public_key = self.private_key.public_key()

    def regenerate(self):
        """regenerate key EC key pair"""
        self.private_key = ec.generate_private_key(self.curve, default_backend())
        self.public_key = self.private_key.public_key()

    def get_instnace_private(self):
        """returns private key part"""
        return self.private_key

    def get_instnace_public(self):
        """returns public key part"""
        return self.public_key

    def get_private(self):
        """returns private key encoded to PEM format"""
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        return pem

    def get_public(self):
        """returns public key encoded to PEM format"""
        pem = self.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return pem

    def set_private(self, private_key):
        """sets private key in PEM format"""
        self.private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())

    def set_public(self, public_key):
        """sets public key in PEM format"""
        self.public_key = serialization.load_pem_public_key(public_key, backend=default_backend())

    def get_public_key_hash(self):
         digest = hashes.Hash(HKDF_HASH_SIZE, backend=default_backend())
         digest.update(self.public_key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.CompressedPoint))
         return digest.finalize()


# -*-  AES encryption wrapper -*-
# -*-  Copyright (c) 2021 Petr Vanek fotoventus.cz -*-
# -*-  @author Petr Vanek (petr@fotoventus.cz) -*-

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class ContentEncryptor:

    def __init__(self, secret_key):
        """sets secret key for encryption & decryption"""
        self.secretKey = secret_key
        self.BS = 16

    def pad(self, s):
        """added PKCS7 padding"""
        return  s + (self.BS - len(s) % self.BS) * bytes([self.BS - len(s) % self.BS])

    def unpad(self,s):
        """remove PKCS7 padding"""
        return  s[0:-(s[-1])]


    def encrypt_message(self, message):
        """encrypt message"""
        backend = default_backend()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.secretKey), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        raw = message
        raw = self.pad(message)
        ct = iv + encryptor.update(raw) + encryptor.finalize()
        return ct

    def decrypt_message(self, encrypted_message):
        """decrypt  message"""
        backend = default_backend()
        iv = bytes(encrypted_message[:16])
        ct = encrypted_message[16:len(encrypted_message)]
        cipher = Cipher(algorithms.AES(self.secretKey), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        dc = decryptor.update(ct) + decryptor.finalize()
        dc = self.unpad(dc)
        return dc

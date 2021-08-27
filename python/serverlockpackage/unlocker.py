# -*-  Client's functionality  -*-
# -*-  Copyright (c) 2021 Petr Vanek fotoventus.cz -*-
# -*-  @author Petr Vanek (petr@fotoventus.cz) -*-
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .pwd_exchange_const import AES_KEY_SIZE_BYTES, HKDF_HASH_SIZE, E_CURVE_TYPE, hash_to_number
from .content_encryptor import ContentEncryptor
from .ec_key_material import ECKeyMaterial
from .key_exchange import KeyExchange

import json
import base64


class Unlocker:

    def __init__(self):
        """default server key pair"""
        self.client_key = ECKeyMaterial(E_CURVE_TYPE)
        self.server_key = None
        self.phase2 = None

    def get_client_key_pair(self):
        """gets unlocker client key pair for persistence"""
        key_data = {
            "public_key_hash": (self.client_key.get_public_key_hash()).hex(),
            "public": base64.b64encode(self.client_key.get_public()).decode('ascii'),
            "private": base64.b64encode(self.client_key.get_private()).decode('ascii'),
        }

        return json.dumps(key_data, indent=2)

    def get_key_pair(self):
        return self.client_key

    def get_public_key(self):
        return self.client_key.get_public()

    def get_private_key(self):
        return self.client_key.get_private()


    def get_registration_request(self):
        """gets registration message for server lock"""
        return json.dumps(
            {"payload": "registration", "public": base64.b64encode(self.client_key.get_public()).decode('ascii')}, indent=2)

    def get_side_channel_code(self):
        """gets numeric acknowledge code for side channel - prevent to register unauthorized client"""
        return hash_to_number(self.client_key.get_public_key_hash());

    def load_public_key_from_json(self, json_data):
        """find and load public key from json"""
        data = json.loads(json_data)
        self.client_key.set_public(base64.b64decode(data["public"]))

    def load_private_key_from_json(self, json_data):
        """find and load private key from json"""
        data = json.loads(json_data)
        self.client_key.set_private(base64.b64decode(data["private"]))

    def load_keypair(self, json_data):
        """load key pair from json"""
        self.load_public_key_from_json(json_data)
        self.load_private_key_from_json(json_data)

    def process_registration_response(self, registration_response):
        """analyze phase1 response
        """
        data = json.loads(registration_response)
        if data["payload"] != "phase1":
            raise Exception('Invalid registration response message')

        self.server_key = ECKeyMaterial(E_CURVE_TYPE)
        self.server_key.set_public(base64.b64decode(data["public"]))

        # compute common secret key and decrypt Phase1-Enc to Phase1
        keyC = KeyExchange(AES_KEY_SIZE_BYTES, HKDF_HASH_SIZE)
        phase2_enc_content_encryptor = ContentEncryptor(keyC.get_two_party_key(self.client_key, self.server_key))
        phase1 = phase2_enc_content_encryptor.decrypt_message(base64.b64decode(data["phase1_enc"]))

        # create phase2 message
        keyU = KeyExchange(AES_KEY_SIZE_BYTES, HKDF_HASH_SIZE)
        phase2_content_encryptor = ContentEncryptor(keyU.get_one_party_key(self.client_key))
        phase2 = phase2_content_encryptor.encrypt_message(phase1)

        return json.dumps(
            {"payload": "phase2",
             "phase2": base64.b64encode(phase2).decode('ascii')},
            indent=2)


    def process_invoke_message(self, invoke_unlock_message):
        data = json.loads(invoke_unlock_message)
        if data["payload"] != "invoke":
            raise Exception('Invalid invoke request message')

        self.server_key = ECKeyMaterial(E_CURVE_TYPE)
        self.server_key.set_public(base64.b64decode(data["public"]))

        keyC = KeyExchange(AES_KEY_SIZE_BYTES, HKDF_HASH_SIZE)
        phase2_enc_content_encryptor = ContentEncryptor(keyC.get_two_party_key(self.client_key, self.server_key))

        # phase2-enc to phase2
        self.phase2 = phase2_enc_content_encryptor.decrypt_message(base64.b64decode(data["phase2-enc"]))

        keyU = KeyExchange(AES_KEY_SIZE_BYTES, HKDF_HASH_SIZE)
        phase2_content_encryptor = ContentEncryptor(keyU.get_one_party_key(self.client_key))

        # phase2 to phase1
        phase1 = phase2_content_encryptor.decrypt_message(self.phase2)

        # phase1 to phase1-enc
        phase1_enc = phase2_enc_content_encryptor.encrypt_message(phase1)
        unlock_server_data = {
            "payload": "unlock",
            "phase1-enc": base64.b64encode(phase1_enc).decode('ascii'),
        }
        return json.dumps(unlock_server_data, indent=2)





# -*-  Server's functionality  -*-
# -*-  Copyright (c) 2021 Petr Vanek fotoventus.cz -*-
# -*-  @author Petr Vanek (petr@fotoventus.cz) -*-
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .content_encryptor import ContentEncryptor
from .ec_key_material import ECKeyMaterial
from .key_exchange import KeyExchange
from .unlocker import Unlocker
from .pwd_exchange_const import AES_KEY_SIZE_BYTES, HKDF_HASH_SIZE, E_CURVE_TYPE 

import json
import base64



class ServerLock:

    def __init__(self):
        """default server key pair"""
        self.server_key = ECKeyMaterial(E_CURVE_TYPE)
        self.unlocker = None
        self.passphrase = ""
        self.phase2 = None

    def persist_server_key(self):
        """creates json for key pair storage"""
        key_data = {
            "public_key_hash": (self.server_key.get_public_key_hash()).hex(),
            "public": base64.b64encode(self.server_key.get_public()).decode('ascii'),
            "private": base64.b64encode(self.server_key.get_private()).decode('ascii'),
        }

        return json.dumps(key_data, indent=2)

    def process_registration_request(self, registration_payload_payload):
        """analyze incoming data and returns registration code for comparing"""
        data = json.loads(registration_payload_payload)
        if data["payload"] != "registration":
            raise Exception('Invalid registration message')

        self.unlocker = Unlocker()
        self.unlocker.load_public_key_from_json(registration_payload_payload)

    def get_side_channel_code(self):
        """compute channel verification code from unlocker's public key"""
        if self.unlocker is None:
            raise Exception('Required to call process_registration_request')

        return self.unlocker.get_side_channel_code()

    def load_public_key_from_json(self, json_data):
        """find and load public key from json"""
        data = json.loads(json_data)
        self.server_key.set_public(base64.b64decode(data["public"]))

    def load_private_key_from_json(self, json_data):
        """find and load private key from json"""
        data = json.loads(json_data)
        self.server_key.set_private(base64.b64decode(data["private"]))

    def load_keypair(self, json_data):
        """load key pair from json"""
        self.load_public_key_from_json(json_data)
        self.load_private_key_from_json(json_data)

    def get_passphrase(self):
        """Gets passphrase"""
        return self.passphrase

    def set_passphrase(self, ps):
        """Set passphrase"""
        self.passphrase = ps

    def get_registration_response(self):
        """Create shared key - KeyC and server keyS
           Encrypt passphrase
        """

        # compute common  and server secret key
        keyS = KeyExchange(AES_KEY_SIZE_BYTES, HKDF_HASH_SIZE)
        keyC = KeyExchange(AES_KEY_SIZE_BYTES, HKDF_HASH_SIZE)
        phase1_content_encryptor = ContentEncryptor(keyS.get_one_party_key(self.server_key))
        phase1_enc_content_encryptor = ContentEncryptor(keyC.get_two_party_key(self.server_key, self.unlocker.get_key_pair()))

        # passhrase must be converted from string to bytes
        phase1 = phase1_content_encryptor.encrypt_message(bytes(self.passphrase, 'utf-8'))
        phase1_enc = phase1_enc_content_encryptor.encrypt_message(phase1)

        #returns phase1_enc and server's public key
        response_data = {
            "payload": "phase1",
            "phase1_enc": base64.b64encode(phase1_enc).decode('ascii'),
            "public": base64.b64encode(self.server_key.get_public()).decode('ascii'),
        }

        return json.dumps(response_data, indent=2)

    def process_phase2_request(self, phase2_message):
        """ Finalize unlocker registation - phase 2 """
        data = json.loads(phase2_message)
        if data["payload"] != "phase2":
            raise Exception('Invalid phase2 message')

        self.phase2 = base64.b64decode(data["phase2"])

    def get_unlocker_record(self):
        """creates json record for ulocker"""
        unlocker_data = {
            "public_key_hash": (self.unlocker.get_key_pair().get_public_key_hash()).hex(),
            "public": base64.b64encode(self.unlocker.get_key_pair().get_public()).decode('ascii'),
            "phase2": base64.b64encode(self.phase2).decode('ascii'),
        }
        return json.dumps(unlocker_data, indent=2)

    def get_unlocker_key_field(self):
        """return unique identifier for one unlocker instance, g.g. for filename of DB key"""
        return self.unlocker.get_key_pair().get_public_key_hash().hex()

    def load_unlocker(self, json_locker_record):
        """restore unlocker record - pairing function with get_unlocker_record"""
        data = json.loads(json_locker_record)
        self.unlocker = Unlocker()
        self.unlocker.load_public_key_from_json(json_locker_record)
        self.phase2 = base64.b64decode(data["phase2"])

    def get_invoke_unlock_message(self):
        """create unlock invokation request"""
        if self.phase2 is None:
            raise Exception('phase2 not loaded see at get_unlocker_record')

        keyC = KeyExchange(AES_KEY_SIZE_BYTES, HKDF_HASH_SIZE)
        phase2_enc_content_encryptor = ContentEncryptor(
            keyC.get_two_party_key(self.server_key, self.unlocker.get_key_pair()))

        phase2_enc = phase2_enc_content_encryptor.encrypt_message(self.phase2)   # each phase2 will be different

        request_data = {
            "payload": "invoke",
            "public": base64.b64encode(self.server_key.get_public()).decode('ascii'),
            "phase2-enc": base64.b64encode(phase2_enc).decode('ascii'),
        }

        return json.dumps(request_data, indent=2)


    def unlock(self, unlock_response):
        """finalize decrypt passphrase"""
        data = json.loads(unlock_response)
        if data["payload"] != "unlock":
            raise Exception('Invalid unlock message')

        phase1_enc = base64.b64decode(data["phase1-enc"])
        keyC = KeyExchange(AES_KEY_SIZE_BYTES, HKDF_HASH_SIZE)
        phase1_enc_content_encryptor = ContentEncryptor(
            keyC.get_two_party_key(self.server_key, self.unlocker.get_key_pair()))

        # phase1-enc to phase1
        phase1 = phase1_enc_content_encryptor.decrypt_message(phase1_enc)

        keyS = KeyExchange(AES_KEY_SIZE_BYTES, HKDF_HASH_SIZE)
        phase1_content_encryptor = ContentEncryptor(keyS.get_one_party_key(self.server_key))
        self.passphrase = phase1_content_encryptor.decrypt_message(phase1)



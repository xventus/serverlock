# -*-  How to use   -*-
# -*-  Copyright (c) 2021 Petr Vanek fotoventus.cz -*-
# -*-  @author Petr Vanek (petr@fotoventus.cz) -*-
from serverlockpackage import ServerLock
from serverlockpackage import Unlocker


"""
server_key_pair_json    - server lock key pair  (persistence required)
unlocker_key_json       - unlocker key pair     (persistence required)


"""




# -----------------------------------------------------------------------------------------------
# -----------------------------------------------------------------------------------------------
#   INITIALISE LOCK SERVER
# -----------------------------------------------------------------------------------------------
# -----------------------------------------------------------------------------------------------


# -----------------------------------------------------------------------------------------------
# On the server side
# This phase is called only one on server initialisation
# 1, generate server's key pair and persist it
server = ServerLock()
server_key_pair_json = server.persist_server_key()
print("SEVER LOCK will persist this key pair :", server_key_pair_json)
# start some mechanism for accepting unlocker exchange message (manually transfer, https transfer ...)
# -----------------------------------------------------------------------------------------------



# -----------------------------------------------------------------------------------------------
# -----------------------------------------------------------------------------------------------
#   UNLOCKER (CLIENT) REGISTRATION PROCESS
# -----------------------------------------------------------------------------------------------
# -----------------------------------------------------------------------------------------------


# -----------------------------------------------------------------------------------------------
# On the unlocker side
# This phase runs only once when unlocker will be registered
# 1, generate unlocker's key pair and persist it
unlocker = Unlocker()
unlocker_key_json = unlocker.get_client_key_pair()
print("UNLOCKER will persist this key pair :", unlocker_key_json)

# 2, registration process: client send registration message to server with own public key
registration_payload_payload = unlocker.get_registration_request()
print("registration payload  UNLOCKER --> SERVER LOCK:", registration_payload_payload)

registration_side_channel_code = unlocker.get_side_channel_code()
print("registration side channel code (optionally) UNLOCKER --> SERVER via SMS or manually check...:", registration_side_channel_code)

# -----------------------------------------------------------------------------------------------


# -----------------------------------------------------------------------------------------------
# On the server side
# This phase called  for each unlocker registration
# 2, result will be stored into local file
server_connection_session = ServerLock()
server_connection_session.load_keypair(server_key_pair_json)

server_connection_session.process_registration_request(registration_payload_payload)
side_channel_code = server_connection_session.get_side_channel_code()

if side_channel_code == registration_side_channel_code :
    print("Registration side channel is correct")
else:
    print("side channel code is not same, ignore this registration")
    raise Exception('side channel code is different')

server_connection_session.set_passphrase("my secret message for unlocking server application") # password
registration_response = server_connection_session.get_registration_response()
print("registration response SERVER LOCK --> UNLOCKER :", registration_response)

# -----------------------------------------------------------------------------------------------


# -----------------------------------------------------------------------------------------------
# On the unlocker side
# This phase runs only once when unlocker received registration message from ServerLock
# 2,

# can be use same instance asi in step #1 if client communicates via transaction protocol and skip this two lines
unlocker_receiver = Unlocker()
unlocker_receiver.load_keypair(unlocker_key_json)
phase2_message = unlocker_receiver.process_registration_response(registration_response)
print("finalize registration message (phase2) UNLOCKER --> LOCK SERVER:", phase2_message)


# -----------------------------------------------------------------------------------------------


# -----------------------------------------------------------------------------------------------
# On the server side
# This phase called for each unlocker registration - finalization phase2
# 3, result will be stored into local file

server_connection_session.process_phase2_request(phase2_message)
unlocker_record = server_connection_session.get_unlocker_record()
unlocker_key_field = server_connection_session.get_unlocker_key_field();
print("persist unlocker record on  LOCK SERVER:", unlocker_record)
print("persist unlocker key field on LOCK SERVER:", unlocker_key_field)



# -----------------------------------------------------------------------------------------------
# -----------------------------------------------------------------------------------------------
#   UNLOCK OPERATION
# -----------------------------------------------------------------------------------------------
# -----------------------------------------------------------------------------------------------

# -----------------------------------------------------------------------------------------------
# On the server lock side
# Create request for unlock
server_unlocking_session = ServerLock()
server_unlocking_session.load_keypair(server_key_pair_json)
server_unlocking_session.load_unlocker(unlocker_record)     # required unlocker will be invoked
invoke_unlock_message = server_unlocking_session.get_invoke_unlock_message() # get message for unlocker
print("request for invoking unlock operation via unlocker LOCK SERVER --> UNLOCKER :", invoke_unlock_message)


# -----------------------------------------------------------------------------------------------
# On the unlocker side
# Create request for unlock

unlocker_unlock = Unlocker()
unlocker_unlock.load_keypair(unlocker_key_json)
unlock_response = unlocker_unlock.process_invoke_message(invoke_unlock_message)
print("unlock response  UNLOCKER --> LOCK SERVER :", unlock_response)

# -----------------------------------------------------------------------------------------------


# On the server lock side
# Receive response for unlock
# -----------------------------------------------------------------------------------------------
server_unlocking_session.unlock(unlock_response)
passwd = server_unlocking_session.get_passphrase()
print("unlocked passphrase is: ", passwd)








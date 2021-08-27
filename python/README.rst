

Server Passphrase Lock 
======================

Server lock protocol covers phase exchange and derivation keys material. Secret keys as KeyS and Key derived from asymmetric key pairs which are generated on the server lock and unlock side during its initialisation process. There will be generate  two assymetric key pairs. One for server (PrivateKeyServerLock, PublicKeyServerLock ) and other for unlocker device  (PrivateKeyUnlocker, PublicKeyUnlocker). Unlocker is the device for ulocking the password on the server lock side. In the Server lock persist Server Lock key pair and phase2 product for eaech unlocker. Unlocker persist only unlocker key pair.  

As asymmetric algorithm is chosed ECC for it's easy secret key derivation based on ECDH algorithm.




from OpenSSL import crypto, SSL
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

import Key
from enforce import runtime_validation

def test_rsa_generateKey() -> Key:
    #Generate RSA Key
    algo = Key.RSA2048
    rsaKey = Key.Key.generateKey(algo)
    return rsaKey

def test_dsa_generateKey() -> Key:
    #Generate DSA Key
    algo = Key.DSA3072
    dsaKey = Key.Key.generateKey(algo)
    return dsaKey

def test_ec_generateKey() -> Key:
    #Generate EC Key
    algo = ec.SECP256R1
    ecKey = Key.Key.generateKey(algo)
    return ecKey

def test_rsa_getPEM() -> bytes:
    key = test_rsa_generateKey()
    rsaPEM = key.getPEM()
    print(rsaPEM.decode("utf-8") )
    return rsaPEM

def test_dsa_getPEM() -> bytes:
    key = test_dsa_generateKey()
    dsaPEM = key.getPEM()
    print(dsaPEM.decode("utf-8") )
    return dsaPEM

def test_ec_getPEM() -> bytes:
    key = test_ec_generateKey()
    ecPEM = key.getPEM(password="toto".encode('ascii'),encryption="aes-192-cbc".encode('ascii'))
    print(ecPEM.decode("utf-8"))
    return ecPEM

def test_rsa_initFromPEM() -> bytes:
    key = test_rsa_generateKey()
    rsaPEM = key.getPEM(password="toto".encode('ascii'),encryption="aes-192-cbc".encode('ascii'))
    key = Key.Key(rsaPEM, password="toto".encode('ascii'))
    rsaPEM = key.getPEM()
    print(rsaPEM.decode("utf-8") )
    return rsaPEM

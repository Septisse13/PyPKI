# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography.hazmat.backends.openssl.backend import Backend

import collections

from cryptography import utils
from cryptography.hazmat.backends.interfaces import (
    CMACBackend, CipherBackend, DERSerializationBackend, DHBackend, DSABackend,
    EllipticCurveBackend, HMACBackend, HashBackend, PBKDF2HMACBackend,
    PEMSerializationBackend, RSABackend, ScryptBackend, X509Backend
)
from cryptography.hazmat.bindings.openssl import binding
from cryptography.hazmat.primitives import serialization

@utils.register_interface(serialization.KeySerializationEncryption)
class Encryption(object):
    SUPPORTED_CIPHER =[
            b"aes-128-cbc",
            b"aes-192-cbc",
            b"aes-256-cbc",
            b"camellia-128-cbc",
            b"camellia-192-cbc",
            b"camellia-256-cbc"
    ]

    def __init__(self, password, cipher):
        if not isinstance(password, bytes) or len(password) == 0:
            raise ValueError("Password must be 1 or more bytes.")

        if not cipher:
            raise TypeError("Forgotten cipher.")
        elif not isinstance(cipher, bytes):
            raise TypeError("Cipher must be a bytes object.")

        if cipher not in Encryption.SUPPORTED_CIPHER:
            raise ValueError("Unsupported cipher.")

        self.cipher = cipher
        self.password = password

_MemoryBIO = collections.namedtuple("_MemoryBIO", ["bio", "char_ptr"])

@utils.register_interface(CipherBackend)
@utils.register_interface(CMACBackend)
@utils.register_interface(DERSerializationBackend)
@utils.register_interface(DHBackend)
@utils.register_interface(DSABackend)
@utils.register_interface(EllipticCurveBackend)
@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
@utils.register_interface(PBKDF2HMACBackend)
@utils.register_interface(RSABackend)
@utils.register_interface(PEMSerializationBackend)
@utils.register_interface(X509Backend)
@utils.register_interface_if(
    binding.Binding().lib.Cryptography_HAS_SCRYPT, ScryptBackend
)
class PyPKIBackend(Backend):
    """
    OpenSSL API binding interfaces.
    """
    name = "PyPKIBackend"

    def __init__(self):
        super().__init__()

    def _private_key_bytes(self, encoding, format, encryption_algorithm,
                           evp_pkey, cdata):
        if not isinstance(format, serialization.PrivateFormat):
            raise TypeError(
                "format must be an item from the PrivateFormat enum"
            )

        if not isinstance(encryption_algorithm,
                          serialization.KeySerializationEncryption):
            raise TypeError(
                "Encryption algorithm must be a KeySerializationEncryption "
                "instance"
            )

        if isinstance(encryption_algorithm, serialization.NoEncryption):
            password = b""
            passlen = 0
            evp_cipher = self._ffi.NULL
        elif isinstance(encryption_algorithm,
                        serialization.BestAvailableEncryption):
            # This is a curated value that we will update over time.
            evp_cipher = self._lib.EVP_get_cipherbyname(
                b"aes-256-cbc"
            )
            password = encryption_algorithm.password
            passlen = len(password)
            if passlen > 1023:
                raise ValueError(
                    "Passwords longer than 1023 bytes are not supported by "
                    "this backend"
                )
        elif isinstance(encryption_algorithm, Encryption):
            # This is a curated value that we will update over time.
            evp_cipher = self._lib.EVP_get_cipherbyname(
                encryption_algorithm.cipher
            )
            password = encryption_algorithm.password
            passlen = len(password)
            if passlen > 1023:
                raise ValueError(
                    "Passwords longer than 1023 bytes are not supported by "
                    "this backend"
                )
        else:
            raise ValueError("Unsupported encryption type")

        key_type = self._lib.EVP_PKEY_id(evp_pkey)
        if encoding is serialization.Encoding.PEM:
            if format is serialization.PrivateFormat.PKCS8:
                write_bio = self._lib.PEM_write_bio_PKCS8PrivateKey
                key = evp_pkey
            else:
                assert format is serialization.PrivateFormat.TraditionalOpenSSL
                if key_type == self._lib.EVP_PKEY_RSA:
                    write_bio = self._lib.PEM_write_bio_RSAPrivateKey
                elif key_type == self._lib.EVP_PKEY_DSA:
                    write_bio = self._lib.PEM_write_bio_DSAPrivateKey
                else:
                    assert self._lib.Cryptography_HAS_EC == 1
                    assert key_type == self._lib.EVP_PKEY_EC
                    write_bio = self._lib.PEM_write_bio_ECPrivateKey

                key = cdata
        elif encoding is serialization.Encoding.DER:
            if format is serialization.PrivateFormat.TraditionalOpenSSL:
                if not isinstance(
                    encryption_algorithm, serialization.NoEncryption
                ):
                    raise ValueError(
                        "Encryption is not supported for DER encoded "
                        "traditional OpenSSL keys"
                    )

                return self._private_key_bytes_traditional_der(key_type, cdata)
            else:
                assert format is serialization.PrivateFormat.PKCS8
                write_bio = self._lib.i2d_PKCS8PrivateKey_bio
                key = evp_pkey
        else:
            raise TypeError("encoding must be an item from the Encoding enum")

        bio = self._create_mem_bio_gc()
        res = write_bio(
            bio,
            key,
            evp_cipher,
            password,
            passlen,
            self._ffi.NULL,
            self._ffi.NULL
        )
        self.openssl_assert(res == 1)
        return self._read_mem_bio(bio)

default_PyPKIbackend = PyPKIBackend()

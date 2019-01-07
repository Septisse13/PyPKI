from cryptography.hazmat.primitives.asymmetric.ec import _CURVE_TYPES
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from PyPKIBackend import PyPKIBackend, default_PyPKIbackend, Encryption

from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption
from OpenSSL import crypto, SSL

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from enforce import runtime_validation
from overloading import overload
from typing import Any


class RSA1024(object):
    name = "rsa1024"
    key_size = 1024

class RSA2048(object):
    name = "rsa2048"
    key_size = 2048

class RSA4096(object):
    name = "rsa4096"
    key_size = 4096

class DSA1024(object):
    name = "dsa1024"
    key_size = 1024

class DSA2048(object):
    name = "dsa2048"
    key_size = 2048

class DSA3072(object):
    name = "dsa3072"
    key_size = 3072

#@runtime_validation
class Key:

    _RSA_TYPES = {
                "rsa1024": RSA1024,
                "rsa2048": RSA2048,
                "rsa4096": RSA4096
            }

    _DSA_TYPES = {
                "dsa1024": DSA1024,
                "dsa2048": DSA2048,
                "dsa3072": DSA3072
            }

    SUPPORTED_KEY_TYPE = { **_CURVE_TYPES, **_RSA_TYPES, **_DSA_TYPES }

    @staticmethod
    def isSupportedType(type) -> bool:
        """ Teste si le type de clé type est supporté.

        Args:
            type : Le type à tester.

        Returns:
            bool: Vrai si le type est supporté.
        """
        if isinstance(type, str):
            return type in Key.SUPPORTED_KEY_TYPE.keys()
        else:
            return type in Key.SUPPORTED_KEY_TYPE.values()

    @staticmethod
    def backend():
        return default_PyPKIbackend

    def __init__(self, key, password: bytes=None):
        """
        Args:
            key: La clé au format PEM ou OpenSSL
            password (bytes): Le mot de passe de déchiffrement de la clé.
        """
        if     isinstance(key, rsa.RSAPublicKey) \
            or isinstance(key, rsa.RSAPrivateKey) \
            or isinstance(key, dsa.DSAPublicKey) \
            or isinstance(key, dsa.DSAPrivateKey) \
            or isinstance(key, ec.EllipticCurvePrivateKey) \
            or isinstance(key, ec.EllipticCurvePublicKey):
            self._initFromCryptoKey(key)
        else:
            self._initFromPEM(key, password)

    @runtime_validation
    def _initFromPEM(self, pem_data: bytes, password: bytes =None):
        """ Initialise la clé à partir d'un bytes au format PEM.

        Args:
            pem_data (bytes): Un bytes représentant la clé au format PEM.
            password (bytes): Le secret de déchffrement de la clé.

        Raises:
            ValueError : If the PEM data could not be decrypted or if its
                structure could not be decoded successfully.
            TypeError : If a password was given and the private key was not
                encrypted. Or if the key was encrypted but no password was
                supplied.
            cryptography.exceptions.UnsupportedAlgorithm : If the serialized
                key is of a type that is not supported by the backend or if the
                key is encrypted with a symmetric cipher that is not supported
                by the backend.
        """
        key = load_pem_private_key(pem_data,
                                    password=password,
                                    backend=Key.backend())
        self._initFromCryptoKey(key)

    def _initFromCryptoKey(self, key):
        """ Initialise la clé à partir d'un object clé de la librairie OpenSSL.

        Args:
            key (rsa.RSAPrivateKey, rsa.RSAPublicKey, dsa.DSAPrivateKey,
                dsa.DSAPublicKey, ec.EllipticCurvePrivateKey,
                ec.EllipticCurvePublicKey): L'object clé de la librairie OpenSSL.

        """
        self._key = key

        # Initialisation de l'algorithme
        if isinstance(key, rsa.RSAPublicKey) \
                or isinstance(key, rsa.RSAPrivateKey):
            size = key.key_size
            algo = "rsa" + str(size)
        elif isinstance(key, dsa.DSAPublicKey) \
                or isinstance(key, dsa.DSAPrivateKey):
            size = key.key_size
            algo = "dsa" + str(size)
        elif isinstance(key, ec.EllipticCurvePrivateKey) \
                or isinstance(key, ec.EllipticCurvePublicKey):
            size = key.curve.key_size
            algo = key.curve.name
        else:
            raise TypeError("{type} key is not supported".format(type=type(size)))
        self._algorithm = Key.SUPPORTED_KEY_TYPE[algo]

        # Définition du type de clé
        self._public = isinstance(self.cryptoKey, rsa.RSAPublicKey) \
                   or isinstance(self.cryptoKey, dsa.DSAPublicKey) \
                   or isinstance(self.cryptoKey, ec.EllipticCurvePublicKey)

    @property
    def algorithm(self):
        """ L'algorithme cryptographique associé à la clé.

        Retourne une valeur de Key.SUPPORTED_KEY_TYPE
        """
        return self._algorithm

    @property
    def cryptoKey(self):
        """ La clé au format rsa.RSAPublicKey, dsa.DSAPublicKey,
        ec.EllipticCurvePublicKey, rsa.RSAPrivateKey, dsa.DSAPrivateKey,
        ec.EllipticCurvePrivateKey.
        """
        return self._key

    @property
    def size(self) -> int:
        """ (int): La taille de la clé. """
        return self.algorithm.key_size

    @property
    def type(self) -> str:
        """ (str): L'algorithme associé à la clé """
        return self.algorithm.name

    def isPublic(self):
        """ Test si la clé contient uniquement une partie publique.

        Returns:
            bool: Vrai si la clé contient uniquement une partie publique.
        """
        return self._public

    @runtime_validation
    def getPEM(self, encryption: bytes =None, password: bytes =None) -> bytes:
        """ Retourne la clé au format PEM.

        Args:
            encryption (str): L'algorithme de chiffrement de la clé.
            passpharse (str): La password de déchiffrement de la clé.

        Returns:
            bytes: La clé au format PEM.
        """
        if encryption:
            return self.cryptoKey.private_bytes(
                            encoding=Encoding.PEM,
                            format=PrivateFormat.PKCS8,
                            encryption_algorithm=Encryption(password, encryption))
        else:
            return self.cryptoKey.private_bytes(
                            encoding=Encoding.PEM,
                            format=PrivateFormat.PKCS8,
                            encryption_algorithm=NoEncryption())

    def __str__(self) -> str:
        return "key : {algo}:{size}".format(algo=self.type, size=self.size)


    @staticmethod
    @runtime_validation
    def generateKey(algorithm: Any):
        """ Génère une clé pour l'algorithm.

        Args:
            algorithm (Any): L'algorithme associé à la clé.

        Returns:
            Key : la nouvelle clé
        """
        if algorithm in Key._RSA_TYPES.values():
            key = rsa.generate_private_key(
                        public_exponent = 65537,
                        key_size = algorithm.key_size,
                        backend = Key.backend()
                        )
        elif algorithm in Key._DSA_TYPES.values():
            key = dsa.generate_private_key(
                        key_size = algorithm.key_size,
                        backend = Key.backend()
                        )
        elif algorithm in _CURVE_TYPES.values():
            key = ec.generate_private_key(
                        algorithm,
                        Key.backend()
                        )
        else:
            raise TypeError("{algo} is not supported".format(algo=algorithm))

        return Key(key)

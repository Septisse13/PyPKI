from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import _CURVE_TYPES
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.backends import default_backend

import jsonUtils
import json

from Key import Key
import datetime

from PyPKIBackend import Encryption

class KeyPolicy:

    def __init__(self, duration, algorithm, encryption):
        self.duration = duration
        self.algorithm = algorithm
        self.encryption = encryption
        pass

    @property
    def duration(self):
        """ (datetime.timedelta): La durée de vie des clé """
        return self._duration

    @duration.setter
    def duration(self, duration):
        if isinstance(duration, int):
            if duration <= 0:
                raise ValueError("Duration must be positive.")
            else:
                self.duration = datetime.timedelta(seconds=duration)
        elif isinstance(duration, datetime.timedelta):
            self._duration = duration
        else:
            raise TypeValue("Duration must be a datetime.timedelta.")

    @property
    def algorithm(self):
        """ L'algorithme associé à la clé """
        return self._algorithm

    @algorithm.setter
    def algorithm(self, algorithm):
        if algorithm in Key.SUPPORTED_KEY_TYPE.values():
            self._algorithm = algorithm
        elif isinstance(algorithm, str):
            if algorithm in Key.SUPPORTED_KEY_TYPE.keys():
                self.algorithm = Key.SUPPORTED_KEY_TYPE[algorithm]
            else:
                raise ValueError("{algo} n'est pas supporté.".format(algo=algorithm))
        else:
            raise ValueError("{algo} n'est pas supporté.".format(algo=algorithm))

    @property
    def encryption(self):
        """ L'algorithme de chiffrement de la clé."""
        return self._encryption

    @encryption.setter
    def encryption(self, encryption):
        if isinstance(encryption, str):
            encryption = encryption.encode("ascii")

        if encryption not in Encryption.SUPPORTED_CIPHER:
            raise ValueError("{enc} is not supported.".format(enc=encryption))
        self._encryption = encryption

    def generateKey(self) -> Key:
        """ Génère une clé conforme à la politique.

        Returns:
            Key: La nouvelle clé.
        """
        return Key.generateKey(self.algorithm)

    def generateCipheredKey(self, passphrase) -> bytes:
        """ Génère une clé chiffrée au format PEM conforme à la politique.

        Args:
            passphrase (bytes): La phassphrase de chiffrement.

        Returns:
            Key: La nouvelle clé.
        """
        key = Key.generateKey(self.algorithm)
        return key.getPEM(self.encryption, passphrase)

    def __str__(self):
        return json.dumps(self.toJSon(self), indent=4)

    @staticmethod
    def fromJSon(keyPolicyJSon):
        """ Initialise un KeyPolicy à partir d'un JSon

        Args:
            keyPolicyJSon (str): Le KeyPolicy au format JSon.

        Returns:
            KeyPolicy: Le KeyPolicy
        """
        duration = int(keyPolicyJSon["duration"])
        algorithm = keyPolicyJSon["algorithm"]
        encryption = keyPolicyJSon["encryption"]

        keyPolicy = KeyPolicy(duration, algorithm, encryption)

        return keyPolicy

    @staticmethod
    def toJSon(keyPolicy):
        """ Retourne un KeyPolicy au format JSon.

        Args:
            keyPolicy (KeyPolicy): Le KeyPolicy.

        Returns:
            dict : Le KeyPolicy au format JSon.
        """
        keyPolicy_dict = {}
        keyPolicy_dict["duration"] = int(keyPolicy.duration.total_seconds())
        keyPolicy_dict["algorithm"] = keyPolicy.algorithm.name
        keyPolicy_dict["encryption"] = keyPolicy.encryption.decode("ascii")

        return keyPolicy_dict

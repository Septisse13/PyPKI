from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import extensions

from pathlib import Path
import jsonUtils
import datetime
import getpass
import binascii
import re
import json
from collections import OrderedDict

from FileStorage import FileStorage
from FileAccess import FileAccess
from Key import Key
from Subject import Subject

from CertificateTemplate import CertificateTemplate
from KeyPolicy import KeyPolicy

CERT_DIR = Path("../test/cert/")
SIGNKEY_DIR = Path("../test/private/")
CACERT_DIR = Path("../test/cacert/")
CERTTEMPLATE_DIR = Path("../test/template/")
CACSR_DIR = Path("../test/cacsr/")
CSR_DIR = Path("../test/csr/")

CERT_NAMETEMPLATE = "${id}.crt"
SIGNKEY_NAMETEMPLATE = "${id}.key"
CACERT_NAMETEMPLATE = "${id}.cacert"
CERTTEMPLATE_NAMETEMPLATE = "${id}.tmp.crt"
CACSR_NAMETEMPLATE = "${id}.cacsr"
CSR_NAMETEMPLATE = "${id}.csr"

CERT_ACCESS = FileAccess("septisse", "septisse", 0o640)
SIGNKEY_ACCESS = FileAccess("septisse", "septisse", 0o640)
CACERT_ACCESS = FileAccess("septisse", "septisse", 0o640)
CERTTEMPLATE_ACCESS = FileAccess("septisse", "septisse", 0o640)
CACSR_ACCESS = FileAccess("septisse", "septisse", 0o640)
CSR_ACCESS = FileAccess("septisse", "septisse", 0o640)

class Authority:

    def __init__(self, name):
        self.name = name
        self._currentSignKeyId = ""
        self.initFileStorage()

    def initFileStorage(self,
                    signKeyDir      = SIGNKEY_DIR,
                    certDir         = CERT_DIR,
                    cacertDir       = CACERT_DIR,
                    certTemplateDir = CERTTEMPLATE_DIR,
                    caCSRDir        = CACSR_DIR,
                    csrDir          = CSR_DIR):

        self.signKeyStorage = FileStorage(signKeyDir)
        signkey_nametemplate = SIGNKEY_NAMETEMPLATE
        self.signKeyStorage.nameTemplate = signkey_nametemplate
        self.signKeyStorage.access = SIGNKEY_ACCESS

        self.certStorage = FileStorage(certDir)
        cert_nametemplate = CERT_NAMETEMPLATE
        self.certStorage.nameTemplate = cert_nametemplate
        self.certStorage.access = CERT_ACCESS

        self.caCertStorage = FileStorage(cacertDir)
        cacert_nametemplate = CACERT_NAMETEMPLATE
        self.caCertStorage.nameTemplate = cacert_nametemplate
        self.caCertStorage.access = CACERT_ACCESS

        self.childTemplateStorage = FileStorage(certTemplateDir)
        certtemplate_nametemplate = CERTTEMPLATE_NAMETEMPLATE
        self.childTemplateStorage.nameTemplate = certtemplate_nametemplate
        self.childTemplateStorage.access = CERTTEMPLATE_ACCESS

        self.caCSRStorage = FileStorage(caCSRDir)
        caCSR_nametemplate = CACSR_NAMETEMPLATE
        self.caCSRStorage.nameTemplate = caCSR_nametemplate
        self.caCSRStorage.access = CACSR_ACCESS

        self.csrStorage = FileStorage(csrDir)
        csr_nametemplate = CSR_NAMETEMPLATE
        self.csrStorage.nameTemplate = csr_nametemplate
        self.csrStorage.access = CSR_ACCESS

#--------------------- Name --------------------------#

    @property
    def name(self):
        """ Le nom de l'authorité

        Ce nom doit être composé uniquement de caractères alpha-numériques
        """
        return self._name

    @name.setter
    def name(self, name):
        if not re.match('^[a-zA-Z0-9_]+$',name):
            raise ValueError("name {name} invalide.".format(name=name))
        self._name = name

#--------------------- Storage ------------------------#

    @property
    def caCertStorage(self) -> FileStorage:
        """ L'espace de stockage des certificats assurant l'authenticité de
        l'autorité de certification

        Cet object est de type FileStorage

        Raises:
            TypeError: Si caCertStorage n'est pas du type FileStorage
        """
        return self._cacertStorage

    @caCertStorage.setter
    def caCertStorage(self, cacertStorage):
        self._cacertStorage = cacertStorage

#--------------------- Sign Key -----------------------#

    @property
    def signKeyStorage(self) -> FileStorage:
        """ L'espace de stockage des clés de signature de l'autorité.

        Cet object est de type FileStorage.

        Raises:
            TypeError: Si signKeyStorage n'est pas du type FileStorage.
        """
        return self._signKeyStorage

    @signKeyStorage.setter
    def signKeyStorage(self, signKeyStorage):
        self._signKeyStorage = signKeyStorage

    def getSignKeyId(self, key):
        """ Retourne l'identifiant de stockage d'une clé de signature de
        l'autorité.

        Args:
            key (Key): La clé.

        Returns:
            str: L'identifiant de la clé key.
        """
        public_key = key.cryptoKey.public_key()
        digest = extensions.SubjectKeyIdentifier.from_public_key(public_key).digest.hex().upper()[:8]
        return digest + "-" + self.name

    @property
    def signKeyPolicy(self) -> KeyPolicy:
        """ La politique de gestion des clés de signature associée à l'autorité

        Cet object est de type KeyPolicy.

        Raises:
            TypeError: Si signKeyPolicy n'est pas du type KeyPolicy.
        """
        return self._signKeyPolicy

    @signKeyPolicy.setter
    def signKeyPolicy(self, signKeyPolicy):
        self._signKeyPolicy = signKeyPolicy

    @property
    def currentSignKey(self) -> Key:
        """ (Key): La clé de signature par défaut.
        """
        return self._currentSignKey

    @property
    def currentSignKeyId(self) -> str:
        """ (str): L'identifiant de la clé de signature par défaut.
        """
        return self._currentSignKeyId

    @currentSignKeyId.setter
    def currentSignKeyId(self, currentSignKeyId: str):
        self._currentSignKeyId = currentSignKeyId

    def readSignKey(self, passphrase=None, signKeyId=None):
        """ Initialise la clé de signature.

        Recherche dans signKeyStorage la clé associée à l'identifiant
        signKeyId. Si celui-ci n'est pas fourni, le currentSignKeyId
        est utilisé. Cette clé devient la clé de signature par défaut.

        Args:
            passphrase (str): Si la clé est chiffrée, la passphrase de
                déchiffrement de la clé.
            signKeyId (str): L'identifiant de stockage de la clé. Si ce paramètre
                est fourni, il remplace currentSignKeyId.

        Returns:
            str: L'identifiant de la clé key.

        Raises:
            ValueError: If the PEM data could not be decrypted or if its
                structure could not be decoded successfully.
            TypeError: Si signKeyId n'est pas du type str. Or if a password was
                given and the private key was not encrypted. Or if the key was
                encrypted but no password was supplied. Or if Si currentSignKeyId
                n'est pas initialisé et que signKeyId n'est pas fourni.
            UnsupportedAlgorithm: If the serialized key is of a type that is not
                supported by the backend or if the key is encrypted with a
                symmetric cipher that is not supported by the backend.

        """
        if not signKeyId and not self.currentSignKeyId:
            raise TypeError("currentSignKey doit être initialisée ou signKeyId doit être fournie")

        if signKeyId:
            self.currentSignKeyId = signKeyId

        signKey_file = self.signKeyStorage.files[self.currentSignKeyId]
        signKey_file = Key(signKey_file, passphrase)
        self._currentSignKey = signKey_file

    def renewSignKey(self, password) -> str:
        """ Génère une nouvelle clé de signature conforme à la politique de
        gestion des clé signKeyPolicy et la stocke dans signKeyStorage.

        Returns:
            str: L'identifiant de la clé générée.

        Raises:
            ValueError: If the PEM data could not be decrypted or if its
                structure could not be decoded successfully.
            TypeError: Si signKeyId n'est pas du type str. Or if a password was
                given and the private key was not encrypted. Or if the key was
                encrypted but no password was supplied. Or if Si currentSignKeyId
                n'est pas initialisé et que signKeyId n'est pas fourni.
            UnsupportedAlgorithm: If the serialized key is of a type that is not
                supported by the backend or if the key is encrypted with a
                symmetric cipher that is not supported by the backend.
        """
        newkey = self.signKeyPolicy.generateKey()
        newid = self.getSignKeyId(newkey)
        self.signKeyStorage.files[newid] = newkey.getPEM(self.signKeyPolicy.encryption, password)
        return newid

#--------------------- Suject ---------------------#

    @property
    def subject(self) -> Subject:
        """ Le sujet de l'autorité.

        Cette propriété est un synonyme de authorityTemplate.subject.

        Returns:
            str: Le sujet de l'autorité.

        Raises:
            TypeError: Si authorityTemplate n'est pas initialisé.
        """
        return self.authorityTemplate.subject

    @subject.setter
    def subject(self, subject: Subject):
        self.authorityTemplate.subject = subject

#------------------ Authority Template --------------------#

    @property
    def authorityTemplate(self) -> CertificateTemplate:
        """ (CertificateTemplate):Le patron du certificat de l'autorité.

        Ce patron est utilisé pour générer les requêtes de certification de
        la clé de signature de l'autorité.

        Returns:
            CertificateTemplate: Le patron de l'autorité.

        Raises:
            TypeError: Si authorityTemplate n'est pas initialisé.
        """
        if not self._authorityTemplate:
            raise TypeError("authorityTemplate is not initialized")
        return self._authorityTemplate

    @authorityTemplate.setter
    def authorityTemplate(self, authorityTemplate: CertificateTemplate):
        self._authorityTemplate = authorityTemplate

#--------------------- Child Template ----------------#

    @property
    def childTemplateStorage(self) -> FileStorage:
        """ (FileStorage): L'espace de stockage des patrons de certificats
            utilisés par l'autorité.

        Returns:
            FileStorage: L'espace de stockage des patrons de certificats
                utilisés par l'autorité.

        Raises:
            TypeError: Si childTemplateStorage n'est pas initialisé.
        """
        if not self._childTemplateStorage:
            raise TypeError("childTemplateStorage is not initialized")
        return self._childTemplateStorage

    @childTemplateStorage.setter
    def childTemplateStorage(self, certTemplateStorage: FileStorage):
        self._childTemplateStorage = certTemplateStorage

    def getChildTemplate(self, id: str):
        return self._childTemplates[id]

    def setChildTemplate(self, name: str, template: CertificateTemplate):
        self._childTemplates[name] = template

    def delChildTemplate(self, name: str):
        del self._childTemplates[name]

    def commitChildTemplate(self, name: str):
        """ Enregistre le patron childTemplates[name] dans childTemplateStorage.
        Si childTemplates[name] n'existe pas, le fichier associé à name dans
        childTemplateStorage est supprimé.

        Args:
            name (str): Le nom du patron à enregister.
        """
        if self.childTemplates[name]:
            self.childTemplateStorage.addFile(
                jsonUtils.certificateTemplateToJSon(
                    self.childTemplates[name]), name)
        else:
            self.childTemplateStorage.delFile(name)

#--------------------- Cert -----------------------#

    @property
    def certStorage(self) -> FileStorage:
        """ (FileStorage): L'espace de stockage des certificats signés par
            sl'autorité.

        Returns:
            FileStorage: L'espace de stockage des certificats signés par
                sl'autorité.

        Raises:
            TypeError: Si certStorage n'est pas initialisé.
        """
        if not self._certStorage:
            raise TypeError("certStorage is not initialized")
        return self._certStorage

    @certStorage.setter
    def certStorage(self, certStorage: FileStorage):
        self._certStorage = certStorage

    def getCertId(self, cert):
        """ (str): Retourne l'identifiant associé à cert.
        Args:
            cert (x509.Certificate/bytes): Le certificat au format PEM.
        """
        if isinstance(cert, bytes):
            cert = x509.load_pem_x509_certificate(cert, default_backend())
        elif not isinstance(cert, x509.Certificate):
            raise TypeError("Cert must be a x509.Certificate.")
        serial_number = hex(cert.serial_number)[2:].upper()[:8]
        return serial_number + "-" + self.name

    @staticmethod
    def generateSerialNumber():
        """ Génère un numéro de série.
        """
        return x509.random_serial_number()

    def generateCert(self,
                     public_key,
                     beginDate: datetime.datetime,
                     template: CertificateTemplate) -> str:
        """ Signe un certificat.

        Args:
            public_key: One of RSAPublicKey , DSAPublicKey , or EllipticCurvePublicKey.
            beginDate (datetime.datetime): La date de début de validité.
            template (CertificateTemplate): Le patron du certificat.
        """

        if isinstance(public_key, Key):
            public_key = public_key.cryptoKey
        elif not (isinstance(public_key, rsa.RSAPublicKey) or \
                  isinstance(public_key, rsa.RSAPrivateKey) or \
                  isinstance(public_key, rsa.DSAPublicKey) or \
                  isinstance(public_key, rsa.DSAPrivateKey) or \
                  isinstance(public_key, rsa.EllipticCurvePublicKey) or \
                  isinstance(public_key, rsa.EllipticCurvePrivateKey)):
            raise TypeError("public_key must be a Key")

        builder = template.getCertBuilder()

        builder = builder.serial_number(self.generateSerialNumber())

        # Période de validitée
        endDate = template.getEndDate(beginDate)
        builder = builder.not_valid_before(beginDate)
        builder = builder.not_valid_after(endDate)

        # Clé publique
        SKI = extensions.SubjectKeyIdentifier.from_public_key(public_key)
        builder = builder.add_extension(SKI, False)
        builder = builder.public_key(public_key)

        # Signature
        sign_key = self.currentSignKey.cryptoKey
        sign_pubkey = sign_key.public_key()
        AKI = extensions.AuthorityKeyIdentifier.from_issuer_public_key(sign_pubkey)
        builder = builder.add_extension(AKI, False)
        builder = builder.issuer_name(self.authorityTemplate.subject)
        certificate = builder.sign(
            private_key=sign_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        # Stockage
        cert = certificate.public_bytes(
            encoding=serialization.Encoding.PEM)
        id = self.getCertId(cert)
        self.certStorage.addFile(cert, id)
        return id

    def generateSelfSignedCert(self, beginDate: datetime.datetime) -> str:
        """ Génère un certificat auto-signé avec currentSignKey

        Args:
            beginDate (datetime.datetime): La date de début de validité.
        """

        public_key = self._currentSignKey.cryptoKey.public_key()

        builder = self.authorityTemplate.getCertBuilder()

        builder = builder.serial_number(self.generateSerialNumber())

        # Période de validitée
        endDate = self.authorityTemplate.getEndDate(beginDate)
        builder = builder.not_valid_before(beginDate)
        builder = builder.not_valid_after(endDate)

        # Clé publique
        SKI = extensions.SubjectKeyIdentifier.from_public_key(public_key)
        builder = builder.add_extension(SKI, False)
        builder = builder.public_key(public_key)

        # Signature
        sign_key = self._currentSignKey.cryptoKey
        sign_pubkey = sign_key.public_key()
        AKI = extensions.AuthorityKeyIdentifier.from_issuer_public_key(sign_pubkey)
        builder = builder.add_extension(AKI, False)
        builder = builder.issuer_name(self.authorityTemplate.subject)
        certificate = builder.sign(
            private_key=sign_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        # Stockage
        cert = certificate.public_bytes(
            encoding=serialization.Encoding.PEM)
        id = self.getCertId(cert)
        self.caCertStorage.files[id] = cert
        return id

#------------------- Ca CSR -------------------------#
    @property
    def caCSRStorage(self) -> FileStorage:
        """ (FileStorage): l'espace de stockage des demandes de signature
        émises par l'autorité.
        Raises:
            TypeError: Si caCSRStorage n'est pas initialisé.
        """
        if not self._caCSRStorage:
            raise TypeError("caCSRStorage is not initialized")
        return self._caCSRStorage

    @caCSRStorage.setter
    def caCSRStorage(self, caCSRStorage: FileStorage):
        self._caCSRStorage = caCSRStorage

    def getCaCSRId(self, csr: x509.CertificateSigningRequest) -> str:
        """ (str): Retourne l'identifiant associé à la demande de signature csr
        de l'autorité.

        Args:
            csr (bytes/x509.CertificateSigningRequest): La demande de signature de l'autorité.
        """
        if isinstance(csr, bytes):
            csr = x509.load_pem_x509_csr(csr, default_backend())
        public_key = csr.public_key()
        digest = extensions.SubjectKeyIdentifier.from_public_key(public_key).digest.hex().upper()[:8]
        return digest + "-" + self.name

    def generateCaCSR(self, id=None, password=None) -> str:
        """ Génère une demande signature pour currentSignKey.

        """
        template = self.authorityTemplate

        builder = template.getCSRBuilder()

        if id:
            sign_key = Key(self.signKeyStorage.files[id], password).cryptoKey
        else:
            sign_key = self.currentSignKey.cryptoKey

        # Signature
        csr = builder.sign(
            private_key=sign_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        # Stockage
        csr_file = csr.public_bytes(
            encoding=serialization.Encoding.PEM)
        id = self.getCaCSRId(csr_file)
        self.caCSRStorage.files[id] = csr_file

        return id

#------------------- CSR -------------------------#

    @property
    def csrStorage(self) -> FileStorage:
        """ (FileStorage): l'espace de stockage des demandes de signature
        soumises à l'autorité.

        Raises:
            TypeError: Si csrStorage n'est pas initialisé.
        """
        if not self._csrStorage:
            raise TypeError("csrStorage is not initialized")
        return self._csrStorage

    @csrStorage.setter
    def csrStorage(self, csrStorage: FileStorage):
        self._csrStorage = csrStorage

    def signCSR(self, csr, template):

        error = []
        if isinstance(template, str):
            template = self.childTemplates[template]

        # Verify signature
        if not csr.is_signature_valid():
            error += ["Signature invalide"]

        # Verify key



        #size
        #algo
        #jamais signée

        # Verify Subject

        # Verify extensions
        exts_csr = {}
        exts_tmpl = {}

        for ext_csr in csr.extensions():
            if exts_csr[ext_csr.oid]:
                #TODO ERROR  : duplicate ext
                return
            else:
                exts_csr[ext.oid] = ext_csr

        for ext_tmpl in template.getExtensions():
            exts_tmpl[ext.oid] = ext_tmpl

        # {CRS Ext} n {Template Ext}
        exts_intersection = list(set(exts_csr.keys()) & set(exts_tmpl.keys()))
        for ext_oid in exts_intersection:
            if exts_csr[ext_oid] != exts_tmpl[ext_oid]:
                error += [str(ext_oid.dotted_string) + " is different"]

        # {CRS Ext} - {Template Ext}
        exts_csr_sub_tmpl = exts_csr.keys() - exts_tmpl.keys()
        for ext_oid in exts_csr_sub_tmpl:
            error += [str(ext_oid.dotted_string) + " is not requested"]

        # {Template Ext} - {CRS Ext}
        exts_tmpl_sub_csr = exts_tmpl.keys() - exts_csr.keys()
        for ext_oid in exts_tmpl_sub_csr:
            error += [str(ext_oid.dotted_string) + " is forgotten"]


    def __str__(self):
        return json.dumps(self.toJSon(), indent=4)

    @staticmethod
    def fromJSon(authorityJSon):
        """ Initialise une Authority à partir d'un JSon

        Args:
            authorityJSon (str): L'Authority au format JSon.

        Returns:
            Authority: L'Authority.
        """
        authority_dict = json.loads(authorityJSon)
        result = Authority(authority_dict["name"])
        result.signKeyPolicy = KeyPolicy.fromJSon(authority_dict["signKeyPolicy"])
        result.authorityTemplate = CertificateTemplate.fromJSon(authority_dict["authorityTemplate"])

        if "currentSignKeyId" in authority_dict:
            result.currentSignKeyId = authority_dict["currentSignKeyId"]

        result.signKeyStorage = FileStorage.fromJSon(authority_dict["signKeyStorage"])
        result.caCertStorage = FileStorage.fromJSon(authority_dict["cacertStorage"])
        result.certStorage = FileStorage.fromJSon(authority_dict["certStorage"])
        result.childTemplateStorage = FileStorage.fromJSon(authority_dict["childTemplateStorage"])

        return result

    def toJSon(self):
        authority_dict = OrderedDict()

        authority_dict["name"] = self.name
        authority_dict["signKeyPolicy"] = KeyPolicy.toJSon(self.signKeyPolicy)
        authority_dict["authorityTemplate"]   = CertificateTemplate.toJSon(self.authorityTemplate)

        if self.currentSignKeyId:
            authority_dict["currentSignKeyId"]    = self.currentSignKeyId

        authority_dict["signKeyStorage"]      = FileStorage.toJSon(self.signKeyStorage)
        authority_dict["cacertStorage"]       = FileStorage.toJSon(self.caCertStorage)
        authority_dict["certStorage"]         = FileStorage.toJSon(self.certStorage)
        authority_dict["childTemplateStorage"] = FileStorage.toJSon(self.childTemplateStorage)

        return authority_dict

#!/usr/bin/python3

from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join
import json
import datetime
from pathlib import Path
import pwd
import grp
import os
import binascii

CERT_FILE = "myapp.crt"
KEY_FILE = "myapp.key"
CAJSON_FILE = "myapp.json"

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

import OpenSSL

from OpenSSL._util import lib as _lib
                                      
KeyAlgorithms = [
        "rsa1024",
        "rsa2048",
        "rsa4096",
        "secp256r1",
        "secp384r1",
        "secp521r1"
        ]

SignAlgorithms = [
        "sha1",
        "sha256"
        ]

EncAlgorithms = [
        "none",
        "aes128",
        "aes192",
        "aes256",
        "camellia128",
        "camellia192"
        ]

def generate_key(keyAlgorithm):
    keyAlgorithm = keyAlgorithm.lower()
    if ('secp256r1' == keyAlgorithm):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    elif ('secp384r1' == keyAlgorithm):
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    elif ('secp521r1' == keyAlgorithm):
        key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    elif ('rsa' in keyAlgorithm and keyAlgorithm in KeyAlgorithms):
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, int(keyAlgorithm[3:]))
        return k
    key_pem = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption())
    return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_pem)

def write_key(path, key, cipher=None, passphrase=None):
    with open(path, "w") as key_file:
        key_file.write(crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key, cipher, passpharse))

def jsonToSubject(subject_json):
    subject = crypto.X509Name(crypto.X509().get_subject()) 
    subject.C  = subject_json['C']
    subject.ST = subject_json['ST']
    subject.L  = subject_json['L']
    subject.O  = subject_json['O']
    subject.OU = subject_json['OU']
    subject.CN = subject_json['CN']
    return subject 

def checkDir(path, mode, user, group):
    if path.exists():
        path.chmod(mode)            
    else:
        privateDir_path.mkdir(mode=mode, parents=False, exist_ok=True)
    os.chown(str(path), user.pw_uid, group.gr_gid)


def generate_basicConstraints(critical, isCA, pathlen=None):
    if not isCA and pathlen is None:
        return crypto.X509Extension(b"basicConstraints", critical, str("CA:FALSE").encode())
    elif not isCA and pathlen is not None:
        print("ERROR : Bad basicConstraints")
        return None
    elif isCA and pathlen is None:
        return crypto.X509Extension(b"basicConstraints", critical, str("CA:TRUE").encode())
    elif isCA and isinstance(pathlen, int) and pathlen in range(0,256):
        return crypto.X509Extension(b"basicConstraints", critical, 
                                            str("CA:TRUE, pathlen:"+str(pathlen)).encode())
    else:
        print("ERROR : Bad basicConstraints")
        return None


PRIVATE_DIR = Path("private/")
PUBLIC_DIR = Path("public/")
CACERTS_DIR = Path("cacerts/")
CERTS_DIR = Path("certs/")
NEWCERTS_DIR = Path("newcerts/")
CSR_DIR = Path("csr/")
NEWCSR_DIR = Path("newcsr/")
CRL_DIR = Path("crl/")
TEMPLATES_DIR = Path("templates/")

SERIAL_SIZE = 20

KEY_EXT = ".key"
PUB_EXT = ".pub"
CERT_EXT = ".crt"
TEMPLATE_EXT = ".json"

CURRENTKEY_SL = "current.key"
CURRENTPUB_SL = "current.pub"

def generate_serial():
    return binascii.hexlify(os.urandom(SERIAL_SIZE)).upper();

password = str("ijhqsrbgfiuhqzbgiuq")
calledWith = []
def passphraseCallback(maxlen, verify=None, extra=None):
    calledWith.append((maxlen, verify, extra))
    return password.encode('utf-8')

class CA:
    subject = None
    pkey = None
    path = None
    isRootCA = False
    duration = 0
    signAlgorithm = None
    keyAlgorithm = None
    encAlgorithm = None
    user = None
    group = None
    privateKeyMode = 0o600
    only_pubKeu = True
    templates = None

    def __init__(self, ca_json, path):
        if json is not None:
            self.subject = jsonToSubject(ca_json['Subject'])
            self.duration = int(ca_json["Key"]["Duration"])
            self.isRootCA = bool(ca_json['isRootCA'])
            self.signAlgorithm = ca_json["SignAlgorithm"]
            self.keyAlgorithm = ca_json["Key"]["Algorithm"]
            self.encAlgorithm = ca_json["Key"]["Encryption"]
            self._init_Access(ca_json["Access"])
            #self.templates = ca_json["Templates"]
        if path is not None:
            self.path = Path(path)
        #load_templates()
        #self.init_path()
    
    def load_templates(self, template_path=None):
        if templates_path is None or not templates_path.exists():
            templates_path = self.path / TEMPLATES_DIR

        for template in templates_path.iterdir():
            template_json = json.load(open(template, "r"))

            template_name = template_json["Name"]

            subject_json = template_json["Subject"]

            if subject_json["CN"] is None or not subject_json["CN"]:
                print("There is no CN to request")
                continue
   
            crypto.X509Name(crypto.X509().get_subject())
            subject.C  = subject_json.get('C' , self.subject.C ) 
            subject.ST = subject_json.get('ST', self.subject.ST ) 
            subject.L  = subject_json.get('L' , self.subject.L ) 
            subject.O  = subject_json.get('O' , self.subject.O ) 
            subject.OU = subject_json.get('OU', self.subject.OU )
            subject.CN = subject_json.get('CN', self.subject.OU )

            self.template[template_name] = {}
            self.template[template_name]["Name"] = template_name
            self.template[template_name]["Subject"] = subject
            template_ext = self.template[template_name]["Extensions"]
            template_ext = {}

            for extention_json in template_json["Extensions"]:
                name = extention_json["Name"]
                isCritical = bool(extention_json["Critical"])
                value_json = extention_json["Value"]
                value = ""

                if template_ext[name] is not None:
                    print(name + " is already defined, ERROR")
                    return

                if name == "basicConstraints":
                    if "CA:TRUE" == value_json[:7].upper():
                        value = "CA:TRUE"
                        path_len = value_json.split(",")[1]
                    









    def _init_Access(self, access_json):
        self.user = pwd.getpwnam(access_json["User"])
        self.group = grp.getgrnam(access_json["Group"])
        privateKeyMode = access_json["PrivateKeyMode"]

    def get_CA_name(self):
        if self.subject is not None:
            return self.subject.CN

    def init_path(self):
        os.chown(str(self.path), self.user.pw_uid, self.group.gr_gid)
        self.path.chmod(0o744)

        checkDir(self.path / PRIVATE_DIR   , 0o700, self.user, self.group)
        checkDir(self.path / CACERTS_DIR   , 0o750, self.user, self.group)
        checkDir(self.path / CERTS_DIR     , 0o750, self.user, self.group)
        checkDir(self.path / NEWCERTS_DIR  , 0o750, self.user, self.group)
        checkDir(self.path / CSR_DIR       , 0o750, self.user, self.group)
        checkDir(self.path / NEWCSR_DIR    , 0o750, self.user, self.group)
        checkDir(self.path / CRL_DIR       , 0o750, self.user, self.group)
        checkDir(self.path / TEMPLATES_DIR , 0o750, self.user, self.group)


    def generate_private_key(self, passphrase):
        key_pkey = generate_key(self.keyAlgorithm)
        now = datetime.datetime.now()
        key_fileName = now.strftime("%Y%m%d%H%M%S") + "-000000-" + self.get_CA_name()
        key_path = self.path / PRIVATE_DIR / (key_fileName + KEY_EXT)
        with open(key_path, "wb") as key_file:
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, 
                                                  key_pkey, 
                                                  self.encAlgorithm, 
                                                  passphrase))

        pub_path = self.path / PUBLIC_DIR / (key_fileName + PUB_EXT)
        with open(pub_path, "wb") as pub_file:
            pub_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, 
                                                 key_pkey))

        return key_fileName


    def load_private_key(self, name, passphrase):
        key_path = self.path / PRIVATE_DIR / (name + KEY_EXT)
        pub_path = self.path / PUBLIC_DIR  / (name + PUB_EXT)
        
        key_file = open(key_path, 'rb').read()
        self.pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file, passphrase)

        currentKey_path = self.path / CURRENTKEY_SL
        if currentKey_path.is_symlink():
            currentKey_path.unlink()
        currentKey_path.symlink_to(key_path)

        currentPub_path = self.path / CURRENTPUB_SL
        if currentPub_path.is_symlink():
            currentPub_path.unlink()
        currentPub_path.symlink_to(pub_path)
 
        self.only_pubKey = False


    def load_public_key(self, name):
        pub_path = self.path / PUBLIC_DIR  / (name + PUB_EXT)

        pub_file = open(pub_path, 'rb').read()
        self.pkey = crypto.load_publickey(crypto.FILETYPE_PEM, pub_file)

        currentPub_path = self.path / CURRENTPUB_SL
        if currentPub_path.is_symlink():
            currentPub_path.unlink()
        currentPub_path.symlink_to(pub_path)

        self.only_pubKey = False


    def create_self_signed_cert(self, dateBegin=None):
        if not self.isRootCA:
            print("This CA is not a root CA")
            return None
        
        if self.pkey is None or self.only_pubKey:
            print("No loaded private key")
            return None
    
        # create a self-signed cert
        cert = crypto.X509()
        cert.set_subject(self.subject)

        serial = generate_serial()
        cert.set_serial_number(int(serial, 16))

        if dateBegin is not None:
            cert.set_notBefore(dateBegin)
        else:
            cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.duration)
        cert.set_issuer(cert.get_subject())

        cert.add_extensions([
            crypto.X509Extension(
                b"keyUsage", False,
                b"Digital Signature, Non Repudiation, Key Encipherment"),
            crypto.X509Extension(
                b"basicConstraints", False, b"CA:FALSE"),
            crypto.X509Extension(
                b"basicConstraints", False, b"CA:TRUE"),
            crypto.X509Extension(
                b'extendedKeyUsage', False, b'serverAuth, clientAuth')#,
            #crypto.X509Extension(
            #    b"subjectAltName", False, b"tutu.fr")
        ])

        cert.set_pubkey(self.pkey)
        cert.sign(self.pkey, self.signAlgorithm)
      
        cert_name  = cert.get_notBefore().decode("utf-8")[:-1]
        cert_name += "-" + serial[:6].decode("utf-8")
        cert_name += "-" + self.get_CA_name()

        cert_path = self.path / CACERTS_DIR / (cert_name + CERT_EXT)
        with open(cert_path, "wb") as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        key_path = (self.path / CURRENTKEY_SL).resolve()
        renamedKey_path = self.path / PRIVATE_DIR / (cert_name + KEY_EXT)
        key_path.rename(renamedKey_path)

        currentKey_path = self.path / CURRENTKEY_SL
        if currentKey_path.is_symlink():
            currentKey_path.unlink()
        currentKey_path.symlink_to(renamedKey_path)
        
        pub_path = (self.path / CURRENTPUB_SL).resolve()
        renamedPub_path = self.path / PUBLIC_DIR / (cert_name + PUB_EXT)
        pub_path.rename(renamedPub_path)

        currentPub_path = self.path / CURRENTPUB_SL
        if currentPub_path.is_symlink():
            currentPub_path.unlink()
        currentPub_path.symlink_to(renamedPub_path)
        
        return cert.get_serial_number()

    def generate_csr(self, pub_path, template_selector = "default"):
#        if self.pkey is None:
        
#        pub_file = open(pub_path, 'rb').read()
#        pub_pkey = crypto.load_publickey(crypto.FILETYPE_PEM, pub_file)

        template = self.templates[template_selector]
        
        req = crypto.X509Req()
        subject = req.get_subject()

        if template["CN"] is None or not template["CN"]:
            print("There is no CN to request")
            return

        subject.C  = template.get('C' , self.subject.C ) 
        subject.ST = template.get('ST', self.subject.ST ) 
        subject.L  = template.get('L' , self.subject.L ) 
        subject.O  = template.get('O' , self.subject.O ) 
        subject.OU = template.get('OU', self.subject.OU )

        print(subject)

    
#        for key, value in name.items():
#            setattr(subj, key, value)
#    
#        req.set_pubkey(pkey)
#        req.sign(pkey, digest)
#        return req


ca_json = json.load(open("CAtest.json", "r"))
ca = CA(ca_json, ".")

ca.init_path()

#ca.generate_csr("toto")


cafalse = generate_basicConstraints(True, isCA=True)
print(str(cafalse) + " " + str(cafalse.get_critical()) + " " + str(cafalse.get_data()))

cafalse = generate_basicConstraints(True, isCA=False)
print(str(cafalse) + " " + str(cafalse.get_critical()) + " " + str(cafalse.get_data()))


cafalse = generate_basicConstraints(True, isCA=True, pathlen=8)
print(str(cafalse) + " " + str(cafalse.get_critical()) + " " + str(cafalse.get_data()))

cafalse = generate_basicConstraints(True, isCA=True, pathlen=256)
print(str(cafalse) + " " + str(cafalse.get_critical()) + " " + str(cafalse.get_data()))

cafalse = generate_basicConstraints(True, isCA=False, pathlen=2)
#print(str(cafalse) + " " + str(cafalse.get_critical()) + " " + str(cafalse.get_data()))

#cafalse = generate_basicConstraints(True, "CA:FALSE, patle:3")
#print(str(cafalse) + " " + str(cafalse.get_critical()) + " " + str(cafalse.get_data()))




#newkey_path = ca.generate_private_key(passphraseCallback)
#ca.load_private_key(newkey_path, passphraseCallback)
#ca.create_self_signed_cert()

#print(binascii.hexlify(os.urandom(20)).upper())
#
#print(calledWith)
#
#
#print(ca.get_CA_name())
#print(ca.isRootCA)
#print(ca.duration)
#print(ca.signAlgorithm)
#print(ca.keyAlgorithm)
#print(ca.encAlgorithm)
#print(ca.subject)


#create_self_signed_cert(".")
#jsonToX509Name("CAtest.json")
#print generate_ecdsa_key("secp256r1")
#print TYPE_ECDSA

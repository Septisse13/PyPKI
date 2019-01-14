import Authority

import FileStorage
import KeyPolicy
import FileAccess
import Key

from cryptography import x509
import datetime
from pathlib import Path
import jsonUtils

from cryptography.x509.oid import NameOID
from CertificateTemplate import CertificateTemplate
from cryptography.x509 import extensions

import Subject

attr = {
    NameOID.COUNTRY_NAME : "FR",
    NameOID.STATE_OR_PROVINCE_NAME : "state",
    NameOID.LOCALITY_NAME : "locality",
    NameOID.ORGANIZATION_NAME : "organization",
    NameOID.ORGANIZATIONAL_UNIT_NAME : "organization unit",
    NameOID.COMMON_NAME : "common name"
}

subject = Subject.Subject(attr)

signKeyPolicy = KeyPolicy.KeyPolicy(1000, "rsa2048", "aes-192-cbc")

signKeyAccess = FileAccess.FileAccess("septisse", "septisse", 0o600)
signKeyStorage = FileStorage.FileStorage("./private")
signKeyStorage.nameTemplate = "{id}.key"
signKeyStorage.access = signKeyAccess

caCertAccess = FileAccess.FileAccess("septisse", "septisse", 0o644)
caCertStorage = FileStorage.FileStorage("./cacert")
caCertStorage.nameTemplate = "{id}.cacrt"
caCertStorage.access = caCertAccess

certAccess = FileAccess.FileAccess("septisse", "septisse", 0o644)
certStorage = FileStorage.FileStorage("./cert")
certStorage.nameTemplate = "{id}.crt"
certStorage.access = certAccess

childTemplateAccess = FileAccess.FileAccess("septisse", "septisse", 0o644)
childTemplateStorage = FileStorage.FileStorage("./template")
childTemplateStorage.nameTemplate = "{id}.template"
childTemplateStorage.access = childTemplateAccess

caCSRAccess = FileAccess.FileAccess("septisse", "septisse", 0o644)
caCSRStorage = FileStorage.FileStorage("./cacsr")
caCSRStorage.nameTemplate = "{id}.cacsr"
caCSRStorage.access = caCSRAccess

csrAccess = FileAccess.FileAccess("septisse", "septisse", 0o644)
csrStorage = FileStorage.FileStorage("./csr")
csrStorage.nameTemplate = "{id}.csr"
csrStorage.access = csrAccess

authorityCertTemplate = CertificateTemplate()
authorityCertTemplate.subject = subject
authorityCertTemplate.duration = datetime.timedelta(365, 0, 0)
authorityCertTemplate.addExtension(extensions.BasicConstraints(True, 42), True)

authority = Authority.Authority("authtest")
authority.signKeyStorage = signKeyStorage
authority.caCertStorage = caCertStorage
authority.certStorage = certStorage
authority.childTemplateStorage = childTemplateStorage
authority.caCSRStorage = caCSRStorage
authority.csrStorage = csrStorage
authority.authorityTemplate = authorityCertTemplate
authority.signKeyPolicy = signKeyPolicy

try:
    authority.signKeyStorage.create()
except FileExistsError as e:
    print(e)
try:
    authority.caCertStorage.create()
except FileExistsError as e:
    print(e)
try:
    authority.certStorage.create()
except FileExistsError as e:
    print(e)
try:
    authority.childTemplateStorage.create()
except FileExistsError as e:
    print(e)
try:
    authority.caCSRStorage.create()
except FileExistsError as e:
    print(e)
try:
    authority.csrStorage.create()
except FileExistsError as e:
    print(e)

#authority.renewSignKey()
#authority.generateSelfSignedCert(datetime.datetime.today() - datetime.timedelta(1, 0, 0))
#authority.generateCaCSR()

with open(".authority", "w") as f:
    f.write(str(authority))

#authority.generateCaCSR()
#
#authorityJSon = jsonUtils.authorityToJSon(authority)
#print(authorityJSon)

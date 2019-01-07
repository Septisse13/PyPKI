import jsonUtils
import json
import datetime
from cryptography.x509.oid import NameOID
from cryptography.x509 import extensions
from cryptography.x509 import general_name
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from cryptography.x509.oid import ExtendedKeyUsageOID

from FileAccess import FileAccess
from FileStorage import FileStorage
from Subject import Subject
from CertificateTemplate import CertificateTemplate
from pathlib import Path
from string import Template

fileAccess = FileAccess("septisse", "septisse", 0o750)
fileAccessJSon = jsonUtils.fileAccessToJSon(fileAccess)
#print(fileAccessJSon)
fileAccess = jsonUtils.fileAccessFromJSon(json.loads(fileAccessJSon))
#print(oct(fileAccess.getMode()))

attr = {
    NameOID.COUNTRY_NAME : "FR",
    NameOID.STATE_OR_PROVINCE_NAME : "state",
    NameOID.LOCALITY_NAME : "locality",
    NameOID.ORGANIZATION_NAME : "organization",
    NameOID.ORGANIZATIONAL_UNIT_NAME : "organization unit",
    NameOID.COMMON_NAME : "common name"
}

subject = Subject.fromObjStrDict(attr)
subjectJSon = jsonUtils.subjectToJSon(subject)
#print(subjectJSon)
subject = jsonUtils.subjectFromJSon(json.loads(subjectJSon))
#print(subject)


#print(extensions.BasicConstraints(True, 42))

basicConstraints = extensions.BasicConstraints(True, 42)

rfc822name = general_name.RFC822Name("toto@google.com")
dnsname = general_name.DNSName("toto.fr")
ipadressname = general_name.IPAddress(IPv4Address("1.2.3.4"))

generalNames = [rfc822name] + [dnsname] + [ipadressname]
san = extensions.SubjectAlternativeName(generalNames)
sanJSon = jsonUtils.subjectAlternativeNameToJSon(san)
#print(sanJSon)
san = jsonUtils.subjectAlternativeNameFromJSon(json.loads(sanJSon))
#print(san)

keyUsage = extensions.KeyUsage(
                digital_signature = True,
                content_commitment = False,
                key_encipherment = True,
                data_encipherment = False,
                key_agreement = True,
                key_cert_sign = False,
                crl_sign = True,
                encipher_only = False,
                decipher_only = False)
#print(keyUsage)
keyUsageJSon = jsonUtils.keyUsageToJSon(keyUsage)
#print(keyUsageJSon)
keyUsage = jsonUtils.keyUsageFromJSon(json.loads(keyUsageJSon))
print(keyUsage)

eku_list = [    ExtendedKeyUsageOID.CODE_SIGNING,
                ExtendedKeyUsageOID.EMAIL_PROTECTION]
eku = extensions.ExtendedKeyUsage(eku_list)
#print(eku)
ekuJSon = jsonUtils.extendedKeyUsageToJSon(eku)
#print(ekuJSon)
eku = jsonUtils.extendedKeyUsageFromJSon(json.loads(ekuJSon))
#print(eku)


permittedSubTree = [general_name.DNSName("*.toto.fr"), general_name.RFC822Name("*@toto.fr")]
excludedSubTree = [general_name.IPAddress(IPv4Network("1.2.3.0/24"))]
nameConstraints = extensions.NameConstraints(permittedSubTree, excludedSubTree)

extension = [keyUsage, eku, san, basicConstraints, nameConstraints]
extensionJSon = jsonUtils.extensionsToJSon(extension)
#print(extensionJSon)

certTemplate = CertificateTemplate()
certTemplate.setSubject(subject)
certTemplate.setDuration(datetime.timedelta(365, 0, 0))
for ext in extension:
    certTemplate.addExtension(ext, True)

certTemplateJSon = jsonUtils.certificateTemplateToJSon(certTemplate)
print(certTemplateJSon)
certTemplate = jsonUtils.certificateTemplateFromJSon(json.loads(certTemplateJSon))
certTemplateJSon = jsonUtils.certificateTemplateToJSon(certTemplate)
print(certTemplateJSon)

certAccess = FileAccess("septisse", "septisse", 0o640)
certStorage = FileStorage()
certStorage.setFolder(Path("cert/"))
certStorage.setNameTemplate(Template("${id}.crt"))
certStorage.setAccess(certAccess)
print(certStorage)
certStorageJSon = jsonUtils.fileStorageToJSon(certStorage)
print(certStorageJSon)
certStorage = jsonUtils.fileStorageFromJSon(json.loads(certStorageJSon))
certStorageJSon = jsonUtils.fileStorageToJSon(certStorage)
print(certStorageJSon)

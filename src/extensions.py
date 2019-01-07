
from cryptography.x509 import extensions

def SubjectKeyIdentifier():
    return extensions.SubjectKeyIdentifier.from_public_key(public_key)

def basicConstraints(isCA, pathlen=None):
    return extensions.BasicConstraints(isCA, pathlen)

# cryptography.x509.oid.ExtendedKeyUsageOID
def extendedKeyUsages(usages):
    return extensions.ExtendedKeyUsages(usages)

# usages: cryptography.x509.general_name
def SubjectAlternativeName():
    return extensions.ExtendedKeyUsages(usages)

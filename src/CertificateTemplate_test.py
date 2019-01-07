from CertificateTemplate import CertificateTemplate
from cryptography.x509 import extensions


certTemplate = CertificateTemplate()

#subjectKeyIdentifier = extensions.SubjectKeyIdentifier.from_public_key(public_key)
#certTemplate.addExtension(subjectKeyIdentifier, True)

basicConstraints = extensions.BasicConstraints(True, 12)
certTemplate.addExtension(basicConstraints, True)

print(certTemplate.getExtensions())

from cryptography.x509.oid import NameOID

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

print("C :" + subject.country)
print("ST :" + subject.state)
print("L :" + subject.locality)
print("O :" + subject.organization)
print("OU :" + subject.organisationUnit)
print("CN :" + subject.commonName)

print(subject.x509Name)

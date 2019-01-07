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

subject = Subject.Subject.fromObjStrDict(attr)

print("C :" + subject.getC())
print("ST :" + subject.getST())
print("L :" + subject.getL())
print("O :" + subject.getO())
print("OU :" + subject.getOU())
print("CN :" + subject.getCN())

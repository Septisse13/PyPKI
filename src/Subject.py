from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import oid

from collections import OrderedDict

class Subject(x509.Name):

    def __init__(self, attributes):
        super().__init__(attributes)

    @staticmethod
    def fromObjStrDict(attributes):
        """ Initialise un Subject à partir d'un dictionnaire {OID: str}

        Args:
            attributes ({OID: str}): Le dictionnaire associant les OID et leurs
                attributs.

        Returns:
            Subject : Le sujet
        """
        nameAttributes = []
        for nameOID in attributes.keys():
            nameAttribute = x509.NameAttribute(nameOID,
                attributes[nameOID])
            nameAttributes.append(nameAttribute)
        return Subject(nameAttributes)

    @staticmethod
    def fromStrStrDict(attributes):
        """ Initialise un Subject à partir d'un dictionnaire {str: str}

        Args:
            attributes ({str: str}): Le dictionnaire associant les OID et leurs
                attributs.

        Returns:
            Subject : Le sujet
        """
        nameAttributes = {}
        # Inverse les key et les values
        NAME_OID = {v: k for k, v in oid._OID_NAMES.items()}
        for nameOIDStr, value in attributes.items():
            nameAttributes[NAME_OID[nameOIDStr]] = value
        return Subject.fromObjStrDict(nameAttributes)

    @property
    def country(self):
        """ x509.NameAttribute : le country du sujet."""
        return self.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value

    @property
    def state(self):
        """ x509.NameAttribute : le state du sujet."""
        return self.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value

    @property
    def locality(self):
        """ x509.NameAttribute : la locality du sujet."""
        return self.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value

    @property
    def organization(self):
        """ x509.NameAttribute : la organization du sujet."""
        return self.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value

    @property
    def organisationUnit(self):
        """ x509.NameAttribute : la organisationUnit du sujet."""
        return self.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value

    @property
    def commonName(self):
        """ x509.NameAttribute : le commonName du sujet."""
        return self.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    def __str__(self):
        return json.dumps(self.toJSon(self), indent=4)

    @staticmethod
    def fromJSon(subjectJSon):
        """ Initialise un Subject à partir d'un JSon

        Args:
            extensionsJSon (str): Le Subject au format JSon.

        Returns:
            Subject: Le Subject
        """
        return Subject.fromStrStrDict(subjectJSon)

    @staticmethod
    def toJSon(subject):
        """ Retourne un Subject au format JSon.

        Args:
            subject (Subject): Le Subject.

        Returns:
            dict : Le Subject au format JSon.
        """
        # Construction d'un dictionnaire {oid: value}
        # L'oeil attentif remarquera la perversité des développeurs de la lib
        # crypto : rdns est une liste de RelativeDistinguishedName. Chaque RDN
        # contient un ou plusieurs NameAttribute, x509 le permettant. Or l'usage
        # veut que chaque  RelativeDistinguishedName ne soit valué strictement
        # qu'une fois... Les dev ont rien trouvé de mieux que de fournir comme
        # unique interface un itérateur...
        attr_dict = {}
        for rdn in subject.rdns:
            attr = next(iter(rdn))
            attr_dict[attr.oid] = attr.value

        subject_dict = OrderedDict()
        # Ordonancement standart des principaux NamesOID : C,ST,L,O,OU,CN
        if subject.country:
            attr_dict.pop(NameOID.COUNTRY_NAME)
            subject_dict[oid._OID_NAMES[NameOID.COUNTRY_NAME]] = subject.country
        if subject.state:
            attr_dict.pop(NameOID.STATE_OR_PROVINCE_NAME)
            subject_dict[oid._OID_NAMES[NameOID.STATE_OR_PROVINCE_NAME]] = subject.state
        if subject.locality:
            attr_dict.pop(NameOID.LOCALITY_NAME)
            subject_dict[oid._OID_NAMES[NameOID.LOCALITY_NAME]] = subject.locality
        if subject.organization:
            attr_dict.pop(NameOID.ORGANIZATION_NAME)
            subject_dict[oid._OID_NAMES[NameOID.ORGANIZATION_NAME]] = subject.organization
        if subject.organisationUnit:
            attr_dict.pop(NameOID.ORGANIZATIONAL_UNIT_NAME)
            subject_dict[oid._OID_NAMES[NameOID.ORGANIZATIONAL_UNIT_NAME]] = subject.organisationUnit
        if subject.commonName:
            attr_dict.pop(NameOID.COMMON_NAME)
            subject_dict[oid._OID_NAMES[NameOID.COMMON_NAME]] = subject.commonName
        for key, attr in attr_dict:
            subject_dict[key] = attr.value
        return subject_dict

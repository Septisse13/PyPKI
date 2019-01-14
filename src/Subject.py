from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import oid

from collections import OrderedDict
import json

class Subject():

    def __init__(self, attributes):
        """ Initialise un Subject à partir d'un dictionnaire {OID: str}

        Args:
            attributes ({OID: str}): Le dictionnaire associant les OID et leurs
                attributs.

        Returns:
            Subject : Le sujet
        """
        self._attributes = attributes

    @property
    def x509Name(self):
        nameAttributes = []
        for nameOID, value in self._attributes.items():
            nameAttribute = x509.NameAttribute(nameOID, value)
            nameAttributes.append(nameAttribute)
        return x509.Name(nameAttributes)

    def __setitem__(self, key, item):
        self._attributes[key] = item

    def __getitem__(self, key):
        return self._attributes[key]

    def __repr__(self):
        return repr(self._attributes)

    def __len__(self):
        return len(self._attributes)

    def __delitem__(self, key):
        del self._attributes[key]

    def clear(self):
        return self._attributes.clear()

    def copy(self):
        return self._attributes.copy()

    def has_key(self, k):
        return k in self._attributes

    def update(self, *args, **kwargs):
        return self._attributes.update(*args, **kwargs)

    def keys(self):
        return self._attributes.keys()

    def values(self):
        return self._attributes.values()

    def items(self):
        return self._attributes.items()

    def pop(self, *args):
        return self._attributes.pop(*args)

    def __cmp__(self, dict_):
        return self.__cmp__(self._attributes, dict_)

    def __contains__(self, item):
        return item in self._attributes

    def __iter__(self):
        return iter(self._attributes)

    def __unicode__(self):
        return unicode(repr(self._attributes))

    @property
    def country(self):
        """ x509.NameAttribute : le country du sujet."""
        return self._attributes[NameOID.COUNTRY_NAME]

    @country.setter
    def country(self, country):
        self._attributes[NameOID.COUNTRY_NAME] = country

    @property
    def state(self):
        """ x509.NameAttribute : le state du sujet."""
        return self._attributes[NameOID.STATE_OR_PROVINCE_NAME]

    @state.setter
    def state(self, state):
        self._attributes[NameOID.STATE_OR_PROVINCE_NAME] = state

    @property
    def locality(self):
        """ x509.NameAttribute : la locality du sujet."""
        return self._attributes[NameOID.LOCALITY_NAME]

    @locality.setter
    def locality(self, locality):
        self._attributes[NameOID.LOCALITY_NAME] = locality

    @property
    def organization(self):
        """ x509.NameAttribute : la organization du sujet."""
        return self._attributes[NameOID.ORGANIZATION_NAME]

    @organization.setter
    def organization(self, organization):
        self._attributes[NameOID.ORGANIZATION_NAME] = organization

    @property
    def organisationUnit(self):
        """ x509.NameAttribute : la organisationUnit du sujet."""
        return self._attributes[NameOID.ORGANIZATIONAL_UNIT_NAME]

    @organisationUnit.setter
    def organisationUnit(self, organisationUnit):
        self._attributes[NameOID.ORGANIZATIONAL_UNIT_NAME] = organisationUnit

    @property
    def commonName(self):
        """ x509.NameAttribute : le commonName du sujet."""
        return self._attributes[NameOID.COMMON_NAME]

    @commonName.setter
    def commonName(self, commonName):
        self._attributes[NameOID.COMMON_NAME] = commonName

    def __str__(self):
        return json.dumps(self.toJSon(), indent=4)

    @staticmethod
    def fromJSon(subjectJSon):
        """ Initialise un Subject à partir d'un JSon

        Args:
            extensionsJSon (str): Le Subject au format JSon.

        Returns:
            Subject: Le Subject
        """
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
        for nameOIDStr, value in subjectJSon.items():
            if nameOIDStr in NAME_OID.keys():
                nameAttributes[NAME_OID[nameOIDStr]] = value
            else:
                nameAttributes[oid.ObjectIdentifier(nameOIDStr)] = value
        return Subject(nameAttributes)

    def toJSon(self):
        """ Retourne un Subject au format JSon.

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
        attr_dict = self.copy()

        subject_dict = OrderedDict()
        # Ordonancement standart des principaux NamesOID : C,ST,L,O,OU,CN
        if self.country:
            attr_dict.pop(NameOID.COUNTRY_NAME)
            subject_dict[oid._OID_NAMES[NameOID.COUNTRY_NAME]] = self.country
        if self.state:
            attr_dict.pop(NameOID.STATE_OR_PROVINCE_NAME)
            subject_dict[oid._OID_NAMES[NameOID.STATE_OR_PROVINCE_NAME]] = self.state
        if self.locality:
            attr_dict.pop(NameOID.LOCALITY_NAME)
            subject_dict[oid._OID_NAMES[NameOID.LOCALITY_NAME]] = self.locality
        if self.organization:
            attr_dict.pop(NameOID.ORGANIZATION_NAME)
            subject_dict[oid._OID_NAMES[NameOID.ORGANIZATION_NAME]] = self.organization
        if self.organisationUnit:
            attr_dict.pop(NameOID.ORGANIZATIONAL_UNIT_NAME)
            subject_dict[oid._OID_NAMES[NameOID.ORGANIZATIONAL_UNIT_NAME]] = self.organisationUnit
        if self.commonName:
            attr_dict.pop(NameOID.COMMON_NAME)
            subject_dict[oid._OID_NAMES[NameOID.COMMON_NAME]] = self.commonName
        for key, value in attr_dict.items():
            if key in _OID_NAMES.keys():
                subject_dict[oid._OID_NAMES[key]] = value
            else:
                subject_dict[str(key)] = value

        return subject_dict

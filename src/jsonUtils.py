
from cryptography.x509 import oid
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509 import general_name
from ipaddress import IPv4Address, IPv6Address
import ipaddress
import datetime
from cryptography.x509 import extensions
from pathlib import Path

import json
# TODO : CRLdistribution point
#





def extensionsFromJSon(extensionsJSon):
    """ Initialise un extensions.Extension à partir d'un JSon

    Args:
        extensionsJSon (str): Le extensions.Extension
            au format JSon.

    Returns:
        extensions.Extension: Le extensions.Extension
    """
    extensions = {}
    for name, value in extensionsJSon.items():
        if name in extensions.keys():
            #TODO ERROR : duplicate ext
            return
        elif name == "basicConstraints":
            extensions["basicConstraints"] = basicConstraintsFromJSon(value)
        elif name == "subjectAltName":
            extensions["subjectAltName"] = subjectAlternativeNameFromJSon(value)
        elif name == "keyUsage":
            extensions["keyUsage"] = keyUsageFromJSon(value)
        elif name == "extendedKeyUsage":
            extensions["extendedKeyUsage"] = extendedKeyUsageFromJSon(value)
        elif name == "nameConstraints":
            extensions["nameConstraints"] = nameConstraintsFromJSon(value)
    return extensions.values()

def extensionsToJSon(extensionsList):
    """ Retourne une liste de extensions.Extension au format JSon.

    Args:
        extensionsList (list[extensions.Extension]): La liste d'extensions.Extension.

    Returns:
        dict : La liste d'extensions.Extension au format JSon.
    """
    extensions_dict = {}
    for ext in extensionsList:
        if   isinstance(ext, extensions.BasicConstraints):
            extensions_dict["basicConstraints"] = basicConstraintsToJSon(ext)
        elif isinstance(ext, extensions.SubjectAlternativeName):
            extensions_dict["subjectAltName"] = subjectAlternativeNameToJSon(ext)
        elif isinstance(ext, extensions.KeyUsage):
            extensions_dict["keyUsage"] = keyUsageToJSon(ext)
        elif isinstance(ext, extensions.ExtendedKeyUsage):
            extensions_dict["extendedKeyUsage"] = extendedKeyUsageToJSon(ext)
        elif isinstance(ext, extensions.NameConstraints):
            extensions_dict["nameConstraints"] = nameConstraintsToJSon(ext)
        else:
            #TODO ERROR : unreconized extension
            #return
            pass
    return extensions_dict

def basicConstraintsFromJSon(basicConstraintsJSon):
    """ Initialise un extensions.BasicConstraints à partir d'un JSon

    Args:
        basicConstraintsJSon (str): Le extensions.BasicConstraints
            au format JSon.

    Returns:
        extensions.BasicConstraints: Le extensions.BasicConstraints
    """
    ca = basicConstraintsJSon["ca"]
    pathlen = int(basicConstraintsJSon["pathlen"])
    return extensions.BasicConstraints(ca, pathlen)

def basicConstraintsToJSon(basicConstraints):
    """ Retourne un extensions.BasicConstraints au format JSon.

    Args:
        basicConstraints (extensions.BasicConstraints): La extensions.BasicConstraints.

    Returns:
        dict : La extensions.BasicConstraints au format JSon.
    """
    ca = basicConstraints.ca
    pathlen = basicConstraints.path_length
    basicConstraints_dict = {"ca":ca, "pathlen":pathlen}
    return basicConstraints_dict

def subjectAlternativeNameFromJSon(subjectAlternativeNameJSon):
    """ Initialise une extensions.SubjectAlternativeName à partir d'un JSon

    Args:
        subjectAlternativeNameJSon (str): Le extensions.SubjectAlternativeName
            au format JSon.

    Returns:
        extensions.SubjectAlternativeName: Le extensions.SubjectAlternativeName
    """
    generalNames = []
    for name in subjectAlternativeNameJSon:
        generalNames = generalNames + [generalNameFromJSon(name)]
    return extensions.SubjectAlternativeName(generalNames)

def subjectAlternativeNameToJSon(subjectAlternativeName):
    """ Retourne une extensions.SubjectAlternativeName au format JSon.

    Args:
        subjectAlternativeName (extensions.SubjectAlternativeName):
            La extensions.SubjectAlternativeName.

    Returns:
        dict : La extensions.SubjectAlternativeName au format JSon.
    """
    generalNames_list = []
    for name in subjectAlternativeName:
        generalNames_list = generalNames_list + [generalNameToJSon(name)]
    return generalNames_list

KEY_USAGES = [
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
        "encipher_only",
        "decipher_only"
]

def keyUsageFromJSon(keyUsageJSon):
    """ Initialise un extensions.KeyUsage à partir d'un JSon

    Args:
        keyUsageJSon (str): Le extensions.KeyUsage au format JSon.

    Returns:
        extensions.KeyUsage: Le extensions.KeyUsage
    """
    keyUsage = {}
    for keyUsageStr in KEY_USAGES:
        keyUsage[keyUsageStr] = False

    for keyUsageStr in keyUsageJSon:
        if keyUsageStr not in KEY_USAGES:
            raise ValueError("Unreconized extension {ext}.".format(ext=keyUsageStr))
        elif keyUsage[keyUsageStr]:
            raise ValueError("Duplicate extension.")
        else:
            keyUsage[keyUsageStr] = True

    return extensions.KeyUsage(
                digital_signature = keyUsage["digital_signature"],
                content_commitment = keyUsage["content_commitment"],
                key_encipherment = keyUsage["key_encipherment"],
                data_encipherment = keyUsage["data_encipherment"],
                key_agreement = keyUsage["key_agreement"],
                key_cert_sign = keyUsage["key_cert_sign"],
                crl_sign = keyUsage["crl_sign"],
                encipher_only = keyUsage["encipher_only"],
                decipher_only = keyUsage["decipher_only"]
                )

def keyUsageToJSon(keyUsage):
    """ Retourne une extensions.KeyUsage au format JSon.

    Args:
        keyUsage (extensions.KeyUsage):
            La extensions.KeyUsage.

    Returns:
        dict : La extensions.KeyUsage au format JSon.
    """
    keyUsage_dict = {}
    keyUsage_dict["digital_signature"] = keyUsage.digital_signature
    keyUsage_dict["content_commitment"] = keyUsage.content_commitment
    keyUsage_dict["key_encipherment"] = keyUsage.key_encipherment
    keyUsage_dict["data_encipherment"] = keyUsage.data_encipherment
    keyUsage_dict["key_agreement"] = keyUsage.key_agreement
    keyUsage_dict["key_cert_sign"] = keyUsage.key_cert_sign
    keyUsage_dict["crl_sign"] = keyUsage.crl_sign

    keyUsage_list = [keyUsage for keyUsage, bool in keyUsage_dict.items() if bool]

    return keyUsage_list

OID_EKU = {
    ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth",
    ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth",
    ExtendedKeyUsageOID.CODE_SIGNING: "codeSigning",
    ExtendedKeyUsageOID.EMAIL_PROTECTION: "emailProtection",
    ExtendedKeyUsageOID.TIME_STAMPING: "timeStamping",
    ExtendedKeyUsageOID.OCSP_SIGNING: "OCSPSigning"
}

def extendedKeyUsageFromJSon(extendedKeyUsageJSon):
    """ Initialise un extensions.ExtendedKeyUsage à partir d'un JSon

    Args:
        extendedKeyUsageJSon (str): Le extensions.ExtendedKeyUsage au format JSon.

    Returns:
        extensions.ExtendedKeyUsage: Le extensions.ExtendedKeyUsage
    """
    EKU_OID = {v: k for k, v in OID_EKU.items()}
    extendedKeyUsage_list = []
    for ekuName in extendedKeyUsageJSon:
        if ekuName not in EKU_OID.keys():
            #TODO ERROR
            return
        else:
            extendedKeyUsage_list += [EKU_OID[ekuName]]
    return extensions.ExtendedKeyUsage(extendedKeyUsage_list)

def extendedKeyUsageToJSon(extendedKeyUsage):
    """ Retourne une extensions.ExtendedKeyUsage au format JSon.

    Args:
        extendedKeyUsage (extensions.ExtendedKeyUsage): La
            extensions.ExtendedKeyUsage.

    Returns:
        dict : La extensions.ExtendedKeyUsage au format JSon.
    """
    extendedKeyUsage_list = []
    for ekuOID in extendedKeyUsage:
        extendedKeyUsage_list += [OID_EKU[ekuOID]]
    return extendedKeyUsage_list

def nameConstraintsFromJSon(nameConstraintsJSon):
    """ Initialise un extensions.NameConstraints à partir d'un JSon

    Args:
        nameConstraintsJSon (str): Le extensions.NameConstraints au format JSon.

    Returns:
        extensions.NameConstraints: Le extensions.NameConstraints
    """
    permittedSubTreeJSon = nameConstraintsJSon["permittedSubTree"]
    excludedSubTreeJSon = nameConstraintsJSon["excludedSubTree"]

    permittedSubTree = []
    for permittedName in permittedSubTreeJSon:
        permittedSubTree += [generalNameFromJSon(permittedName)]

    excludedSubTree = []
    for excludedName in excludedSubTreeJSon:
        excludedSubTree += [generalNameFromJSon(excludedName)]

    return extensions.NameConstraints(permittedSubTree, excludedSubTree)

def nameConstraintsToJSon(nameConstraints):
    """ Retourne une extensions.NameConstraints au format JSon.

    Args:
        nameConstraints (extensions.NameConstraints): La
            extensions.NameConstraints.

    Returns:
        dict : La extensions.NameConstraints au format JSon.
    """
    permittedSubTree = nameConstraints.permitted_subtrees
    excludedSubTree = nameConstraints.excluded_subtrees

    permittedSubTreeJSon = []
    for permittedName in permittedSubTree:
        permittedSubTreeJSon += [generalNameToJSon(permittedName)]

    excludedSubTreeJSon = []
    for excludedName in excludedSubTree:
        excludedSubTreeJSon += [generalNameToJSon(excludedName)]

    nameConstraints_dict = {
        "permittedSubTree":permittedSubTreeJSon,
        "excludedSubTree":excludedSubTreeJSon
    }

    return nameConstraints_dict

def generalNameFromJSon(generalNameJSon):
    """ Initialise un x509.GeneralName à partir d'un JSon

    Args:
        generalNameJSon (str): Le x509.GeneralName au format JSon.

    Returns:
        x509.GeneralName: Le x509.GeneralName
    """
    type, value = generalNameJSon.split(":")
    if   type == "DNS":
        return general_name.DNSName(value)
    elif type == "RFC822":
        return general_name.RFC822Name(value)
    elif type == "URI":
        return general_name.UniformResourceIdentifier(value)
    elif type == "DIR":
        return general_name.DirectoryName(value)
    elif type == "RID":
        return general_name.RegisteredID(value)
    elif type == "IP":
        if "/" in value:
            return general_name.IPAddress(ipaddress.ip_network(value))
        else:
            return general_name.IPAddress(ipaddress.ip_address(value))
    else:
        raise ValueError("Parsing error : {json}".format(json=generalName))

def generalNameToJSon(generalName):
    """ Retourne un x509.GeneralName au format JSon.

    Args:
        nameConstraints (x509.GeneralName): Le x509.GeneralName.

    Returns:
        str : Le x509.GeneralName au format JSon.
    """
    if   isinstance(generalName, general_name.DNSName):
        return "DNS:" + generalName.value
    elif isinstance(generalName, general_name.RFC822Name):
        return "RFC822:" + generalName.value
    elif isinstance(generalName, general_name.UniformResourceIdentifier):
        return "URI:" + generalName.value
    elif isinstance(generalName, general_name.DirectoryName):
        return "DIR:" + generalName.value
    elif isinstance(generalName, general_name.RegisteredID):
        return "RID:" + generalName.value
    elif isinstance(generalName, general_name.IPAddress):
        return "IP:" + str(generalName.value)
    else:
        raise ValueError("{type} name is not supported.".format(type=type(generalName)))



def authorityFromJSon(authorityJSon):
    """ Initialise une Authority à partir d'un JSon

    Args:
        authorityJSon (str): L'Authority au format JSon.

    Returns:
        Authority: L'Authority.
    """
    pass

def authorityToJSon(authority):
    authority_dict = {}

    authority_dict["name"] = authority.name

    authority_dict["signKeyStorage"]      = fileStorageToJSon(authority.signKeyStorage)
    authority_dict["cacertStorage"]       = fileStorageToJSon(authority.caCertStorage)
    authority_dict["certStorage"]         = fileStorageToJSon(authority.certStorage)
    authority_dict["certTemplateStorage"] = fileStorageToJSon(authority.certTemplateStorage)

    authority_dict["authorityTemplate"]   = certificateTemplateToJSon(authority.authorityTemplate)


    return authority_dict

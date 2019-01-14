from cryptography import x509
from cryptography.x509 import extensions

import datetime
from collections import OrderedDict

from KeyPolicy import KeyPolicy
from Subject import Subject
import jsonUtils

class CertificateTemplate:

    def __init__(self):
        self._extensionsDict = {}
        pass

# --------------- Extensions ----------------------#

    def addExtension(self, extension, critical):
        """ Ajoute une extention au template.

        Args:
            extension (extensions.Extension): L'extention ;
            critical (bool): La criticité de l'extension.
        """
        if    isinstance(extension, extensions.SubjectKeyIdentifier) \
           or isinstance(extension, extensions.AuthorityKeyIdentifier):
           raise ValueError("{extension} is not supported.".format(extension=extension))

        for e in self._extensionsDict.keys():
            if e.oid == extension.oid:
                raise ValueError('This extension has already been set.')
        self._extensionsDict[extension] = critical

    def delExtention(self, extensionType):
        """ Supprime une extension du template.

        Args:
            extensionType (cls Extension): Le type d'extension à supprimer.

        """
        for ext in self._extensionsDict.keys():
            if isinstance(type, extensionType):
                self._extensionsDict.pop(ext)
                return

    def getExtension(self, extensionType) -> extensions.Extension:
        """ Retourne l'extension du type extensionType du template.

        Args:
            extensionType (cls Extension): Le type d'extension

        Returns:
            extension.Extension: L'extension du template.
        """
        for ext in self._extensionsDict.keys():
            if isinstance(type, extensionType):
                return ext

    def getExtensions(self):
        """ Retourne la liste des extensions du template. """
        return extensions.Extensions(self._extensionsDict.keys())

# ---------- Subject --------------#
    @property
    def subject(self):
        """ (Subject): Le sujet du template."""
        return self._subject

    @subject.setter
    def subject(self, subject: Subject):
        self._subject = subject

#------------ Duration ---------------#
    @property
    def duration(self):
        """ (datetime.timedelta): La durée de validité du certificat."""
        return self._duration

    @duration.setter
    def duration(self, duration):
        if isinstance(duration, int):
            if duration <= 0:
                print(duration)
                raise ValueError("Duration must be positive.")
            else:
                self.duration = datetime.timedelta(seconds=duration)
        elif isinstance(duration, datetime.timedelta):
            self._duration = duration
        else:
            raise TypeValue("Duration must be a datetime.timedelta.")

    def getEndDate(self, beginDate):
        """ Retourne la date de fin de validité"""
        return beginDate + self.duration

#---------- KeyPolicy ----------------#
    @property
    def keyPolicy(self):
        """(KeyPolicy): La politique de gestion de la clé associé au certificat."""
        return self._keyPolicy

    @keyPolicy.setter
    def keyPolicy(self, keyPolicy):
        if isinstance(keyPolicy, KeyPolicy):
            self._keyPolicy = keyPolicy
        else:
            raise TypeError("keyPolicy must be a keyPolicy")

#---------- Builder ------------------#

    def getCertBuilder(self) -> x509.CertificateBuilder:
        """ Génère un builder de certificat à partir du template.

        Returns:
            (x509.CertificateBuilder): Le builder
        """
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(self.subject.x509Name)
        for ext, critical in self._extensionsDict.items():
            builder = builder.add_extension(ext, critical)
        return builder

    def getCSRBuilder(self) -> x509.CertificateSigningRequestBuilder:
        """ Génère un builder de CSR à partir du template.

        Returns:
            (x509.CertificateSigningRequestBuilder): Le builder
        """
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(self.subject.x509Name)
        for ext, critical in self._extensionsDict.items():
            builder = builder.add_extension(ext, critical)
        return builder

    def __str__(self):
        return json.dumps(self.toJSon(self), indent=4)

    @staticmethod
    def fromJSon(certificateTemplateJSon):
        """ Initialise un CertificateTemplate à partir d'un JSon

        Args:
            certificateTemplateJSon (str): Le CertificateTemplate au format JSon.

        Returns:
            CertificateTemplate: Le CertificateTemplate.
        """
        subject = Subject.fromJSon(certificateTemplateJSon["subject"])
        duration = datetime.timedelta(int(certificateTemplateJSon["duration"]),0,0)
        extensions = jsonUtils.extensionsFromJSon(certificateTemplateJSon["extensions"])

        certificateTemplate = CertificateTemplate()
        certificateTemplate.subject = subject
        certificateTemplate.duration = duration

        for ext in extensions:
            certificateTemplate.addExtension(ext, True)

        return certificateTemplate

    @staticmethod
    def toJSon(certificateTemplate):
        """ Retourne un CertificateTemplate au format JSon.

        Args:
            certificateTemplate (CertificateTemplate): Le CertificateTemplate.

        Returns:
            dict : Le CertificateTemplate au format JSon.
        """
        certificateTemplate_dict = OrderedDict()

        subject_dict = Subject.toJSon(certificateTemplate.subject)
        certificateTemplate_dict["subject"] = subject_dict

        certificateTemplate_dict["duration"] = str(certificateTemplate.duration.days)

        extensions_dict = jsonUtils.extensionsToJSon(certificateTemplate.getExtensions())
        certificateTemplate_dict["extensions"] = extensions_dict

        return certificateTemplate_dict

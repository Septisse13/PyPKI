from pathlib import Path
from FileAccess import FileAccess
import os
import re
import json


class FileDict(object):
    def __init__(self, storage):
        """
        Args:
            FileStorage: Le stockage associé au FileDict
        """
        self._storage = storage

    def keysPath(self) -> list:
        """
        Return
            list[Path]: La liste des Path des fichiers.
        """
        regex = self._storage.nameTemplate.replace("${id}", "*")
        regex = regex.replace("{id}", "*")
        paths = list(self._storage.folder.glob(regex))
        return paths

    def keys(self) -> list:
        """
        Return
            list[str]: La liste des identifiants.
        """
        keys = []
        regex = self._storage.nameTemplate.replace("${id}", "(.*)")
        regex = regex.replace("{id}", "(.*)")
        for path in self.keysPath():
            id = re.search(regex, path.name, re.IGNORECASE)
            keys += [id.group(1)]
        return keys

    def values(self) -> list:
        """
        Returns:
            list[bytes]: La liste des contenus des fichiers.
        """
        values = []
        for key in self.keys():
            values += [self[key]]
        return values

    def items(self) -> list:
        """
        Returns:
            list[(str, bytes)]: La liste des tuples associant les identifiant
                des fichiers et leur contenu.
        """
        values = []
        for key in self.keys():
            values += [(key, self[key])]
        return values

    def len(self) -> int:
        """
        Returns:
            int: Le nombre de fichiers.
        """
        return len(self.keys())

    def iter(self):
        """
        Returns:
            iter: Un itérateur sur la liste des identifiants.
        """
        return iter(self.keys())

    def clear(self):
        """ Supprime tous les fichiers. """
        for key in self.keys():
            self.delFile(key)

    def get(self, id, default=None) -> bytes:
        """ Retourne le contenu du fichier associé à l'identifiant.
        Args:
            id (str): L'identifiant du fichier

        Returns:
            bytes: Le contenu du fichier.
        """
        fileName = self._storage.nameTemplate.format(id = id)
        with open(str(self._storage.folder / fileName), "rb") as file:
            result = file.read()
        return result

    def set(self, id, value):
        """ Met à jour le contenu du fichier identifié par id avec value.
        Si le fichier existe déjà, son contenu est remplacé.

        Args:
            id (str): L'identifiant du fichier ;
            value (bytes): Le contenu du fichier.
        """
        fileName = self._storage.nameTemplate.format(id = id)
        with open(str(self._storage.folder / fileName), "w") as file:
            file.write("")

        self._storage.access.updateAccess(self._storage.folder / fileName)
        with open(str(self._storage.folder / fileName), "wb") as file:
            file.write(value)

    def delFile(self, id):
        """ Supprime le fichier associé à id.

        Args:
            id (str): L'identifiant du fichier à supprimer.
        """
        file = self._storage.folder / self._storage.nameTemplate.format(id = id)
        file.unlink()

    def pop(self, id) -> bytes:
        """ Supprime le fichier identifié par id et retourne son contenu.

        Args:
            id (str): L'identifiant du fichier.

        Returns:
            bytes: Le contenu du fichier supprimé
        """
        result = self.get(id)
        self.delFile(id)
        return result

    def popitem(self):
        """ Supprime le dernier fichier et renvoie le tuple contenant
        l'identifiant et le contenu du fichier supprimé.

        Returns:
            (str, bytes): le tuple contenant l'identifiant et le contenu du
                fichier supprimé.
        """
        key = sorted(self.keys()).pop()
        value = self.get(key)
        self.delFile(key)
        return (key, value)

    def __getitem__(self, id):
        return self.get(id)

    def __setitem__(self, id, value):
        self.set(id, value)

    def __delitem__(self, key):
        self.delFile(key)

    def __len__(self):
        return self.len()

    def __contains__(self, key):
        return key in self.keys()

    def __str__(self):
        return str(self.keys())

class FileStorage:

    def __init__(self, folder):
        """
        Args:
            folder (Path): Le dossier de stockage.
        """
        self.folder = folder
        self._files = FileDict(self)

#---------------------------- Folder ------------------------------------#
    @property
    def folder(self):
        """ (Path): Le dossier de stockage."""
        return self._folder

    @folder.setter
    def folder(self, folder: Path):
        if isinstance(folder, str):
            folder = Path(folder)

        if isinstance(folder, Path):
            self._folder = folder
        else:
            raise TypeError("Folder must be a Path")


#-------------------------- Access ------------------------------------#

    @property
    def access(self):
        """ (FileAccess): Les droits d'accès associés au stockage."""
        return self._access

    @access.setter
    def access(self, access):
        if isinstance(access, FileAccess):
            self._access = access
        else:
            raise TypeError("Access must be a FileAccess")

#------------------------- NameTemplate --------------------------------#

    @property
    def nameTemplate(self):
        """ (str): Le modèle de nommage des fichiers stockés.

        Cette chaine de caractère doit contenir un argument {id}.

        Raise:
            ValueError: La chaine de caractère ne contient pas un argument {id}.
        """
        return self._nameTemplate

    @nameTemplate.setter
    def nameTemplate(self, nameTemplate):
        if "{id}" not in nameTemplate:
            raise ValueError("nameTemplate must contain {id}.")
        else:
            self._nameTemplate = nameTemplate

    @property
    def files(self):
        """ Un dictionnaire {id: bytes} associant chaque identifiant au contenu
        du fichier.
        """
        return self._files

    def create(self):
        """ Créé le dossier """
        self.folder.mkdir(self.access.mode, True)
        self.updateFolder()

    def checkFolder(self) -> (bool, dict):
        """ Teste les permission dun dossier et de son contenu.
        Seul les fichiers respectant le nameTemplate sont évalués.

        Returns:
            bool: Si le contenu est valide;
            dict {Path: [AccessError]}: Un dictionnaire associant les Path avec
                les erreurs.
        """
        isValid = True
        error_dict = {}

        # Permissions du folder
        pathIsValid, path_error_dict = self.access.checkAccess(self.folder, 0)
        isValid &= pathIsValid
        if not pathIsValid:
            error_dict[self.folder] = path_error_dict

        # Permissions des fichiers
        for path in self.files.keysPath():
            pathIsValid, path_error_dict = self.access.checkAccess(path, 0)
            isValid &= pathIsValid
            if not pathIsValid:
                error_dict[path] = path_error_dict
        return (isValid, error_dict)

    def updateFolder(self):
        """ Met à jours les permissions du dossier et de son contenu.
        Seul les fichiers respectant le nameTemplate sont évalués.
        """
        self.access.updateAccess(self.folder, 0)
        for path in self.files.keysPath():
            self.access.updateAccess(path, 0)

    def __str__(self):
        return json.dumps(self.toJSon(self), indent=4)

    @staticmethod
    def fromJSon(fileStorageJSon):
        """ Initialise un FileStorage à partir d'un JSon

        Args:
            fileStorageJSon (str): Le FileStorage au format JSon.

        Returns:
            FileStorage: Le FileStorage
        """
        folder = fileStorageJSon["folder"]
        access = FileAccess.fromJSon(fileStorageJSon["access"])
        nameTemplate = fileStorageJSon["nameTemplate"]

        fileStorage = FileStorage(folder)
        fileStorage.access = access
        fileStorage.nameTemplate = nameTemplate
        return fileStorage

    @staticmethod
    def toJSon(fileStorage):
        """ Retourne un FileStorage au format JSon.

        Args:
            fileStorage (FileStorage): Le FileStorage.

        Returns:
            dict : Le FileStorage au format JSon.
        """
        fileStorage_dict = {}
        fileStorage_dict["folder"] = str(fileStorage.folder)
        fileStorage_dict["nameTemplate"] = fileStorage.nameTemplate
        fileStorage_dict["access"] = FileAccess.toJSon(fileStorage.access)

        return fileStorage_dict

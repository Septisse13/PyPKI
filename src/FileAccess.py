from pathlib import Path
import stat
import os
import pwd
import grp
import json

from enum import Enum

from enforce import runtime_validation
from overloading import overload
from typing import Any

class AccessError(Enum):
    OX = 1
    OW = 2
    OR = 4
    GX = 1*8
    GW = 2*8
    GR = 4*8
    UX = 1*8*8
    UW = 2*8*8
    UR = 4*8*8
    USER = 512
    GROUP = 1024

def checkMode(file_mode: int, access_mode: int) -> (bool, list):
    """ Retourne une liste d'AccessError correspondants aux bits différents entre
    file_mode et access_mode.

    Args:
        file_mode (int): Un mode.
        file_mode (int): Un autre mode.

    Returns:
        bool: Si les deux modes sont égaux.
        list<AccessError>: La liste des bits différents.
    """
    error_list = []
    error_int = file_mode ^ access_mode
    for i in range(0, 9):
        if error_int & 2**i:
            error_list += [AccessError(2**i)]
    return (not bool(error_list), error_list)

class FileAccess(object):

    def __init__(self, user, group, mode):
        """
        Args:
            user (pwd.struct_passwd/str): L'utilisateurs propriétaire du fichier.
            group (grp.struct_group/str): Le groupe propriétaire du fichier.
            mode (int): Les permissions.
        """
        self._user = pwd.getpwnam(user)
        self._group = grp.getgrnam(group)
        self._mode = mode

#-------------------- User ----------------------#
    @property
    def uid(self) -> int:
        """ (int): L'UID de l'utilisateurs propriétaire du fichier."""
        return self.user.pw_uid

    @property
    def user(self) -> pwd.struct_passwd:
        """ (pwd.struct_passwd): L'utilisateurs propriétaire du fichier. """
        return self._user

    @user.setter
    def user(self, user):
        if isinstance(user, str):
            self.user = pwd.getpwnam(user)
        elif isinstance(user, pwd.struct_passwd):
            self._user = user
        else:
            raise TypeError("User doit être du type pwd.struct_passwd")

#-------------------- Group ----------------------#
    @property
    def gid(self) -> int:
        """ (int): Le GID du groupe propriétaire du fichier."""
        return self.group.gr_gid

    @property
    def group(self) -> grp.struct_group:
        """ (grp.struct_group): Le groupe propriétaire du fichier."""
        return self._group

    @group.setter
    def group(self, group: grp.struct_group):
        if isinstance(group, str):
            self.group = grp.getgrnam(group)
        elif isinstance(group, grp.struct_group):
            self._group = group
        else:
            raise TypeError("Group doit être du type grp.struct_group")

#-------------------- Mode ----------------------#
    @property
    def dirMode(self) -> int:
        """ (int): Les permissions associées aux dossiers."""
        x_flags =  0o001 if self.mode & 0o004 else 0
        x_flags += 0o010 if self.mode & 0o040 else 0
        x_flags += 0o100 if self.mode & 0o400 else 0
        return self.mode | x_flags

    @property
    def mode(self) -> int:
        """ (int): Les permissions associées au fichier."""
        return self._mode

    @mode.setter
    def mode(self, mode: int):
        self._mode = int(mode)

    def __str__(self):
        return "{user},{group},{mode}".format(user=self.user,
                                              group=self.group,
                                              mode=oct(self.mode))

    def updateAccess(self, path, rec=None):
        """ Met à jour les droits des fichiers.

        Si path est un dossier, applique les permissions au dossier et à ces
        fils immédiats.

        Args:
            path (Path/str): Le chemin.
        """

        isValid, error_dict = self.checkAccess(path, rec)

        for path, error_list in error_dict.items():
            if set([AccessError.USER, AccessError.GROUP]).intersection(error_list):
                os.chown(str(path), self.uid, self.gid)
            if set([AccessError(2**i) for i in range(0,9)]).intersection(error_list):
                if path.is_dir():
                    path.chmod(mode=self.dirMode)
                else:
                    path.chmod(mode=self.mode)

    def checkAccess(self, path, rec=None) -> (bool, list):
        """ Teste les droits associés aux fichiers.

        Tous les dossiers ayant un droit de lecture doivent avoir un droit
        d'exécution.

        Args:
            path (Path/str): Le chemin
            rec (int): Le niveau de récursion. Si il n'est pas fourni, le niveau
                de récursion est considéré comme infini (255).

        Raises:
            ValueError: Si path n'existe pas

        Retuns:
            bool: Si les droits des fichiers correspondent."""

        # Normalisation de path
        if not path:
            raise ValueError("Le chemin doit exister")

        if isinstance(path, str):
            path = Path(path)

        if not path.exists():
            raise ValueError("Le chemin doit exister")

        # Normalisation de rec
        if rec not in range(-1,256):
            rec = 255

        error_dict = {}

        # Test du fichier pointé par path
        isValid = True

        if path.stat().st_uid != self.uid:
            error_dict[path] = [AccessError.USER]
            isValid = False

        if path.stat().st_gid != self.gid:
            if isValid:
                error_dict[path] = [AccessError.GROUP]
                isValid = False
            else:
                error_dict[path] += [AccessError.GROUP]

        #Sélection de la partie permission de st_mode
        file_mode = stat.S_IMODE(path.stat().st_mode) & 0o777

        # Récursion sur les sous-dossiers
        if path.is_dir():
            # Le droit r implite le droit x pour les dossiers
            isValidMode, error_list_mode = checkMode(file_mode, self.dirMode)
            if error_list_mode:
                if isValid:
                    error_dict[path] = error_list_mode
                    isValid = False
                else:
                    error_dict[path] += error_list_mode

            if rec > 0:
                for file in path.iterdir():
                    file_isValid, file_error_dict = self.checkAccess(file, rec-1)
                    error_dict = { **error_dict, **file_error_dict}
                    isValid &= file_isValid
        else:
            isValidMode, error_list_mode = checkMode(file_mode, self.mode)
            if not isValidMode:
                if isValid:
                    error_dict[path] = error_list_mode
                    isValid = False
                else:
                    error_dict[path] += error_list_mode

        return (isValid, error_dict)

    def __str__(self):
        return json.dumps(self.toJSon(self), indent=4)

    @staticmethod
    def fromJSon(fileAccessJSon):
        """ Initialise un FileAccess à partir d'un JSon

        Args:
            fileAccessJSon (str): Le FileAccess au format JSon.

        Returns:
            FileAccess: Le FileAccess
        """
        user = fileAccessJSon["user"]
        group = fileAccessJSon["group"]
        mode = int(fileAccessJSon["mode"], 8)

        fileAccess = FileAccess(user, group, mode)

        return fileAccess

    @staticmethod
    def toJSon(fileAccess):
        """ Retourne un FileAccess au format JSon

        Args:
            fileAccess (FileAccess): Le FileAccess

        Returns:
            dict : Le FileAccess au format JSon.
        """
        user = fileAccess.user.pw_name
        group = fileAccess.group.gr_name
        mode = oct(fileAccess.mode)

        fileAccess_dict = { "user":user, "group":group, "mode":mode}

        return fileAccess_dict

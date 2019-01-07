from FileStorage import FileStorage
import KeyPolicy
import FileAccess
import Key
import re

from pathlib import Path

def test_initFileStorage():
    keyAccess = FileAccess.FileAccess("septisse", "septisse", 0o750)

    keyStorage = FileStorage(Path("../test"))
    keyStorage.nameTemplate = "{id}-test.pem"
    keyStorage.access = keyAccess

    print(keyStorage.files.popitem())

    print(keyStorage.files)
    print(keyStorage.files.items())

test_initFileStorage()


#newKey = keyPolicy.generateKey()
#
#keyStorage.addKey(newKey.getPEM())
#
#print(keyStorage.getKey("CBA737"))

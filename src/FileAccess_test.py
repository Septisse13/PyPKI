from FileAccess import FileAccess, AccessError, checkMode
import pwd
import grp

def test_chekMode():
    print(checkMode(0o776, 0o477))

def test_initFileAccess():
    access = FileAccess("septisse", "septisse", 0o640)
    access.user = "root"
    access.group = "docker"
    print(access)

def test_ckeckAccess():
    access = FileAccess("septisse", "septisse", 0o644)
    check = access.checkAccess(".",1)
    print(check)

def test_updateAccess():
    access = FileAccess("septisse", "septisse", 0o644)
    check = access.updateAccess(".",1)
    print(check)

#print(AccessError.UR._value_)

test_ckeckAccess()

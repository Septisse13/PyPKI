import argparse
import sys

import asn1
import base64
import binascii
from pyasn1.type import univ
from pyasn1.codec.ber import encoder, decoder

from pathlib import Path
from Authority import Authority
from AuthoritySignKeyCli import AuthoritySignKeyCli
from PolicyCli import PolicyCli
from SubjectCli import SubjectCli

class AuthorityCli:

    commands = [
        "init"
        "renewKey"
    ]
    def __init__(self, argv):

        if Path(".authority").exists():
            self.localAuthority = Authority.fromJSon(Path(".authority").read_text())

        self._update = self.Callable(self.localAuthority)

        parser = argparse.ArgumentParser(
            description="Gestion d'une autorité de certification",
            usage='''pypki ca [<command>]''')
        parser.add_argument('command', help='Subcommand to run')
        # parse_args defaults to [1:] for args, but you need to
        # exclude the rest of the args too, or validation will fail
        args = parser.parse_args(argv[:1])
        if not hasattr(self, args.command):
            print("Unrecognized command")
            parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)(argv[1:])

    class Callable(object):
        def __init__(self, authority):
            self._authority = authority

        def __call__(self):
            with open(".authority", "w") as f:
                f.write(str(self._authority))
            print("Callable")

    def init(self):
        try:
            self.localAuthority.signKeyStorage.create()
            print("{folder} créé.".format(folder=self.localAuthority.signKeyStorage.folder))
        except FileExistsError as e:
            print(e)
        try:
            self.localAuthority.caCertStorage.create()
            print("{folder} créé.".format(folder=self.localAuthority.caCertStorage.folder))
        except FileExistsError as e:
            print(e)
        try:
            self.localAuthority.certStorage.create()
            print("{folder} créé.".format(folder=self.localAuthority.certStorage.folder))
        except FileExistsError as e:
            print(e)
        try:
            self.localAuthority.childTemplateStorage.create()
            print("{folder} créé.".format(folder=self.localAuthority.childTemplateStorage.folder))
        except FileExistsError as e:
            print(e)
        try:
            self.localAuthority.caCSRStorage.create()
            print("{folder} créé.".format(folder=self.localAuthority.caCSRStorage.folder))
        except FileExistsError as e:
            print(e)
        try:
            self.localAuthority.csrStorage.create()
            print("{folder} créé.".format(folder=self.localAuthority.csrStorage.folder))
        except FileExistsError as e:
            print(e)

    def signKey(self, argv):
        AuthoritySignKeyCli(argv, self.localAuthority, self._update)

    def sign(self, argv):
        SignCli(argv, self.localAuthority, self._update)

    def subject(self, argv):
        SubjectCli(argv, self.localAuthority.subject, self._update)

    def show(self, argv):
        print(self.localAuthority)

class CsrCli:
    def __init__(self, argv):
        if Path(".authority").exists():
            self.localAuthority = Authority.fromJSon(Path(".authority").read_text())
        parser = argparse.ArgumentParser(
            description="Gestion d'une autorité de certification",
            usage='''pypki ca [<command>]''')
        parser.add_argument('id', help='Subcommand to run')
        # parse_args defaults to [1:] for args, but you need to
        # exclude the rest of the args too, or validation will fail
        args = parser.parse_args(argv)
        if not hasattr(self, args.id):
            print("Unrecognized command")
            parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)(argv[1:])

    def list(self, argv):
        print(self.localAuthority.csrStorage.files.keys())

    def show(self, argv):
        parser = argparse.ArgumentParser(
            description="Gestion d'une autorité de certification",
            usage='''pypki ca [<command>]''')
        parser.add_argument('id', help='Subcommand to run')
        args = parser.parse_args(argv)

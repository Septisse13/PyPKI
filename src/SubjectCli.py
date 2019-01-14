import argparse

from pathlib import Path

from Authority import Authority
from Subject import Subject

class SubjectCli:

    def __init__(self, argv, subject, update):
        self._subject = subject
        self._update = update

        parser = argparse.ArgumentParser(
            description="Gestion d'une autorité de certification",
            usage='''pypki ca [<command>]''')
        parser.add_argument('command', help='Subcommand to run')
        args = parser.parse_args(argv[:1])
        if not hasattr(self, args.command):
            print("Unrecognized command")
            parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)(argv[1:])

    def show(self, argv):
        print(self._subject)

    def C(self, argv):
        self.country(argv)

    def country(self, argv):
        parser = argparse.ArgumentParser()
        parser.add_argument("--set","-s")
        args = parser.parse_args(argv)

        if args.set:
            self._subject.country = args.set
            self._update()
        print(self.localAuthority.subject.country)

    def ST(self, argv):
        self.state(argv)

    def state(self, argv):
        parser = argparse.ArgumentParser()
        parser.add_argument("--set","-s")
        args = parser.parse_args(argv)

        if args.set:
            self._subject.state = args.set
            self._update()
        print(self.localAuthority.subject.state)

    def L(self, argv):
        self.locality(argv)

    def locality(self, argv):
        parser = argparse.ArgumentParser()
        parser.add_argument("--set","-s")
        args = parser.parse_args(argv)

        if args.set:
            self._subject.locality = args.set
            self._update()
        print(self.localAuthority.subject.locality)

    def O(self, argv):
        self.organization(argv)

    def organization(self, argv):
        parser = argparse.ArgumentParser()
        parser.add_argument("--set","-s")
        args = parser.parse_args(argv)

        if args.set:
            self._subject.organization = args.set
            self._update()
        print(self.localAuthority.subject.organization)

    def OU(self, argv):
        self.organisationUnit(argv)

    def organisationUnit(self, argv):
        parser = argparse.ArgumentParser()
        parser.add_argument("--set","-s")
        args = parser.parse_args(argv)

        if args.set:
            self._subject.organisationUnit = args.set
            self._update()
        print(self.localAuthority.subject.organisationUnit)

    def CN(self, argv):
        self.commonName(argv)

    def commonName(self, argv):
        parser = argparse.ArgumentParser()
        parser.add_argument("--set","-s")
        args = parser.parse_args(argv)

        if args.set:
            self._subject.commonName = args.set
            self._update()
        print(self.localAuthority.subject.commonName)

import argparse

from Authority import Authority
from utils import Observer, Observable
from pathlib import Path

class PolicyCli:

    def __init__(self, argv, keyPolicy, update):
        self._keyPolicy = keyPolicy
        self._update = update

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

    def show(self, set):
        print(self._keyPolicy)

    def algorithm(self, argv):
        parser = argparse.ArgumentParser(
            description="Gestion d'une autorité de certification",
            usage='''pypki ca [<command>]''')
        parser.add_argument('--set', '-s', type=str, help='Subcommand to run')
        args = parser.parse_args(argv)
        if args.set:
            self._keyPolicy.algorithm = args.set
            self._update()
        print(self._keyPolicy.algorithm.name)

    def encryption(self, argv):
        parser = argparse.ArgumentParser(
            description="Gestion d'une autorité de certification",
            usage='''pypki ca [<command>]''')
        parser.add_argument('--set', '-s', type=str, help='Subcommand to run')
        args = parser.parse_args(argv)
        if args.set:
            self._keyPolicy.encryption = args.set
            self._update()
        print(self._keyPolicy.encryption)

    def duration(self, argv):
        parser = argparse.ArgumentParser(
            description="Gestion d'une autorité de certification",
            usage='''pypki ca [<command>]''')
        parser.add_argument('--set', '-s', type=str, help='Subcommand to run')
        args = parser.parse_args(argv)
        if args.set:
            self._keyPolicy.duration = args.set
            self._update()
        print(self._keyPolicy.duration)

    def check(self):
        parser = argparse.ArgumentParser(
            description="Gestion d'une autorité de certification",
            usage='''pypki ca [<command>]''')
        parser.add_argument('--key', '-k', type=str, help='Subcommand to run')
        args = parser.parse_args(argv)

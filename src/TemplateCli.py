import argparse

from pathlib import Path

from Authority import Authority
from SubjectCli import SubjectCli

class TemplateCli:

    def __init__(self, argv):
        if Path(".authority").exists():
            self.localAuthority = Authority.fromJSon(Path(".authority").read_text())
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

    def subject(self, argv):
        SubjectCli(self, argv)

    def duration(self, argv):
        parser = argparse.ArgumentParser(
            description="Gestion d'une autorité de certification",
            usage='''pypki ca [<command>]''')
        parser.add_argument('--set', '-s', type=str, help='Subcommand to run')
        args = parser.parse_args(argv)
        if args.set:
            self.localAuthority.signKeyPolicy.duration = args.set
            with open(".authority", "w") as f:
                f.write(str(self.localAuthority))
        print(self.localAuthority.signKeyPolicy.duration)

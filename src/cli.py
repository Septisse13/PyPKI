#!/usr/bin/env python

import argparse
import sys
from pathlib import Path

from Authority import Authority
from AuthorityCli import AuthorityCli

class PyPKICli(object):

    def __init__(self):
        if Path(".authority").exists():
            self.localAuthority = Authority.fromJSon(Path(".authority").read_text())
        parser = argparse.ArgumentParser(
            description='Pretends to be git',
            usage='''pypki <command> [<args>]''')
        parser.add_argument('command', help='Subcommand to run')
        # parse_args defaults to [1:] for args, but you need to
        # exclude the rest of the args too, or validation will fail
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print("Unrecognized command")
            parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name

        getattr(self, args.command)()


    def ca(self):
        parser = argparse.ArgumentParser(
            description='Record changes to the repository')
        # prefixing the argument with -- means it's optional
        parser.add_argument('command')
        # now that we're inside a subcommand, ignore the first
        # TWO argvs, ie the command (git) and the subcommand (commit)
        AuthorityCli(sys.argv[2:])


    def fetch(self):
        parser = argparse.ArgumentParser(
            description='Download objects and refs from another repository')
        # NOT prefixing the argument with -- means it's not optional
        parser.add_argument('repository')
        args = parser.parse_args(sys.argv[2:])
        print("Running git fetch, repository=%s" % args.repository)


if __name__ == '__main__':
    PyPKICli()

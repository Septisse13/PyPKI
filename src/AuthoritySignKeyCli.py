import argparse

from Authority import Authority
from PolicyCli import PolicyCli
from pathlib import Path

class AuthoritySignKeyCli:
    def __init__(self, argv, authority, update):

        self._authority = authority
        self._update = update

        parser = argparse.ArgumentParser(
            description="Gestion d'une autorité de certification",
            usage='''pypki ca signKey [<command>]''')
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

    def list(self, argv):
        print(self._authority.signKeyStorage.files)

    def delete(self, argv):
        parser = argparse.ArgumentParser(
            description="Gestion d'une autorité de certification",
            usage='''pypki ca signKey [<command>]''')
        parser.add_argument('id', help='Subcommand to run')
        # parse_args defaults to [1:] for args, but you need to
        # exclude the rest of the args too, or validation will fail
        args = parser.parse_args(argv[:1])

        if args.id not in self._authority.signKeyStorage.files.keys():
            print("Attention: la clé {id} n'existe pas.".format(id=args.id))
            return

        if args.id == self._authority.currentSignKeyId:
            print("Attention: la clé {id} est la clé de signature par défaut.")
            rep = input("Voulez-vous supprimer la clé [Y/n]")
            if rep != "Y":
                return

        del self._authority.signKeyStorage.files[args.id]
        print("La clé {id} a été supprimée.".format(id=args.id))

    def renew(self, argv):
        password = "".encode("ascii")
        if self._authority.signKeyPolicy.encryption != "none":
            password = input("Mot de passe:").encode("ascii")

        id = self._authority.renewSignKey(password)
        print("La clé {id} a été créée.".format(id=id))
        csr_id = self._authority.generateCaCSR(id, password)
        print("La requête de signaturte {id} a été créée.".format(id=csr_id))

    def id(self, argv):
        parser = argparse.ArgumentParser(
            description="Gestion d'une autorité de certification",
            usage='''pypki ca [<command>]''')
        parser.add_argument('--set', '-s', type=str, help='Subcommand to run')
        args = parser.parse_args(argv)
        if args.set:
            if args.set not in self._authority.signKeyStorage.files.keys():
                print("Attention: la clé {id} n'existe pas.".format(id=args.set))
                return

            self._authority.currentSignKeyId = args.set
            self._update()
        print("La clé {id} est la clé de signature par défaut.".format(
                                        id=self._authority.currentSignKeyId))
        #print(self._authority.currentSignKeyId)

    def show(self, argv):
        id = self._authority.currentSignKeyId
        pem = self._authority.signKeyStorage.files[id].decode().splitlines()
        pem = read_pem(pem)
        tt = decoder.decode(pem)

        OID_CIPHER ={
                "2.16.840.1.101.3.4.1.2": "aes-128-cbc",
                "2.16.840.1.101.3.4.1.22": "aes-192-cbc",
                "2.16.840.1.101.3.4.1.42": "aes-256-cbc"
                #b"camellia-128-cbc",
                #b"camellia-192-cbc",
                #b"camellia-256-cbc"
        }

        encryption = "none"
        if tt[0][0]:
            if str(tt[0][0][0]) == "1.2.840.113549.1.5.13":
                if str(tt[0][0][1][1][0]) in OID_CIPHER:
                    encryption = OID_CIPHER[str(tt[0][0][1][1][0])]

        print(tt[0][0][1])

        print("id: {id}".format(id=id))
        print("encryption: {encryption}".format(encryption=encryption))
        #print("cipher: {cipher}".format(cipher=cipher))


    def policy(self, argv):
        PolicyCli(argv, self._authority.signKeyPolicy, self._update)

def read_pem(input_file):
    """Read PEM formatted input."""
    data = []
    state = 0
    for line in input_file:
        #print(line)
        if state == 0:
            if line.startswith('-----BEGIN' ):
                state = 1
        elif state == 1:
            if line.startswith('-----END'):
                state = 2
            else:
                data.append(line)
        elif state == 2:
            break
    if state != 2:
        raise ValueError('No PEM encoded input found')
    data = ''.join(data)
    return base64.b64decode(data)

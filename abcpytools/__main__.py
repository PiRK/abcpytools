"""Main entry point for the package"""
import argparse
import json
import sys

from abcpytools.proof import PublicKey, ProofBuilder


def buildavalancheproof(argv):
    parser = argparse.ArgumentParser(
            description="Build a proof for avalanche's sybil resistance")

    parser.add_argument(
        "sequence", type=int, help="The proof's sequence")
    parser.add_argument(
        "expiration", type=int,
        help="A timestamp indicating when the proof expires")
    parser.add_argument(
        "master", type=str, help="The master public key")
    parser.add_argument(
        "stakes", type=json.loads,
        help="The stakes to be signed and associated private keys, as a json "
             "list of objects. A stake is defined by the following attributes:"
             " 'txid' the transaction id, a 32 character hexadecimal string;"
             " 'vout' the utxo's output index;"
             " 'amount' the utxo's amount, in bitcoins;"
             " 'height' the height of the block containing the transaction;"
             " 'privatekey' the private key unlocking the output, in WIF format.")

    args = parser.parse_args(argv)
    pubkey = PublicKey(bytes.fromhex(args.master))
    proofbuilder = ProofBuilder(sequence=args.sequence,
                                expiration_time=args.expiration,
                                master=pubkey)
    for utxo in args.stakes:
        proofbuilder.add_utxo(
            txid=utxo['txid'],
            vout=utxo['vout'],
            value=utxo['amount'],
            height=utxo['height'],
            wif_privkey=utxo['privatekey'])
    proof = proofbuilder.build()
    print(proof.serialize().hex())


def main():
    parser = argparse.ArgumentParser(
            description="Bitcoin toolkit")
    commands = ["buildavalancheproof"]
    parser.add_argument(
        'command',
        help=f'Command to execute.\nAvailable commands: {", ".join(commands)}')
    args = parser.parse_args(sys.argv[1:2])

    if args.command == "buildavalancheproof":
        buildavalancheproof(sys.argv[2:])
    else:
        print(f"Unknown command {args.command}")
        sys.exit(1)


if __name__ == '__main__':
    main()
    sys.exit(0)

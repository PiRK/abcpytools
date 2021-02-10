# This is a sample Python script.
from abcpytools.proof import PublicKey, ProofBuilder


def main():
    pubkey = PublicKey(bytes.fromhex(
        "030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a744"))
    proofbuilder = ProofBuilder(sequence=42,
                                expiration_time=1699999999,
                                master=pubkey)
    proofbuilder.add_utxo(
        txid="0adfaf4927b0d5482a3f01ac508274d6a418fbc60f3e45213870435f3f8a28a8",
        vout=0,
        value=0.001,
        height=665883,
        wif_privkey="...")
    proof = proofbuilder.build()
    hex_str = proof.serialize().hex()

    expected = "2a00000000000000fff053650000000021030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a74401a8288a3f5f43703821453e0fc6fb18a4d6748250ac013f2a48d5b02749afdf0a00000000a086010000000000365214002102000be4ace4549fda67998ddf2854051878901f31aa9392bfaf1af22015724a36c0df0e9f7e21de384cbff3bde497b9228ecd23412a2210212d1b4271f35794e3b76236faa60e7fa0b960c247f4a9e36d538cb92f9e57900c3af4b020b411a668"
    #           ^ sequence      ^ exp_time      ^ master pubkey                                                     ^ ^ txid                                                          ^ vout  ^ amount        ^ h     ^ pubkey                                                            ^ sig

    assert hex_str == expected, "building the proof failed"
    print("Proof successfully generated")


if __name__ == '__main__':
    main()

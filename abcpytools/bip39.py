"""
This module deals with mnemonic sentences for the generation of deterministic
wallets, as specified in BIP 39.

https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

It uses Trezor's python-mnemonic library, which is the reference implementation
according to the above link.
http://github.com/trezor/python-mnemonic
"""

import mnemonic


def is_bip39_seed(seed: str) -> bool:
    """Checks if `seed` is a valid BIP39 seed phrase (passes wordlist AND
    checksum tests)."""
    try:
        language = mnemonic.Mnemonic.detect_language(seed)
    except mnemonic.mnemonic.ConfigurationError:
        return False
    mnemo = mnemonic.Mnemonic(language)
    return mnemo.check(seed)


def bip39_mnemonic_to_seed(words: str, passphrase: str = "") -> bytes:
    """Return binary seed for the specified mnemonic phrase and
    optional password.

    This seed can be used to generate deterministic wallets BIP-0032
    """
    language = mnemonic.Mnemonic.detect_language(words)
    return mnemonic.Mnemonic(language).to_seed(words, passphrase)


def generate_bip39_words(language: str = 'english',
                         strength: int = 128) -> str:
    """Return a new 12 words BIP39 seed phrase.

    :param language: Language used for the seed phrase.
        Must be one of the available languages in
        https://github.com/trezor/python-mnemonic/tree/master/mnemonic/wordlist
        Since the vast majority of BIP39 wallets supports only the English
        wordlist, it is strongly discouraged to use non-English wordlists
        for generating the mnemonic sentences.
    :param strength: Number of entropy bits. This must be a multiple of 32
        between 128 and 256. Possible values: 128 (12 words), 160 (15 words),
        192 (18 words), 224 (21 words) or 256 (24 words).
    """
    return mnemonic.Mnemonic(language).generate(strength=strength)


if __name__ == '__main__':
    words = generate_bip39_words()
    print(f"Mnemonic phrase:\n\t{words}")
    print(f"Binary seed:\n\t{bip39_mnemonic_to_seed(words).hex()}")
    print(f"Binary seed with password:\n\t{bip39_mnemonic_to_seed(words, 'pwd').hex()}")

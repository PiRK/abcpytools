"""
This module deals with mnemonic sentences for the generation of deterministic
wallets, as specified in BIP 39.
https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

It uses Trezor's python-mnemonic library, which is the reference implementation
according to the above link.
http://github.com/trezor/python-mnemonic
"""

import mnemonic


def is_bip39_seed(seed: str, language: str = None) -> bool:
    """Checks if `seed` is a valid BIP39 seed phrase (passes wordlist AND
    checksum tests).

    If no language is specified, this function tries to detect it based on
    the first word.
    Note that this may fail because some languages share words (e.g.
    'million' exists both in the french and english word list).

    :param seed: String containing a list of words separated by a single
        whitespace.
    :param language: Language used for the seed phrase.
        Must be one of the available languages in
        https://github.com/trezor/python-mnemonic/tree/master/mnemonic/wordlist
    """
    if language is None:
        try:
            language = mnemonic.Mnemonic.detect_language(seed)
        except mnemonic.mnemonic.ConfigurationError:
            return False
    mnemo = mnemonic.Mnemonic(language)
    return mnemo.check(seed)


def bip39_mnemonic_to_seed(words: str, passphrase: str = "",
                           language: str = None) -> bytes:
    """Return binary seed for the specified mnemonic phrase and
    optional password.

    This seed can be used to generate deterministic wallets BIP-0032

    If no language is specified, this function tries to detect it based on
    the first word.
    Note that this may fail because some languages share words (e.g.
    'million' exists both in the french and english word list).

    :param words: String containing a list of words separated by a single
        whitespace.
    :param passphrase: Optional password.
    :param language: Language used for the seed phrase.
        Must be one of the available languages in
        https://github.com/trezor/python-mnemonic/tree/master/mnemonic/wordlist
    """
    if language is None:
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

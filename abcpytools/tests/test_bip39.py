import unittest
from .. import bip39

mnemonic_phrase = "flip medal retreat apple dune eye clerk letter harbor physical mask trash"


class TestBip39(unittest.TestCase):
    def test_is_bip39_seed(self):
        self.assertTrue(bip39.is_bip39_seed(mnemonic_phrase))

    def test_bip39_mnemonic_to_seed(self):
        self.assertEqual(
            bip39.bip39_mnemonic_to_seed(mnemonic_phrase).hex(),
            "250fcf2279b810dab85bd6fd562fad45c2697930ce8783f7a53499506da141a9"
            "aeaa767a8a5315f8cbbf2c60e164c52fde8360a774e8ce4220a0eab1e3e9468d"
        )
        self.assertEqual(
            bip39.bip39_mnemonic_to_seed(mnemonic_phrase, "pwd").hex(),
            "fe48aeb5ef3f2ce18bf963174fb4c316f08effd317827d6c1c19312e1ed2729c"
            "8787c68c7634de88ad4fface2486c92e6c0d72301aae1672e7adf48825a5ef5c"
        )

    def test_generate(self):
        strengths = [128, 160, 192, 224, 256]
        languages = ['english', 'french', 'italian', 'japanese', 'korean',
                     'spanish', 'chinese_simplified', "chinese_traditional"]

        for strength in strengths:
            for language in languages:
                words = bip39.generate_bip39_words(language, strength)
                expected_length = strength // 32 * 3
                self.assertEqual(len(words.split()), expected_length)

                # The language needs to be specified, because some languages
                # share identical words, and incorrect auto detection leads
                # to intermittent test failures.
                self.assertTrue(bip39.is_bip39_seed(words, language), words)


if __name__ == '__main__':
    unittest.main()

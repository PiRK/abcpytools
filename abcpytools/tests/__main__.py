"""This script runs the entire test suite.

Each test module must define a `suite()` function returning all tests.

Run it with `python -m pkgname.tests`
"""

import unittest

loader = unittest.TestLoader()
tests = loader.discover('.')
testRunner = unittest.runner.TextTestRunner()
testRunner.run(tests)

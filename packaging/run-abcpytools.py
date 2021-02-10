# coding: utf-8
"""Runner script used for pyinstaller

To generate a binary package with pyinstaller, do the following steps:

 - install abcpytools with `pip install . --user`
 - `cd packaging; pyinstaller run-abcpytools.py -n abcpytools --onefile`

The executable file is created in `packaging/dist/`
"""
import sys

# Import here for static analysis to work
import abcpytools
from abcpytools.__main__ import main

if __name__ == '__main__':
    status = main()
    sys.exit(status)

from setuptools import setup, find_packages

setup(
    name="abcpytools",
    version="1.0.0",
    # url="",
    author="PiRK",
    description="Python toolkit for Bitcoin ABC.",
    packages=find_packages(),
    install_requires=["ecdsa", "mnemonic", "pyaes"],
    entry_points={"gui_scripts": ["abcpytools = abcpytools.__main__:main"]},
)

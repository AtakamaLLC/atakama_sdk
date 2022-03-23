"""Atakama sdk."""

from os import path
from setuptools import setup


def long_description():
    """Extract description from readme."""
    this_directory = path.abspath(path.dirname(__file__))
    with open(path.join(this_directory, "README.md")) as readme_f:
        contents = readme_f.read()
        return contents


setup(
    name="atakama",
    version="1.7.1",
    description="Atakama sdk",
    packages=["atakama"],
    long_description=long_description(),
    long_description_content_type="text/markdown",
    setup_requires=["wheel"],
    install_requires=["oscrypto", "certvalidator"],
    entry_points={"console_scripts": "atakama-pkg=atakama.packager:main"},
)

from setuptools import find_packages, setup

VERSION = "0.6.2"

setup(
    name="async-ingresse-access-control",
    version=VERSION,
    description="Ingresse Access Control SDK",
    long_description="Ingresse Access Control python SDK library to use the Access Control micro-service.",
    url="https://github.com/ingresse/async-access-control-python-sdk",
    author="Ingresse",
    author_email="marcus.campos@ingresse.com",
    license="BSD",
    packages=find_packages(),
    install_requires=["requests"],
    download_url="https://github.com/ingresse/async-access-control-python-sdk/tarball/%r".format(
        VERSION
    ),
    keywords="async ingresse access control sdk",
)

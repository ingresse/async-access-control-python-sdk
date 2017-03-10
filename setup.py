import codecs
import re
import os

from setuptools import setup, find_packages


def read(*parts):
    path = os.path.join(os.path.dirname(__file__), *parts)

    with codecs.open(path, encoding='utf-8') as fobj:
        return fobj.read()

def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^VERSION = ['\"]([^'\"]*)['\"]", version_file, re.M)

    if version_match:
        return version_match.group(1)

    raise RuntimeError('Unable to find version string.')

VERSION = find_version('ingresse_acl', 'sdk.py')

setup(
    name='ingresse-access-control',
    version=VERSION,
    description='Ingresse Access Control SDK',
    long_description='Ingresse Access Control python SDK library to use the Access Control micro-service.',
    url='https://github.com/ingresse/access-control-python-sdk',
    author='Ingresse',
    author_email='carlos.corcioli@ingresse.com',
    license='BSD',
    packages=find_packages(),
    install_requires=['requests'],
    download_url='https://github.com/ingresse/access-control-python-sdk/tarball/%r'.format(VERSION),
    keywords='ingresse access control sdk',
)

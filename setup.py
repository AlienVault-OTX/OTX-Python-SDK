#!/usr/bin/env python

# from distutils.core import setup
from setuptools import setup

setup(
    name='OTXv2',
    version='1.5.12',
    description='AlienVault OTX API',
    author='AlienVault Team',
    author_email='otx@alienvault.com',
    url='https://github.com/AlienVault-Labs/OTX-Python-SDK',
    download_url='https://github.com/AlienVault-Labs/OTX-Python-SDK/tarball/1.5.12',
    py_modules=['OTXv2', 'IndicatorTypes','patch_pulse'],
    install_requires=['requests', 'python-dateutil', 'pytz']
)

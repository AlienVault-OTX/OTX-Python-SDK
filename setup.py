#!/usr/bin/env python

from distutils.core import setup

setup(name='OTXv2',
      version='1.1',
      description='AlienVault OTX API',
      author='AlienVault Team',
      author_email='otx@alienvault.com',
      url='https://github.com/AlienVault-Labs/OTX-Python-SDK',
      py_modules=['OTXv2','IndicatorTypes'],
      install_requires=['simplejson']
      )

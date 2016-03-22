# -*- coding: utf-8 -*-

from setuptools import setup

setup(name='eblob_kit',
      version='0.0.6',
      author='Kirill Smorodinnikov',
      author_email='shaitkir@gmail.com',
      py_modules=['eblob_kit'],
      install_requires=['Click', 'pyhash'],
      entry_points='''
          [console_scripts]
          eblob_kit=eblob_kit:main
      ''')

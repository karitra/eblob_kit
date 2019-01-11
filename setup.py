# -*- coding: utf-8 -*-

from setuptools import setup

setup(name='eblob_kit',
      version='0.0.27',
      author='Kirill Smorodinnikov',
      author_email='shaitkir@gmail.com',
      py_modules=['eblob_kit'],
      install_requires=['Click', 'pyhash'],
      setup_requires=[
        'pytest-runner==2.9',
        'setuptools_scm<=1.9',
      ],
      tests_require=['pytest', 'pytest-mock'],
      entry_points='''
          [console_scripts]
          eblob_kit=eblob_kit:main
      ''')

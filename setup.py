# -*- coding: utf-8 -*-

import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest

        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


setup(name='eblob_kit',
      version='0.1.6',
      author='Kirill Smorodinnikov',
      author_email='shaitkir@gmail.com',
      py_modules=['eblob_kit'],
      install_requires=['Click', 'pyhash'],
      tests_require=['pytest', 'pytest-mock'],
      test_suite='tests',
      cmdclass={
        "test": PyTest,
      },
      entry_points='''
          [console_scripts]
          eblob_kit=eblob_kit:main
      ''')

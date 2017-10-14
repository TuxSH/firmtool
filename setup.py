#!/usr/bin/env python

from setuptools import setup

import os
import sys

if sys.version_info < (2,7):
    sys.exit('Sorry, Python < 2.7 is not supported')
elif sys.version_info[0] == 3 and sys.version_info[1] < 2:
    sys.exit('Sorry, Python 3.0 and 3.1 are not supported')

#https://pythonhosted.org/an_example_pypi_project/setuptools.html
# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name='firmtool',
    version='1.3',
    description='Parses, extracts, and builds 3DS firmware files',
    license='BSD',
    keywords='3DS firmware parse extract build',
    author='TuxSH',
    author_email='tuxsh@sfr.fr',
    long_description=read('README.md'),
    classifiers=[
        "Topic :: Utilities",
        "License :: OSI Approved :: BSD License",
    ],
    install_requires=['cryptography'],
    packages=['firmtool'],
    entry_points={ "console_scripts": [ "firmtool=firmtool.__main__:main" ] }
)

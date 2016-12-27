#!/usr/bin/env python
#-*- coding: utf-8 -*-

import os
import pip
import re
from setuptools import find_packages, setup

from tor2web import __version__

install_requires = [str(r.req) for r in pip.req.parse_requirements('requirements.txt',
                                                                   session=pip.download.PipSession())]

setup(
    name="tor2web",
    version=__version__,
    author="Random GlobaLeaks developers",
    author_email = "info@globaleaks.org",
    url="https://tor2web.org/",
    packages=find_packages(exclude=['*.tests', '*.tests.*']),
    scripts=["bin/tor2web"],
    install_requires=install_requires
)

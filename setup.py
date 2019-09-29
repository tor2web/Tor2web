#!/usr/bin/env python
#-*- coding: utf-8 -*-

import os
import re
from setuptools import find_packages, setup

from tor2web import __version__

setup(
    name="tor2web",
    version=__version__,
    author="Random GlobaLeaks developers",
    author_email = "info@globaleaks.org",
    url="https://tor2web.org/",
    packages=find_packages(exclude=['*.tests', '*.tests.*']),
    scripts=["bin/tor2web"]
)

#!/usr/bin/env python
#-*- coding: utf-8 -*-

import os
import re
from setuptools import setup

from tor2web import __version__

def get_requires():
    with open('requirements.txt') as f:
        requires = f.readlines()
        return requires

def list_files(path):
    result = []
    for f in os.listdir(path):
        result.append(os.path.join(path, f))

    return result

data_files = [
    ('/etc', [
    os.path.join('data', 'tor2web.conf.example'),
    ]),
    ('/usr/share/tor2web/lists',
    list_files(os.path.join('data', 'lists'))),
    ('/usr/share/tor2web/static',
    list_files(os.path.join('data', 'static'))),
    ('/usr/share/tor2web/templates',
    list_files(os.path.join('data', 'templates')))
]

setup(
    name="tor2web",
    version=__version__,
    author="Random GlobaLeaks developers",
    author_email = "info@globaleaks.org",
    url="https://tor2web.org/",
    packages=["tor2web", "tor2web.utils"],
    scripts=["bin/tor2web"],
    data_files=data_files,
    install_requires=get_requires()
)

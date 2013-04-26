#!/usr/bin/env python
#-*- coding: utf-8 -*-

from setuptools import setup

data_files = []

requires = [
"twisted (==12.3.0)",
"zope.interface (>=4.0.0)",
"pyOpenSSL"
]

setup(
    name="tor2web",
    version="0.3",
    author="Random GlobaLeaks developers",
    author_email = "info@globaleaks.org",
    url="https://tor2web.org/",
    packages=["tor2web", "tor2web.utils"],
    data_files=data_files,
    requires=requires
)

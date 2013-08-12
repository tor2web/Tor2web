#!/usr/bin/env python
#-*- coding: utf-8 -*-

import os
import re
from setuptools import setup

def pip_to_requirements(s):
    """
    Change a PIP-style requirements.txt string into one suitable for setup.py
    """

    m = re.match('(.*)([>=]=[.0-9]*).*', s)
    if m:
        return '%s (%s)' % (m.group(1), m.group(2))
    return s.strip()

def get_requires():
    with open('requirements.txt') as f:
        requires = f.readlines()
        return requires

data_files = [

    ('/opt/tor2web/certs', [
    ]),
    ('/etc', [
    os.path.join('data', 'tor2web.conf.example'),
    ]),
    ('/opt/tor2web/lists', [
    os.path.join('data', 'lists', 'blocked_ua.txt'),
    ]),
    ('/opt/tor2web/logs', [
    ]),
    ('/opt/tor2web/static', [
    os.path.join('data', 'static', 'robots.txt'),
    os.path.join('data', 'static', 'index.html'),
    os.path.join('data', 'static', 'tor2web.css'),
    os.path.join('data', 'static', 'tor2web.js'),
    os.path.join('data', 'static', 'tor2web.png'),
    os.path.join('data', 'static', 'tor2web-big.png'),
    os.path.join('data', 'static', 'tor2web-small.png'),
    os.path.join('data', 'static', 'tos.html'),
    ]),
    ('/opt/tor2web/templates', [
    os.path.join('data', 'templates', 'banner.tpl'),
    os.path.join('data', 'templates', 'error_blocked_ua.tpl'),
    os.path.join('data', 'templates', 'error_generic.tpl'),
    os.path.join('data', 'templates', 'error_hs_completely_blocked.tpl'),
    os.path.join('data', 'templates', 'error_hs_specific_page_blocked.tpl'),
    os.path.join('data', 'templates', 'error_invalid_hostname.tpl'),
    os.path.join('data', 'templates', 'error_sock_generic.tpl'),
    os.path.join('data', 'templates', 'error_sock_hs_not_found.tpl'),
    os.path.join('data', 'templates', 'error_sock_hs_not_reachable.tpl'),
    ]),
]

setup(
    name="tor2web",
    version="3.0.14",
    author="Random GlobaLeaks developers",
    author_email = "info@globaleaks.org",
    url="https://tor2web.org/",
    packages=["tor2web", "tor2web.utils"],
    scripts=["bin/tor2web"],
    data_files=data_files,
    install_requires=get_requires()
)

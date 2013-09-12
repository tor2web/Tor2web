#!/usr/bin/env python
#-*- coding: utf-8 -*-

import os
import re
from setuptools import setup

def get_requires():
    with open('requirements.txt') as f:
        requires = f.readlines()
        return requires

data_files = [
    ('/etc', [
    os.path.join('data', 'tor2web.conf.example'),
    ]),
    ('/usr/share/tor2web/lists', [
    os.path.join('data', 'lists', 'blocked_ua.txt'),
    ]),
    ('/usr/share/tor2web/static', [
    os.path.join('data', 'static', 'robots.txt'),
    os.path.join('data', 'static', 'index.html'),
    os.path.join('data', 'static', 'tor2web.css'),
    os.path.join('data', 'static', 'tor2web.js'),
    os.path.join('data', 'static', 'tor2web.png'),
    os.path.join('data', 'static', 'tor2web-big.png'),
    os.path.join('data', 'static', 'tor2web-small.png'),
    os.path.join('data', 'static', 'tos.html'),
    os.path.join('data', 'static', 'decoy.html'),
    ]),
    ('/usr/share/tor2web/templates', [
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
    version="3.0.64",
    author="Random GlobaLeaks developers",
    author_email = "info@globaleaks.org",
    url="https://tor2web.org/",
    packages=["tor2web", "tor2web.utils"],
    scripts=["bin/tor2web", "bin/tor2web-worker"],
    data_files=data_files,
    install_requires=get_requires()
)

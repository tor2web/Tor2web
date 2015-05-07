"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: HostMap util

.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

import re

class HostsMap(object):
    """
    simple object that read a simple /etc/hosts like file
    mapping hostnames to onion addresses
    """
    def __init__(self, path):
        self.hosts = {}
        self.read(path)

    def read(self, path):
        """Read the hosts file at the given location and parse the contents"""
        # regexp to match lines "host onion"
        # lines starting with comments are also ignored
        try:
            hostmapline = re.compile("[^ #][^ ]+ [a-zA-Z0-9]{16}\.onion")
            with open(path, 'r') as hosts_file:
                for line in hosts_file.read().split('\n'):
                    if hostmapline.match(line):
                        parts = re.split('\s+', line)
                        host = parts[0]
                        onion = parts[1]
                        self.hosts[host] = onion
        except Exception:
            pass

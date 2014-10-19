"""
    Tor2web
    Copyright (C) 2014 Hermes No Profit Association - GlobaLeaks Project

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

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
            hostmapline = re.compile("[^ #]{1}[^ ]+ [a-zA-Z0-9]{16}\.onion")
            with open(path, 'r') as hosts_file:
                for line in hosts_file.read().split('\n'):
                    if hostmapline.match(line):
                        print line
                        parts = re.split('\s+', line)
                        host = parts[0]
                        onion = parts[1]
                        self.hosts[host] = onion
        except:
            pass

"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: Lists utils

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

import re
from collections import OrderedDict

from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.web.client import Agent, readBody


class LimitedSizeDict(OrderedDict):
    def __init__(self, *args, **kwds):
        self.size_limit = kwds.pop("size_limit", None)
        OrderedDict.__init__(self, *args, **kwds)
        self._check_size_limit()

    def __setitem__(self, key, value):
        if key in self:
            del self[key]
        OrderedDict.__setitem__(self, key, value)
        self._check_size_limit()

    def _check_size_limit(self):
        if self.size_limit is not None:
            while len(self) > self.size_limit:
                self.popitem(last=False)


def getPage(url):
    return Agent(reactor).request(b'GET', url).addCallback(readBody)


class List(set):
    def __init__(self, filename, url='', mode='MERGE', refreshPeriod=0):
        set.__init__(self)
        self.filename = filename
        self.url = url
        self.mode = mode

        self.load()

        if url != '' and refreshPeriod != 0:
            self.lc = LoopingCall(self.update)
            self.lc.start(refreshPeriod)

    def load(self):
        """
        Load the list from the specified file.
        """
        self.clear()

        # simple touch to create non existent files
        try:
            open(self.filename, 'a').close()
        except Exception:
            pass

        try:
            with open(self.filename, 'r') as fh:
                for l in fh.readlines():
                    self.add(re.split("#", l)[0].rstrip("[ , \n,\t]"))
        except Exception:
            pass

    def dump(self):
        """
        Dump the list to the specified file.
        """
        try:
            with open(self.filename, 'w') as fh:
                for l in self:
                    fh.write(l + "\n")
        except Exception:
            pass

    def handleData(self, data):
        if self.mode == 'REPLACE':
            self.clear()

        for elem in data.split('\n'):
            if elem != '':
                self.add(elem)

    def processData(self, data):
        try:
            if len(data) != 0:
                self.handleData(data)
                self.dump()
        except Exception:
            pass

    def update(self):
        pageFetchedDeferred = getPage(self.url.encode('utf-8'))
        pageFetchedDeferred.addCallback(self.processData)
        return pageFetchedDeferred


class TorExitNodeList(List):
    def handleData(self, data):
        if self.mode == 'REPLACE':
            self.clear()

        for ip in re.findall( b'ExitAddress ([^ ]*) ', data):
            self.add(ip)

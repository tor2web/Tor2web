"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: Stats routines

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-


import json
from datetime import date, datetime, timedelta

from twisted.internet import reactor
from twisted.internet.task import deferLater


class T2WStats(dict):
    def __init__(self):
        dict.__init__(self)
        self.yesterday_stats = ''

        self.update_stats()

    def update(self, key):
        if key not in self:
            self[key] = 0
        self[key] += 1

    def update_stats(self, run_again=True):
        yesterday = date.today() - timedelta(1)
        hidden_services = list()
        for k in self:
            hidden_services.append(({'id': k, 'access_count': self[k]}))

        self.yesterday_stats = json.dumps({'date': yesterday.strftime('%Y-%m-%d'),
                                           'hidden_services': hidden_services})
        self.clear()

        next_time = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) + \
                    timedelta(days=1)
        next_delta = (next_time - datetime.now()).total_seconds()
        deferLater(reactor, next_delta, self.update_stats)

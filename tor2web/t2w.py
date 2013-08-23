"""
    Tor2web
    Copyright (C) 2012 Hermes No Profit Association - GlobaLeaks Project

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
   :synopsis: [GLOBALEAKS_MODULE_DESCRIPTION]

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

import signal
import atexit

import os
import prctl
import re
import sys
import random
import socket
import hashlib

from twisted.internet import reactor, protocol, defer
from twisted.application import service, internet
from twisted.python import log, logfile, syslog
from twisted.python.filepath import FilePath
from twisted.spread import pb

from tor2web.utils.daemon import T2WDaemon
from tor2web.utils.config import config
from tor2web.utils.lists import List, TorExitNodeList
from tor2web.utils.mail import MailException
from tor2web.utils.misc import listenTCPonExistingFD, t2w_file_path, verify_onion
from tor2web.utils.stats import T2WStats

class T2WRPCServer(pb.Root):
    def __init__(self, config):
        self.config = config     
        self.stats = T2WStats()

        if config.logreqs:
            self.logfile_access = logfile.DailyLogFile.fromFullPath(os.path.join(config.datadir, 'logs', 'access.log'))
        else:
            self.logfile_access = log.NullFile

        if config.debugmode:
            self.logfile_debug = logfile.DailyLogFile.fromFullPath(os.path.join(config.datadir, 'logs', 'debug.log'))
        else:
            self.logfile_debug = log.NullFile

        self.load_lists()
    
    def load_lists(self):
        self.access_list = []
        if config.mode == "TRANSLATION":
            pass

        elif config.mode == "WHITELIST":
            self.access_list = List(t2w_file_path(config.datadir, 'lists/whitelist.txt'))
        
        elif config.mode == "BLACKLIST":
            self.access_list = List(t2w_file_path(config.datadir, 'lists/blocklist_hashed.txt'),
                                    config.automatic_blocklist_updates_source,
                                    config.automatic_blocklist_updates_refresh)

            # clear local cleartext list
            # (load -> hash -> clear feature; for security reasons)
            self.blocklist_cleartext = List(t2w_file_path(config.datadir, 'lists/blocklist_cleartext.txt'))
            for i in self.blocklist_cleartext:
                self.access_list.add(hashlib.md5(i).hexdigest())

            self.access_list.dump()

            self.blocklist_cleartext.clear()
            self.blocklist_cleartext.dump()

        self.blocked_ua = []
        if config.blockcrawl:
            tmp = List(t2w_file_path(config.datadir, 'lists/blocked_ua.txt'))
            for ua in tmp:
                self.blocked_ua.append(ua.lower())

        # Load Exit Nodes list with the refresh rate configured  in config file
        self.TorExitNodes = TorExitNodeList(os.path.join(config.datadir, 'lists', 'exitnodelist.txt'),
                                            "https://onionoo.torproject.org/summary?type=relay",
                                            config.exit_node_list_refresh)

    def remote_get_config(self):
        return self.config.__dict__

    def remote_check_blocked_ua(self, check):
        check = check.lower()
        for ua in self.blocked_ua:
            if re.match(ua, check):
                return True
        return False

    def remote_check_access(self, check):
        if check in self.access_list:
            return True
        return False

    def remote_check_tor(self, check):
        if check in self.TorExitNodes:
            return True
        return False

    def remote_update_stats(self, onion):
        self.stats.update(onion)

    def remote_get_yesterday_stats(self):
        return self.yesterday_stats

    def remote_log_access(self, line):
        self.logfile_access.write(line)

    def remote_log_debug(self, line):
        self.logfile_debug.write(str(line))
        self.logfile_debug.write("\n")
 
def spawnT2W(sockets_https, sockets_http):
    childFDs = {}
    childFDs[0] = 0
    childFDs[1] = 1
    childFDs[2] = 2

    fds_https = ''
    fds_http = ''

    for i in range(len(sockets_https)):
        if i != 0:
            fds_https += ','
        childFDs[sockets_https[i].fileno()] = sockets_https[i].fileno()
        fds_https += str(sockets_https[i].fileno())
        
    for i in range(len(sockets_http)):
        if i != 0:
            fds_http += ','

        childFDs[sockets_http[i].fileno()] = sockets_http[i].fileno()            
        fds_http += str(sockets_http[i].fileno())

    subprocess = reactor.spawnProcess(T2WPP(sockets_https, sockets_http),
                                      "tor2web-worker",
                                      ["tor2web-worker",
                                       fds_https,
                                       fds_http],
                                      childFDs=childFDs)
    return subprocess


class T2WPP(protocol.ProcessProtocol):
    def __init__(self, sockets_https, sockets_http):
        self.sockets_https = sockets_https
        self.sockets_http = sockets_http

    def connectionMade(self):
        self.pid = self.transport.pid

    def processExited(self, reason):
        for x in range(len(subprocesses)):
            if subprocesses[x] == self.pid:
                del subprocesses[x]
                break

        if not quitting:
            subprocess = spawnT2W(self.sockets_https, self.sockets_http)
            subprocesses.append(subprocess.pid)

        if len(subprocesses) == 0:
            reactor.stop()

###############################################################################
# Basic Safety Checks
###############################################################################
config.load()

if config.transport is None:
    config.transport = 'BOTH'
    
if config.automatic_blocklist_updates_source is None:
    config.automatic_blocklist_updates_source = ''

if config.automatic_blocklist_updates_refresh is None:
    config.automatic_blocklist_updates_refresh = 600
    
if config.exit_node_list_refresh is None:
    config.exit_node_list_refresh = 600

if not os.path.exists(config.datadir):
    print "Tor2web Startup Failure: unexistent directory (%s)" % config.datadir
    exit(1)

if config.mode not in [ 'TRANSLATION', 'WHITELIST', 'BLACKLIST' ]:
    print "Tor2web Startup Failure: config.mode must be one of: TRANSLATION / WHITELIST / BLACKLIST"
    exit(1)

if config.mode == "TRANSLATION":
    if not verify_onion(config.onion):
        print "Tor2web Startup Failure: TRANSLATION config.mode require config.onion configuration"
        exit(1)        
    
for d in [ 'certs',  'logs']:
    path = os.path.join(config.datadir, d)
    if not os.path.exists(path):
        print "Tor2web Startup Failure: unexistent directory (%s)" % path
        exit(1)

files =[]
files.append('certs/tor2web-key.pem')
files.append('certs/tor2web-intermediate.pem')
files.append('certs/tor2web-dh.pem')
for f in files:
    path = os.path.join(config.datadir, f)
    try:
        if (not os.path.exists(path) or
            not os.path.isfile(path) or
            not os.access(path, os.R_OK)):
            print "Tor2web Startup Failure: unexistent file (%s)" % path
            exit(1)
    except:
        print "Tor2web Startup Failure: error while accessing file (%s)" % path
        exit(1)

###############################################################################

if config.listen_ipv6 == "::" or config.listen_ipv4 == config.listen_ipv6:
    # fix for incorrect configurations
    ipv4 = None
else:
    ipv4 = config.listen_ipv4
ipv6 = config.listen_ipv6

rpc_server = T2WRPCServer(config)

quitting = False
subprocesses = []

def SigTERM(SIG, FRM):
    global quitting
    quitting = True

signal.signal(signal.SIGTERM, SigTERM)
signal.signal(signal.SIGINT, SigTERM)

def open_listenin_socket(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setblocking(False)
    s.bind((ip, port))
    s.listen(socket.SOMAXCONN)
    return s

def daemon_init(self):
    self.socket_rpc = open_listenin_socket('127.0.0.1', 8789)

    self.sockets_https = []
    self.sockets_http = []

    for ip in [ipv4, ipv6]:
        if ip != None:
            if config.transport in ('HTTPS', 'BOTH'):
                self.sockets_https.append(open_listenin_socket(ip, 443))

            if config.transport in ('HTTP', 'BOTH'):
                self.sockets_http.append(open_listenin_socket(ip, 80))

def daemon_main(self):

    reactor.listenTCPonExistingFD = listenTCPonExistingFD

    reactor.listenTCPonExistingFD(reactor, fd=self.socket_rpc.fileno(), factory=pb.PBServerFactory(rpc_server))

    for i in range(config.processes):
        subprocess = spawnT2W(self.sockets_https, self.sockets_http)
        subprocesses.append(subprocess.pid)

    if config.debugmode:
        if config.debugtostdout:
            log.startLogging(sys.stdout)
    else:
        log.startLogging(log.NullFile)

    reactor.run()

def daemon_reload(self):
    rpc_server.load_lists()

prctl.set_proctitle("tor2web")

t2w_daemon = T2WDaemon()
t2w_daemon.daemon_init = daemon_init
t2w_daemon.daemon_main = daemon_main
t2w_daemon.daemon_reload = daemon_reload

#sys.excepthook = MailException

t2w_daemon.run(config.datadir)

exit(0)

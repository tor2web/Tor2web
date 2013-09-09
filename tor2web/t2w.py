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
   :synopsis: Main Tor2web Server Implementation

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

import datetime
import os
import prctl
import re
import sys
import random
import socket
import signal
import hashlib

from twisted.internet import reactor, protocol, defer
from twisted.application import service, internet
from twisted.python import log, logfile, syslog
from twisted.python.filepath import FilePath
from twisted.spread import pb
from twisted.web.http import datetimeToString

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

    def remote_get_blocked_ua_list(self):
        return list(self.blocked_ua)

    def remote_get_access_list(self):
        return list(self.access_list)

    def remote_get_tor_exits_list(self):
        return list(self.TorExitNodes)

    def remote_update_stats(self, onion):
        self.stats.update(onion)

    def remote_get_yesterday_stats(self):
        return self.stats.yesterday_stats

    def remote_log_access(self, line):
        self.logfile_access.write(line)

    def remote_log_debug(self, line):
        date = datetimeToString()
        self.logfile_debug.write(date+" "+str(line)+"\n")
 
def spawnT2W(childFDs, fds_https, fds_http):
    subprocess = reactor.spawnProcess(T2WPP(childFDs, fds_https, fds_http),
                                      "tor2web-worker",
                                      ["tor2web-worker",
                                       fds_https,
                                       fds_http],
                                      childFDs=childFDs)
    return subprocess


class T2WPP(protocol.ProcessProtocol):
    def __init__(self, childFDs, fds_https, fds_http):
        self.childFDs = childFDs
        self.fds_https = fds_https
        self.fds_http = fds_http

    def connectionMade(self):
        self.pid = self.transport.pid

    def processExited(self, reason):
        global quitting
        global subprocesses
        for x in range(len(subprocesses)):
            if subprocesses[x] == self.pid:
                del subprocesses[x]
                break

        if not quitting:
            subprocess = spawnT2W(self.childFDs, self.fds_https, self.fds_http)
            subprocesses.append(subprocess.pid)

        if len(subprocesses) == 0:
            reactor.stop()

##########################
# Security UMASK hardening
os.umask(077)

orig_umask = os.umask

def umask(mask):
    return orig_umask(077)

os.umask = umask
##########################

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
t2w_daemon = T2WDaemon()

quitting = False
subprocesses = []

def open_listenin_socket(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setblocking(False)
        s.bind((ip, port))
        s.listen(socket.SOMAXCONN)
    except Exception as e:
        print "Tor2web Startup Failure: error while binding on %s %s (%s)" % (ip, port, e)
        exit(1)
    return s

def daemon_init(self):
    self.socket_rpc = open_listenin_socket('127.0.0.1', 8789)

    self.childFDs = {}
    self.childFDs[0] = 0
    self.childFDs[1] = 1
    self.childFDs[2] = 2

    self.fds = []

    self.fds_https = ''
    self.fds_http = ''

    i_https = 0
    i_http = 0

    for ip in [ipv4, ipv6]:
        if ip != None:
            if config.transport in ('HTTPS', 'BOTH'):
                if i_https != 0:
                    self.fds_https += ','
                s = open_listenin_socket(ip, config.listen_port_https)
                self.fds.append(s)
                self.childFDs[s.fileno()] = s.fileno()
                self.fds_https += str(s.fileno())
                i_https += 1

            if config.transport in ('HTTP', 'BOTH'):
                if i_http != 0:
                    self.fds_http += ','
                s = open_listenin_socket(ip, config.listen_port_http)
                self.fds.append(s)
                self.childFDs[s.fileno()] = s.fileno()
                self.fds_http += str(s.fileno())
                i_http += 1

def daemon_main(self):

    reactor.listenTCPonExistingFD = listenTCPonExistingFD
    
    reactor.listenUNIX(os.path.join("/var/run/tor2web/rpc.socket"), factory=pb.PBServerFactory(rpc_server))

    for i in range(config.processes):
        global subprocesses
        subprocess = spawnT2W(self.childFDs, self.fds_https, self.fds_http)
        subprocesses.append(subprocess.pid)

    if config.debugmode and config.debugtostdout:
        log.startLogging(sys.stdout)
    else:
        log.startLogging(log.NullFile)

    sys.excepthook = MailException

    reactor.run()

def daemon_reload(self):
    rpc_server.load_lists()

def daemon_shutdown(self):
    global quitting
    global subprocesses

    quitting = True

    for pid in subprocesses:
        os.kill(pid, signal.SIGINT)
    subprocesses = []

prctl.set_proctitle("tor2web")

t2w_daemon = T2WDaemon()

t2w_daemon.daemon_init = daemon_init
t2w_daemon.daemon_main = daemon_main
t2w_daemon.daemon_reload = daemon_reload
t2w_daemon.daemon_shutdown = daemon_shutdown

t2w_daemon.run(config.datadir)

exit(0)

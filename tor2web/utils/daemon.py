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

from optparse import OptionParser

import os
import sys
import time

from signal import signal, SIGINT, SIGHUP
import pwd, grp

class T2WDaemonException:
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return self.msg

class _NullDevice:
    """A substitute for stdout/stderr that writes to nowhere."""

    def isatty(self, *a, **kw):
        return False

    def write(self, s):
        pass

    def flush(self, s):
        pass        


class T2WDaemon:
    def become_daemon(self):

        if os.fork() != 0:  # launch child and ...
            os._exit(0)     # kill off parent
        os.setsid()
        os.chdir(self.options.rundir)

        if (self.options.uid != "") and (self.options.gid != ""):
            uid = pwd.getpwnam(self.options.uid).pw_uid
            gid = grp.getgrnam(self.options.gid).gr_gid

        os.umask(0)
        if os.fork() != 0:  # fork again so we are not a session leader
            os._exit(0)
        sys.stdin.close()
        
        sys.__stdin__ = sys.stdin
        sys.stdout.close()
        sys.stdout = sys.__stdout__ = _NullDevice()
        sys.stderr.close()
        sys.stderr = sys.__stderr__ = _NullDevice()

    def daemon_start(self):
        self.daemon_init(self) # self must be explicit passed
                               # as the function is user defined

        if not self.options.nodaemon:
            self.become_daemon()

        if self.is_process_running():
            raise T2WDaemonException("Unable to start server. Process is already running.")

        f = open(self.options.pidfile, 'w')
        f.write("%s" % os.getpid())
        f.close()
        if (self.options.uid != "") and (self.options.gid != ""):
            self.change_uid()

        def _daemon_reload(SIG, FRM):
            self.daemon_reload() # self must be explicit passed
                                 # as the function is user defined

        signal(SIGHUP, _daemon_reload)

        self.daemon_main(self) # self must be explicit passed
                               # as the function is user defined

    def daemon_stop(self):
        pid = self.get_pid()
        
        try:
            os.kill(pid, SIGINT)  # SIGTERM is too harsh...
        except:
            pass

        time.sleep(1)

        try:
            os.unlink(self.options.pidfile)
        except:
            pass

    def get_pid(self):
        try:
            f = open(self.options.pidfile)
            pid = int(f.readline().strip())
            f.close()
        except IOError:
            pid = None
        return pid
    def is_process_running(self):
        pid = self.get_pid()
        if pid:
            try:
                os.kill(pid, 0)
                return 1
            except OSError:
                pass
        return 0

    def change_uid(self):
      c_user =  self.options.uid
      c_group = self.options.gid
      if os.getuid() == 0:
         cpw = pwd.getpwnam(c_user)
         c_uid = cpw.pw_uid
         if c_group:
            cgr = grp.getgrnam(c_group)
            c_gid = cgr.gr_gid
         else:
            c_gid = cpw.pw_gid
            c_group = grp.getgrgid(cpw.pw_gid).gr_name
         c_groups = []
         for item in grp.getgrall():
            if c_user in item.gr_mem:
               c_groups.append(item.gr_gid)
         if c_gid not in c_groups:
            c_groups.append(c_gid)

         os.setgid(c_gid)
         os.setgroups(c_groups)
         os.setuid(c_uid)

    def run(self, datadir):
        parser = OptionParser()
        parser.add_option("", "--pidfile", dest="pidfile", default="/var/run/tor2web.pid")
        parser.add_option("", "--uid", dest="uid", default="")
        parser.add_option("", "--gid", dest="gid", default="")
        parser.add_option("", "--nodaemon", dest="nodaemon", default=False, action="store_true")
        parser.add_option("", "--rundir", dest="rundir", default=datadir)
        parser.add_option("", "--command", dest="command", default="start")

        (self.options, args) = parser.parse_args()

        pid = self.get_pid()
        
        if self.options.command == 'status':
            if not self.is_process_running():
                exit(1)
            else:
                exit(0)
        elif self.options.command == 'start':
            if not self.is_process_running():
                self.daemon_start()
            exit(0)
        elif self.options.command == 'stop':
            if self.is_process_running():
                self.daemon_stop()
            exit(0)
        elif self.options.command == 'reload':
            if self.is_process_running():
                pid = self.get_pid()
                try:
                   os.kill(pid, SIGHUP)
                except:
                   pass
            else:
               self.daemon_start()
            exit(0)
        elif self.options.command == 'restart':
            self.daemon_stop()
            self.daemon_start()
            exit(0)
        else:
            print "Unknown command:", self.options.command
            raise SystemExit

        exit(1)

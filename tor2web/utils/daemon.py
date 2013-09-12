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

import os
import sys
import time
import glob
import signal
import pwd
import grp
import atexit

from optparse import OptionParser

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
        os.umask(077)

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

        if not os.path.exists(self.options.rundir):
            os.mkdir(self.options.rundir)

        os.chmod(self.options.rundir, 0700)

        if not self.options.nodaemon:
            self.become_daemon()

        with open(self.options.pidfile, 'w') as f:
           f.write("%s" % os.getpid())

        os.chmod(self.options.pidfile, 0600)

        @atexit.register
        def goodbye():
            try:
                os.unlink(self.options.pidfile)
            except Exception:
                pass

        if (self.options.uid != "") and (self.options.gid != ""):
            self.change_uid()

        for item in glob.glob(self.options.rundir + '/*'):
            os.chmod(item, 0600)

        def _daemon_reload(SIG, FRM):
            self.daemon_reload() # self must be explicit passed
                                 # as the function is user defined

        def _daemon_shutdown(SIG, FRM):
            self.daemon_shutdown(self) # self must be explicit passed
                                       # as the function is user defined

        signal.signal(signal.SIGHUP, _daemon_reload)
        signal.signal(signal.SIGTERM, _daemon_shutdown)
        signal.signal(signal.SIGINT, _daemon_shutdown)

        self.daemon_main(self) # self must be explicit passed
                               # as the function is user defined

    def daemon_stop(self):
        pid = self.get_pid()
        
        try:
            os.kill(pid, signal.SIGINT)  # SIGTERM is too harsh...
        except Exception:
            pass

        time.sleep(1)

        try:
            os.unlink(self.options.pidfile)
        except Exception:
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

            c_groups = []
            for item in grp.getgrall():
                if c_user in item.gr_mem:
                    c_groups.append(item.gr_gid)
                if c_gid not in c_groups:
                    c_groups.append(c_gid)

            os.chown(self.options.rundir, c_uid, c_gid)

            os.chown(self.options.pidfile, c_uid, c_gid)

            for item in glob.glob(self.options.rundir + '/*'):
                os.chown(item, c_uid, c_gid)

            os.setgid(c_gid)
            os.setgroups(c_groups)
            os.setuid(c_uid)

    def run(self, datadir):
        parser = OptionParser()
        parser.add_option("", "--pidfile", dest="pidfile", default="/var/run/tor2web/t2w.pid")
        parser.add_option("", "--uid", dest="uid", default="")
        parser.add_option("", "--gid", dest="gid", default="")
        parser.add_option("", "--nodaemon", dest="nodaemon", default=False, action="store_true")
        parser.add_option("", "--rundir", dest="rundir", default='/var/run/tor2web')
        parser.add_option("", "--command", dest="command", default="start")

        (self.options, args) = parser.parse_args()
        
        if self.options.command == 'status':
            if not self.is_process_running():
                exit(1)
            else:
                exit(0)
        elif self.options.command == 'start':
            if not self.is_process_running():
                self.daemon_start()
                exit(0)
            else:
                print "Unable to start Tor2web: process is already running."
                exit(1)
        elif self.options.command == 'stop':
            if self.is_process_running():
                self.daemon_stop()
            exit(0)
        elif self.options.command == 'reload':
            if self.is_process_running():
                pid = self.get_pid()
                try:
                   os.kill(pid, signal.SIGHUP)
                except Exception:
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

    def daemon_init(self):
        pass

    def daemon_reload(self):
        pass

    def daemon_shutdown(self):
        pass

    def daemon_main(self):
        pass

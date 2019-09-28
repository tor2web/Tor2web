"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: Daemon utils

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

import os
import sys
import time
import signal
import pwd
import grp
import atexit
import platform

import ctypes

class _NullDevice(object):
    """A substitute for stdout/stderr that writes to nowhere."""

    def isatty(self, *a, **kw):
        return False

    def write(self, s):
        pass

    def flush(self, s):
        pass


class Daemon(object):
    def __init__(self, config):
        self.config = config

    def become_daemon(self):
        if os.fork() != 0:  # launch child and kill the parent
            os._exit(0)

        os.setsid()
        os.chdir(self.config.rundir)
        os.umask(0o77)

        if os.fork() != 0:  # fork again so we are not a session leader
            os._exit(0)

        sys.stdin.close()
        sys.__stdin__ = sys.stdin

        sys.stdout.close()
        sys.stdout = sys.__stdout__ = _NullDevice()

        sys.stderr.close()
        sys.stderr = sys.__stderr__ = _NullDevice()

    def daemon_start(self):
        self.daemon_init()

        if not os.path.exists(self.config.rundir):
            os.mkdir(self.config.rundir)

        os.chmod(self.config.rundir, 0o700)

        if not self.config.nodaemon:
            self.become_daemon()

        with open(self.config.pidfile, 'w') as f:
            f.write("%s" % os.getpid())

        os.chmod(self.config.pidfile, 0o600)

        @atexit.register
        def goodbye():
            try:
                os.unlink(self.config.pidfile)
            except Exception:
                pass

        if (self.config.uid != "") and (self.config.gid != ""):
            self.change_uid()

        def _daemon_reload(SIG, FRM):
            self.daemon_reload()

        def _daemon_shutdown(SIG, FRM):
            self.daemon_shutdown()

        signal.signal(signal.SIGHUP, _daemon_reload)
        signal.signal(signal.SIGTERM, _daemon_shutdown)
        signal.signal(signal.SIGINT, _daemon_shutdown)

        self.daemon_main()

    def daemon_stop(self):
        pid = self.get_pid()

        try:
            os.kill(pid, signal.SIGINT)  # SIGTERM is too harsh...
        except Exception:
            pass

        time.sleep(1)

        try:
            os.unlink(self.config.pidfile)
        except Exception:
            pass

    def get_pid(self):
        try:
            f = open(self.config.pidfile)
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
        c_user =  self.config.uid
        c_group = self.config.gid

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

            os.chown(self.config.datadir, c_uid, c_gid)
            os.chown(self.config.rundir, c_uid, c_gid)
            os.chown(self.config.pidfile, c_uid, c_gid)

            for root, _, filenames in os.walk(self.config.datadir):
                for filename in filenames:
                    os.chown(os.path.join(root, filename), c_uid, c_gid)

            for root, _, filenames in os.walk(self.config.rundir):
                for filename in filenames:
                    os.chown(os.path.join(root, filename), c_uid, c_gid)

            os.setgid(c_gid)
            os.setgroups(c_groups)
            os.setuid(c_uid)

    def run(self):
        if self.config.command == 'status':
            if not self.is_process_running():
                exit(1)
            else:
                exit(0)
        elif self.config.command == 'start':
            if not self.is_process_running():
                self.daemon_start()
                exit(0)
            else:
                print("Unable to start Tor2web: process is already running.")
                exit(1)
        elif self.config.command == 'stop':
            if self.is_process_running():
                self.daemon_stop()
            exit(0)
        elif self.config.command == 'reload':
            if self.is_process_running():
                pid = self.get_pid()
                try:
                    os.kill(pid, signal.SIGHUP)
                except Exception:
                    pass
            else:
                self.daemon_start()
            exit(0)
        elif self.config.command == 'restart':
            self.daemon_stop()
            self.daemon_start()
            exit(0)
        else:
            print(("Unknown command:", self.config.command))
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

def set_proctitle(title):
    if platform.system() == 'Linux': # Virgil has Mac OS!
        libc = ctypes.cdll.LoadLibrary('libc.so.6')
        buff = ctypes.create_string_buffer(len(title) + 1)
        buff.value = title
        libc.prctl(15, ctypes.byref(buff), 0, 0, 0)

def set_pdeathsig(sig):
    if platform.system() == 'Linux': # Virgil has Mac OS!
        PR_SET_PDEATHSIG = 1
        libc = ctypes.cdll.LoadLibrary('libc.so.6')
        libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                               ctypes.c_ulong, ctypes.c_ulong)
        libc.prctl(PR_SET_PDEATHSIG, sig, 0, 0, 0)

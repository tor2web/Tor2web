# -*- coding: utf-8 -*-
#
# :authors: Israel Leiva <ilv@torproject.org>
#
# :copyright:   (c) 2015, Hermes No Profit Association - GlobaLeaks Project
#               (c) 2015, Israel Leiva
#
# :license:
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
# License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import os

import urllib2
import json
import argparse
import ConfigParser
import shutil


# "regex" for filtering downloads in wget
OS_RE = {
    'windows': '%s.exe,%s.exe.asc',
    'osx': '%s.dmg,%s.dmg.asc',
}

# path to latest version of Tor Browser and Tor Browser files
LATEST_TB_FILE = '../data/lists/latest_torbrowser.txt'
TB_PATH = '../data/torbrowser/'

def main():
    """Script to fetch the latest Tor Browser.

    Fetch the latest version of Tor Browser from dist.torproject.org.
    This script should be executed with a cron in order to automate the
    updating of the files served by GetTor static URL when a new version
    of Tor Browser is released. For the purposes of tor2web, this only
    fetches Tor Browser files for Windows and Mac OS X.

    Usage: python2.7 fetch.py --os=<OS> --lc=<LC>

    Some fetch examples:

    Fetch Tor Browser for both platforms and all languages:
        $ python2.7 fetch.py

    Fetch Tor Browser only for Mac OS X:
        $ python2.7 fetch.py --os=osx

    Fetch Tor Browser only for Windows and in US English:
        $ python2.7 fetch.py --os=windows --lc=en-US

    Fetch Tor Browser for both platforms, but only in Spanish:
        $ python2.7 fetch.py --lc=es-ES

    """
    parser = argparse.ArgumentParser(
        description='Utility to fetch the latest Tor Browser.'
    )

    # if no OS specified, download all
    parser.add_argument('-o', '--os', default=None,
                        help='filter by OS')

    # if no LC specified, download all
    parser.add_argument('-l', '--lc', default='',
                        help='filter by locale')

    args = parser.parse_args()

    # server from which to download Tor Browser
    dist_tpo = 'https://dist.torproject.org/torbrowser/'

    # find out the latest version
    url = 'https://www.torproject.org/projects/torbrowser/RecommendedTBBVersions'
    response = urllib2.urlopen(url)
    json_response = json.load(response)
    latest_version = json_response[0]

    # find out the current version delivered by GetTor static URL
    with open (LATEST_TB_FILE, 'r') as version_file:
        current_version = version_file.read().replace('\n', '')

    if current_version != latest_version:
        mirror = '%s%s/' % (dist_tpo, latest_version)

        # what LC should we download?
        lc_re = args.lc

        # what OS should we download?
        if args.os == 'windows':
            os_re = OS_RE['windows'] % (lc_re, lc_re)

        elif args.os == 'osx':
            os_re = OS_RE['osx'] % (lc_re, lc_re)

        else:
            os_re = '%s.exe,%s.exe.asc,%s.dmg,%s.dmg.asc' %\
                    (lc_re, lc_re, lc_re, lc_re)

        params = "-nH --cut-dirs=1 -L 1 --accept %s" % os_re

        # in wget we trust
        cmd = 'wget %s --mirror %s' % (params, mirror)

        # make the mirror
        # a folder with the value of 'latest_version' will be created
        os.system(cmd)
        # everything inside upload will be uploaded by the providers' scripts
        shutil.move('%slatest' % TB_PATH, '%slatest_backup' % TB_PATH)
        shutil.move(latest_version, '%slatest' % TB_PATH)
        shutil.rmtree('%slatest_backup' % TB_PATH)

        # if everything is OK, update the current version delivered by
        # GetTor static URL
        with open(LATEST_TB_FILE, 'w') as version_file:
            version_file.write(latest_version)

    else:
        print "Tor Browser files are up to date!"

if __name__ == "__main__":
    main()

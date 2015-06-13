#!/bin/bash

set -e

die() {
  echo "Please specify a valid distro codename"
  echo "Available: precise, trusty, wheezy, jessie";
  echo "e.g.: $0 precise"
  exit 1;
}

DISTRIBUTION="precise"
NOSIGN=0

while getopts "d:n" opt; do
  case $opt in
    d) DISTRIBUTION="$OPTARG"
    ;;
    n) NOSIGN=1
    ;;
    \?) echo "Invalid option -$OPTARG" >&2
        die
    ;;
  esac
done

if [ "$DISTRIBUTION" != "precise" ] &&
   [ "$DISTRIBUTION" != "trusty" ] &&
   [ "$DISTRIBUTION" != "wheezy" ] &&
   [ "$DISTRIBUTION" != "jessie" ]; then
 die
fi

echo "Packaging Tor2web for:" $DISTRIBUTION

[ -d T2WRelease ] && rm -rf T2WRelease

mkdir T2WRelease
cd T2WRelease
git clone git@github.com:globaleaks/Tor2web.git
cd Tor2web
sed -i "s/stable; urgency=/$DISTRIBUTION; urgency=/g" debian/changelog

if [ $NOSIGN -eq 1 ]; then
  debuild -i -us -uc -b
else
  debuild
fi

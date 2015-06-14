#!/bin/bash

set -e

usage() {
  echo "Tor2web Build Script"
  echo "Valid options:"
  echo " -h"
  echo -e " -t tagname (build specific release/branch)"
  echo -e " -d distribution (available: precise, trusty, wheezy, jessie)"
  echo -e " -n (do not sign)"
  
}

DISTRIBUTION="precise"
TAG="master"
NOSIGN=0

while getopts "d:n:th" opt; do
  case $opt in
    d) DISTRIBUTION="$OPTARG"
    ;;
    t) TAG="$OPTARG"
    ;;
    n) NOSIGN=1
    ;;
    h)
        usage
        exit 1
    ;;
    \?) usage
        exit 1
    ;;
  esac
done

if [ "$DISTRIBUTION" != "precise" ] &&
   [ "$DISTRIBUTION" != "trusty" ] &&
   [ "$DISTRIBUTION" != "wheezy" ] &&
   [ "$DISTRIBUTION" != "jessie" ]; then
  usage
  exit 1 
fi

echo "Packaging Tor2web for:" $DISTRIBUTION

[ -d T2WRelease ] && rm -rf T2WRelease

mkdir T2WRelease
cd T2WRelease
git clone git@github.com:globaleaks/Tor2web.git
cd Tor2web
git checkout $TAG
sed -i "s/stable; urgency=/$DISTRIBUTION; urgency=/g" debian/changelog

if [ $NOSIGN -eq 1 ]; then
  debuild -i -us -uc -b
else
  debuild
fi

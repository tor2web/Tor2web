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

if [ "$DISTRIBUTION" != "all" ] &&
   [ "$DISTRIBUTION" != "precise" ] &&
   [ "$DISTRIBUTION" != "trusty" ] &&
   [ "$DISTRIBUTION" != "wheezy" ] &&
   [ "$DISTRIBUTION" != "jessie" ]; then
 usage
 exit 1
fi

if [ "$DISTRIBUTION" == "all" ]; then
  TARGETS="precise trusty wheezy jessie"
else
  TARGETS=$DISTRIBUTION
fi

# Preliminary Requirements Check
ERR=0
echo "Checking preliminary Tor2web Build requirements"
for REQ in git debuild
do
  if which $REQ >/dev/null; then
    echo " + $REQ requirement meet"
  else
    ERR=$(($ERR+1))
    echo " - $REQ requirement not meet"
  fi
done

if [ $ERR -ne 0 ]; then
  echo "Error: Found ${ERR} unmet requirements"
  echo "Information on how to setup tor2web development environment at: https://github.com/globaleaks/Tor2web/wiki/setting-up-globaleaks-development-environment"
  exit 1
fi

BUILDSRC="T2WRelease"
[ -d $BUILDSRC ] && rm -rf $BUILDSRC
mkdir $BUILDSRC && cd $BUILDSRC
git clone https://github.com/globaleaks/Tor2web.git
cd Tor2web
git checkout $TAG
cd ../../

for TARGET in $TARGETS; do
  echo "Packaging Tor2web for:" $TARGET

  BUILDDIR="T2WRelease-$TARGET"

  [ -d $BUILDDIR ] && rm -rf $BUILDDIR

  cp -r $BUILDSRC $BUILDDIR
  cd $BUILDDIR/Tor2web
  sed -i "s/stable; urgency=/$TARGET; urgency=/g" debian/changelog

  if [ $NOSIGN -eq 1 ]; then
    debuild -i -us -uc -b
  else
    debuild
  fi

  cd ../../
done

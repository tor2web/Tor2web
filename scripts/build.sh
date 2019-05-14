#!/bin/bash

set -e

usage() {
  echo "Tor2web Build Script"
  echo "Valid options:"
  echo " -h"
  echo -e " -t tagname (build specific release/branch)"
  echo -e " -d distribution (available: xenial, bionic)"
  echo -e " -n (do not sign)"
  echo -e " -p (push on repository)"
}

TARGETS="xenial bionic"
DISTRIBUTION="xenial"
TAG="master"
NOSIGN=0
PUSH=0

while getopts "d:t:np:h" opt; do
  case $opt in
    d) DISTRIBUTION="$OPTARG"
    ;;
    t) TAG="$OPTARG"
    ;;
    n) NOSIGN=1
    ;;
    p) PUSH=1
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

if ! [[ $TARGETS =~ $DISTRIBUTION ]] && [[ $DISTRIBUTION != 'all' ]]; then
 usage
 exit 1
fi

if [ "$DISTRIBUTION" != 'all' ]; then
  TARGETS=$DISTRIBUTION
fi

# Preliminary Requirements Check
ERR=0
echo "Checking preliminary Tor2web Build requirements"
for REQ in git debuild dput
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

  rm debian/control requirements.txt

  cp debian/controlX/control.$TARGET debian/control
  cp requirements/requirements-$TARGET.txt requirements.txt

  sed -i "s/stable; urgency=/$TARGET; urgency=/g" debian/changelog

  if [ $NOSIGN -eq 1 ]; then
    debuild -i -us -uc -b
  else
    debuild
  fi

  cd ../../
done

if [ $PUSH -eq 1 ]; then
  for TARGET in $TARGETS; do

    BUILDDIR="T2WRelease-$TARGET"

    cp -r $BUILDSRC $BUILDDIR

    dput globaleaks tor2web*changes

    cd ../../
  done
fi

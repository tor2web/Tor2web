#!/bin/bash

# user permission check
if [ ! $(id -u) = 0 ]; then
  echo "Error: Tor2web install script must be runned by root"
  exit 1
fi

LOGFILE="./install.log"
ASSUMEYES=0

for arg in "$@"; do
  shift
  case "$arg" in
    --assume-yes ) ASSUMEYES=1; shift;;
    -- ) shift; break;;
    * ) break;;
  esac
done

DISTRO="unknown"
DISTRO_CODENAME="unknown"
if which lsb_release >/dev/null; then
  DISTRO="$( lsb_release -is )"
  DISTRO_CODENAME="$( lsb_release -cs )"
fi

if echo "$DISTRO_CODENAME" | grep -vqE "^xenial$" ; then
  echo "WARNING: GlobaLeaks is supported and tested only on Ubuntu Xenial (16.04)"

  if [ $ASSUMEYES -eq 0 ]; then
    while true; do
      read -p "Do you wish to continue anyway? [y|n]?" yn
      case $yn in
        [Yy]*) break;;
        [Nn]*) exit 1;;
        *) echo $yn; echo "Please answer y/n.";  continue;;
      esac
    done
  fi
fi

echo "Performing Tor2web installation on $DISTRO - $DISTRO_CODENAME"

# The supported platforms are experimentally more than only Ubuntu as
# publicly communicated to users.
#
# Depending on the intention of the user to proceed anyhow installing on
# a not supported distro we using the experimental package if it exists
# or xenial as fallback.
if echo "$DISTRO_CODENAME" | grep -vqE "^(trusty|xenial|wheezy|jessie)$"; then
  # In case of unsupported platforms we fallback on Xenial
  echo "No packages available for the current distribution; the install script will use the Xenial repository."
  echo "In case of a failure refer to the wiki for manual setup possibilities."
  echo "GlobaLeaks wiki: https://github.com/globaleaks/GlobaLeaks/wiki"
  DISTRO="Ubuntu"
  DISTRO_CODENAME="xenial"
fi

DO () {
  if [ -z "$2" ]; then
    RET=0
  else
    RET=$2
  fi
  if [ -z "$3" ]; then
    CMD=$1
  else
    CMD=$3
  fi
  echo -n "Running: \"$CMD\"... "
  eval $CMD &>${LOGFILE}
  if [ "$?" -eq "$RET" ]; then
    echo "SUCCESS"
  else
    echo "FAIL"
    echo "COMBINED STDOUT/STDERR OUTPUT OF FAILED COMMAND:"
    cat ${LOGFILE}
    exit 1
  fi
}

# Preliminary Requirements Check
ERR=0
echo "Checking preliminary Tor2web requirements"
for REQ in apt-key apt-get wget
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
  exit 1
fi

echo "Adding GlobaLeaks PGP key to trusted APT keys"
TMPFILE=/tmp/globaleaks_key.$RANDOM
DO "wget https://deb.globaleaks.org/globaleaks.asc -O $TMPFILE"
DO "apt-key add $TMPFILE"
DO "rm -f $TMPFILE"

DO "apt-get update -y"

if echo "$DISTRO_CODENAME" | grep -qE "^(wheezy)$"; then
  echo "Installing python-software-properties"
  DO "apt-get install python-software-properties -y"
else
  echo "Installing software-properties-common"
  DO "apt-get install software-properties-common -y"
fi

if ! grep -q "^deb .*universe" /etc/apt/sources.list /etc/apt/sources.list.d/*; then
  echo "Adding Ubuntu Universe repository"
  DO "add-apt-repository 'deb http://archive.ubuntu.com/ubuntu $(lsb_release -sc) universe'"
fi

if [ ! -f /etc/apt/sources.list.d/globaleaks.list ]; then
  # we avoid using apt-add-repository as we prefer using /etc/apt/sources.list.d/globaleaks.list
  echo "deb http://deb.globaleaks.org $DISTRO_CODENAME/" > /etc/apt/sources.list.d/globaleaks.list
fi

DO "apt-get update -y"
DO "apt-get install tor2web -y"

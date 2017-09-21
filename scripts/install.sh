#!/bin/bash

# user permission check
if [ ! $(id -u) = 0 ]; then
  echo "Error: Tor2web install script must be runned by root"
  exit 1
fi

# Preliminary Requirements Check
ERR=0
echo "Checking preliminary Tor2web requirements"
for REQ in apt-key apt-get
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

DO () {
  if [ -z "$2" ]; then
    EXPECTED_RET=0
  else
    EXPECTED_RET=$2
  fi
  if [ -z "$3" ]; then
    CMD=$1
  else
    CMD=$3
  fi
  echo -n "Running: \"$CMD\"... "
  eval $CMD &>${LOGFILE}

  STATUS=$?

  echo $CMD > $TMPDIR/last_command
  echo $STATUS > $TMPDIR/last_status

  if [ "$STATUS" -eq "$EXPECTED_RET" ]; then
    echo "SUCCESS"
  else
    echo "FAIL"
    echo "Ouch! The installation failed."
    echo "COMBINED STDOUT/STDERR OUTPUT OF FAILED COMMAND:"
    cat ${LOGFILE}
    exit 1
  fi
}

LOGFILE="./install.log"
ASSUMEYES=0

GLOBALEAKS_PGP_KEY="
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

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
=XU7T
-----END PGP PUBLIC KEY BLOCK-----"

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
  DISTRO="$(lsb_release -is)"
  DISTRO_CODENAME="$(lsb_release -cs)"
  REAL_DISTRO=$DISTRO
  REAL_DISTRO_CODENAME=$DISTRO_CODENAME
fi

# LinuxMint is based on Ubuntu, if we encounter Mint just allign the Ubuntu version is based upon
if [ "$DISTRO" == "LinuxMint" ]; then
  DISTRO="Ubuntu"
  DISTRO_CODENAME=$(grep UBUNTU_CODENAME /etc/os-release | sed -e 's/UBUNTU_CODENAME=//')
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

echo "Detected OS: $DISTRO - $DISTRO_CODENAME"

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

echo "Adding GlobaLeaks PGP key to trusted APT keys"
TMPFILE=$TMPDIR/globaleaks_key
echo "$GLOBALEAKS_PGP_KEY" > $TMPFILE
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

# try adding universe repo only on Ubuntu
if echo "$DISTRO" | grep -qE "^(Ubuntu)$"; then
  if ! grep -q "^deb .*universe" /etc/apt/sources.list /etc/apt/sources.list.d/*; then
    echo "Adding Ubuntu Universe repository"
    DO "add-apt-repository 'deb http://archive.ubuntu.com/ubuntu $DISTRO_CODENAME universe'"
  fi
fi

if [ ! -f /etc/apt/sources.list.d/globaleaks.list ]; then
  # we avoid using apt-add-repository as we prefer using /etc/apt/sources.list.d/globaleaks.list
  echo "deb http://deb.globaleaks.org $DISTRO_CODENAME/" > /etc/apt/sources.list.d/globaleaks.list
fi

DO "apt-get update -y"
DO "apt-get install tor2web -y"

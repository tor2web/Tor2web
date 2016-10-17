#!/bin/bash

# user permission check
if [ ! $(id -u) = 0 ]; then
    echo "Error: Tor2web install script must be runned by root"
    exit 1
fi

LOGFILE="./install.log"

DISTRO="unknown"
DISTRO_CODENAME="unknown"
if which lsb_release >/dev/null; then
  DISTRO="$( lsb_release -is )"
  DISTRO_CODENAME="$( lsb_release -cs )"
fi

if [ $DISTRO_CODENAME != "trusty" ]; then
  echo "!!!!!!!!!!!! WARNING !!!!!!!!!!!!"
  echo "You are attempting to install Tor2web on an unsupported platform."
  echo "Supported platform is Ubuntu Trusty (14.04)"

  while true; do
    read -p "Do you wish to continue anyhow? [y|n]?" yn
    case $yn in
      [Yy]*) break;;
      [Nn]*) echo "Installation aborted."; exit;;
      *) echo $yn; echo "Please answer y/n."; continue;;
    esac
  done
fi

echo "Performing Tor2web installation on $DISTRO - $DISTRO_CODENAME"

if [ $DISTRO_CODENAME != "trusty" ]; then
  # In case of unsupported platforms we fallback on trusty
  echo "Given that the platform is not supported the install script will use trusty repository."
  echo "In case of failure refer to the wiki for manual setup possibilities."
  echo "Tor2web Wiki Address: https://github.com/globaleaks/Tor2web/wiki"

  # Given the fact that the platform is not supported be try as it is an Ubuntu 14.04
  DISTRO="Ubuntu"
  DISTRO_CODENAME="trusty"
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
  $CMD &>${LOGFILE}
  if [ "$?" -eq "$RET" ]; then
    echo "SUCCESS"
  else
    echo "FAIL"
    echo "COMBINED STDOUT/STDERR OUTPUT OF FAILED COMMAND:"
    cat ${FILE}
    exit 1
  fi
}

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

echo "Adding GlobaLeaks PGP key to trusted APT keys"
TMPFILE=/tmp/globaleaks_key.$RANDOM
DO "wget --no-check-certificate https://deb.globaleaks.org/globaleaks.asc -O $TMPFILE"
DO "apt-key add $TMPFILE"
DO "rm -f $TMPFILE"

DO "apt-get update -y"

# on Ubuntu python-pip requires universe repository
if [ $DISTRO == "Ubuntu" ];then
  if [ "$DISTRO_CODENAME" = "precise" ]; then
    echo "Installing python-software-properties"
    DO "apt-get install python-software-properties -y"
  fi

  if [ "$DISTRO_CODENAME" = "trusty" ]; then
    echo "Installing software-properties-common"
    DO "apt-get install software-properties-common -y"
  fi

  echo "Adding Ubuntu Universe repository"
  add-apt-repository "deb http://archive.ubuntu.com/ubuntu $(lsb_release -sc) universe"
fi

if [ ! -f /etc/apt/sources.list.d/globaleaks.list ]; then
  # we avoid using apt-add-repository as we prefer using /etc/apt/sources.list.d/globaleaks.list
  echo "deb http://deb.globaleaks.org $DISTRO_CODENAME/" > /etc/apt/sources.list.d/globaleaks.list
fi

DO "apt-get update -y"

DO "apt-get install tor2web -y"

#!/bin/bash

############## Start Of Variable and Functions Declaration ###########

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR=/tmp/glbuilding.$RANDOM
BUILD_LOG=${BUILD_DIR}.log
DISTRO='unknown'
DISTRO_VERSION='unknown'

if [ -f /etc/redhat-release ]; then
  DISTRO="fedora"
# Debian/Ubuntu
elif [ -r /lib/lsb/init-functions ]; then
  if [ "$( lsb_release -is )" == "Debian" ]; then
    DISTRO="debian"
    DISTRO_VERSION="$( lsb_release -cs )"
  else
    DISTRO="ubuntu"
    DISTRO_VERSION="$( lsb_release -cs )"
  fi
fi

echo "Performing installation on $DISTRO - $DISTRO_VERSION"

if [ $DISTRO != 'ubuntu' ]; then
  echo "!!!!!!!!!!!! WARNING !!!!!!!!!!!!"
  echo "You are attempting to install Tor2web-3.0 on an unsupported platform."
  echo "Do you wish to continue at your own risk [Y|N]? "
  read ans
  if [ $ans = y -o $ans = Y -o $ans = yes -o $ans = Yes -o $ans = YES ]
  then
    echo "Ok, you wanted it!"
  else
    echo "Ok, no worries. Still friends, right?"
    exit
  fi
fi

usage()
{
cat << EOF
usage: ./${SCRIPTNAME} options

OPTIONS:
   -h      Show this message
   -y      To assume yes to all queries

EOF
}

ASSUME_YES=0
while getopts “hv:ny” OPTION
do
  case $OPTION in
    h)
      usage
      exit 1
      ;;
    y)
      ASSUME_YES=1
      ;;
    ?)
      usage
      exit
      ;;
    esac
done

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
    $1 &>${BUILD_LOG}
    if [ "$?" -eq "$2" ]; then
        echo "SUCCESS"
    else
        echo "FAIL"
        echo "COMBINED STDOUT/STDERR OUTPUT OF FAILED COMMAND:"
        cat ${BUILD_LOG}
        exit 1
    fi
}

add_repository () {
  # Distro independent function for adding a line to apt sources.list
  REPO="$(echo $1 | sed 's/DISTRO_VERSION/${DISTRO_VERSION}/')"
  if which add-apt-repository >/dev/null 2>&1;then
    add-apt-repository -y "$REPO"
  else
    if grep -Fxq "$REPO" /etc/apt/sources.list
    then
      echo "Repository already present. Not adding it..."
    else
      echo $REPO >> /etc/apt/sources.list
    fi
  fi
}

vercomp () {
    # Returnned values:
    #   0: version are equals
    #   1: $1 is bigger than $2
    #   2: $2 is bigger than $1
    if [[ $1 == $2 ]]
    then
        return 0
    fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    # fill empty fields in ver1 with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++))
    do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++))
    do
        if [[ -z ${ver2[i]} ]]
        then
            # fill empty fields in ver2 with zeros
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]}))
        then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]}))
        then
            return 2
        fi
    done
    return 0
}

############### End Of Variable and Functions Declaration ############

# User Permission Check
if [[ "$EUID" -ne "0" ]]; then
    echo "Error: Tor2web-3.0 install script must be runned by root"
    exit 1
fi

mkdir -p ${BUILD_DIR}
chmod 700 ${BUILD_DIR}
cd ${BUILD_DIR}

DO "apt-get update -y" "0"

echo "Installing python-dev"
DO "apt-get install python-dev -y" "0"

INSTALL_PIP=1
if which pip >/dev/null 2>&1; then
    INSTALLED_PIP=`pip --version | cut -d" " -f2`
    vercomp ${INSTALLED_PIP} ${NEEDED_VERSION_PIP}
    if [ "$?" -ne "2" ]; then
        INSTALL_PIP=0
    fi
fi

if [ "${INSTALL_PIP}" -eq "1" ] ; then
  DO "wget -O ${BUILD_DIR}/${PIP_PKG} ${PIP_URL}" "0"
  DO "wget -O ${BUILD_DIR}/${PIP_PKG}.asc ${PIP_SIG_URL}" "0"

  echo "Verifying PGP signature"
  echo "${PIP_PUB_KEY}" > ${PIP_KEY_FILE}
  DO "gpg --no-default-keyring --keyring $TMP_KEYRING --import $PIP_KEY_FILE" "0"
  DO "gpg --no-default-keyring --keyring $TMP_KEYRING --verify $PKG_VERIFY" "0"

  DO "tar xzf ${BUILD_DIR}/${PIP_PKG}" "0"
  DO "cd pip-*" "0"

  echo "Installing the latest pip"
  if [ "${ASSUME_YES}" -eq "0" ]; then
    echo "WARNING this will overwrite the pip that you currently have installed and all python dependencies will be installed via pip."
    ANSWER=''
    until [[ $ANSWER = [yn] ]]; do
      read -r -p "Do you wish to continue? [y/n]" ANSWER
      echo
    done
    if [[ $ANSWER != 'y' ]]; then
      echo "Cannot proceed"
      exit
    fi
  fi
  DO "python setup.py install" "0"
fi

DO "wget https://raw.github.com/globaleaks/Tor2web-3.0/master/requirements.txt" "0"
PIP_DEPS=`cat ${BUILD_DIR}/requirements.txt`

for PIP_DEP in ${PIP_DEPS}; do
  DO "pip install ${PIP_DEP}" "0"
done

DO "gpg --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 0x24045008" "0"
# TODO: This should be fixed, because executing this command
# over DO() command escape the pipe character
gpg --export B353922AE4457748559E777832E6792624045008 | apt-key add -

echo "Fetching Deb package from remote repository http://deb.globaleaks.org/"
add_repository 'deb http://deb.globaleaks.org/ unstable/'
DO "apt-get update -y" "0"
DO "apt-get install tor2web -y" "0"

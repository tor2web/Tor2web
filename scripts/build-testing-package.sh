#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [[ $EUID -eq 0 ]]; then
  echo "Error: ${SCRIPTNAME} must not be excecuted by root"
  exit 1
fi

usage()
{
cat << EOF
usage: ./${SCRIPTNAME} options

OPTIONS:
   -h   Show this message
   -v   To build a specific tor2web version
   -y   Assume 'yes' to all questions

EOF
}

SIGN=1
AUTOYES=0
while getopts “hv:y” OPTION
do
  case $OPTION in
    h)
      usage
      exit 1
      ;;
    v)
      TAG=$OPTARG
      ;;
    y)
      AUTOYES=1
      ;;
    ?)
      usage
      exit
      ;;
    esac
done

echo "[+] Setupping Tor2web build environments"

if [ ! -f ${DIR}/.environment_setupped ]; then
    sudo -i apt-get install python-dev build-essential python-virtualenv python-pip python-stdeb devscripts -y
    touch ${DIR}/.environment_setupped
fi

if [ $AUTOYES ]; then
  OPTS="-y"
else
  OPTS=""
fi

if test $TAG; then
  ${DIR}/build-tor2web.sh -v $TAG -n $OPTS
else
  ${DIR}/build-tor2web.sh -n $OPTS
fi

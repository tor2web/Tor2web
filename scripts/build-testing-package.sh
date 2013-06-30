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

EOF
}

SIGN=1
while getopts “hc:b:” OPTION
do
  case $OPTION in
    h)
      usage
      exit 1
      ;;
    v)
      TAG=$OPTARG
      ;;
    ?)
      usage
      exit
      ;;
    esac
done

if test $TAG; then
  ${DIR}/build-tor2web.sh -v $TAG
else
  ${DIR}/build-tor2web.sh
fi

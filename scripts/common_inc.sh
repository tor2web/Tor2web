#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SCRIPTNAME="$(basename "$(test -L "$0" && readlink "$0" || echo "$0")")"

if [[ $EUID -eq 0 ]]; then
  echo "Error: ${SCRIPTNAME} must not be excecuted by root"
  exit 1
fi

T2W_GIT_REPO="https://github.com/globaleaks/Tor2web-3.0.git"

REPO_DIR='/data/deb'
WEB_DIR='/data/website/builds'

if test ${GLOBALEAKS_BUILD_ENV}; then
  BUILD_DIR=${GLOBALEAKS_BUILD_ENV}
  mkdir -p ${BUILD_DIR}
else
  BUILD_DIR=$( readlink -m ${DIR}/../../)
fi

cd ${BUILD_DIR}

T2W_DIR=$( readlink -m ${BUILD_DIR}/Tor2web-3.0)
T2W_TMP=${T2W_DIR}_tmp
T2W_BUILD=$( readlink -m ${T2W_TMP}/Tor2web-3.0_build)

echo "Running command ${SCRIPTNAME} $*"
echo "Build directory used: ${BUILD_DIR}"
echo "To override this do: 'GLOBALEAKS_BUILD_ENV=/what/you/want && export GLOBALEAKS_BUILD_ENV'"

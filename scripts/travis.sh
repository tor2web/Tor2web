#!/bin/bash

set -e

sudo apt-get update -y

sudo apt-get install -y debhelper devscripts dh-apparmor dh-python python python-pip python-setuptools python-sphinx

rm -rf requirements.txt
ln -s requirements/requirements-xenial.txt requirements.txt
pip install -r requirements.txt

./scripts/build.sh -d xenial -t $TRAVIS_COMMIT -n

#!/bin/bash

set -e

sudo apt-get update -y

sudo apt-get install -y debhelper devscripts dh-apparmor dh-python python python-pip python-setuptools python-sphinx

pip install -r requirements.txt
pip install coverage coveralls

coverage run setup.py test # tests still to be implemented
coveralls || true

./scripts/build.sh -d trusty -t $TRAVIS_COMMIT -n

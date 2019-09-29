#!/bin/bash

set -e

sudo apt-get update -y

sudo apt-get install -y debhelper devscripts dh-apparmor dh-python dput fakeroot python3 python3-pip python3-setuptools python3-sphinx

pip3 install -r requirements.txt

./scripts/build.sh -d buster -t $TRAVIS_COMMIT -n

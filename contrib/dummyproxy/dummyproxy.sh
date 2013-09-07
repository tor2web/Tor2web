#!/bin/sh -e

# Simple TCP Proxy implemented using Netcat (nc)
#
# The proxy is intended to be used in conjuntion
# with Tor2web configured with a dummyproxy circuit.
# 
# Typical scenario involves a setup like this:
#
#      t2w -> dummyproxy -> dummyproxy -> dummyproxy -> HTTP/HTTPS application server
#
# Author: Giovanni Pellerano <evilaliv3@globaleaks.org>

if [ $# != 3 ]
then
    echo "usage: $0 <src-port> <dst-host> <dst-port>"
    echo ""
    echo "\t example: ./dummyproxy.sh 80 127.0.0.1 8080"
    exit 0
fi

TMP=`mktemp -d`
DATA=$TMP/data
mkfifo -m 0600 "$DATA"

trap 'rm -rf "$DATA"' EXIT

while [ 1 ]; do
    nc -l "$1" < "$DATA" | nc "$2" "$3" > "$DATA"
done

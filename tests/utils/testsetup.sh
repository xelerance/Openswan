#!/bin/sh

# this script sets up the travis cache.

mkdir -p $HOME/stuff/sbin
BUILDTOP=$(cd $HOME/stuff; pwd)

if [ ! -x $HOME/stuff/sbin/tcpdump ]
then
    cd ${BUILDTOP}
    curl -s http://www.ca.tcpdump.org/release/libpcap-1.7.4.tar.gz | tar xzf -
    curl -s http://www.ca.tcpdump.org/release/tcpdump-4.7.4.tar.gz | tar xzf -
    mkdir -p host/libpcap-1.7.4 && (cd host/libpcap-1.7.4 && ../../libpcap-1.7.4/configure --prefix=${BUILDTOP} && make && make install)
    mkdir -p host/tcpdump-4.7.4 && (cd host/tcpdump-4.7.4 && ../../tcpdump-4.7.4/configure --prefix=${BUILDTOP} && make && make install)
fi

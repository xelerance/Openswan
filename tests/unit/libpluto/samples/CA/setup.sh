#!/bin/sh

export rootca=$(pwd)/root
export cadir=$(pwd)
export format=pem
export cfgdir=${cadir}

export pass="-pass pass:openswan-unit-tests"
export passin="-passin pass:openswan-unit-tests"
export sn=8   # how many digits for serial number

# set things up if never used before
mkdir -p $cadir/certs
mkdir -p $rootca
(cd $rootca
mkdir -p certs crl csr newcerts private
chmod 700 private
touch index.txt index.txt.attr
if [ ! -f serial ]; then echo 00 >serial; fi
)

# edit these to suit
countryName="/C=CA"
stateOrProvinceName="/ST=ON"
localityName="/L=Ottawa"
organizationName="/O=Xelerance"
organizationalUnitName=

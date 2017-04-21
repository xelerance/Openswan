#!/bin/sh

# this script generates a series of self-signed certificates for moon and dave.
# These are used in the lp52-55 series of tests.

set -x
for HOST in moon dave
do
    openssl genrsa -out private/${HOST}Key.pem 2048
    (echo "CA"; echo "Ontario"; echo "Ottawa"; echo "Xelerance Corporation"; echo "Testing Devision"; echo $HOST.openswan.org; echo "testing@xelerance.com"; echo; echo; echo; echo ) | openssl req -x509 -days 1024 -in private/$HOST.req -key private/${HOST}Key.pem -out certs/${HOST}Cert.pem
done


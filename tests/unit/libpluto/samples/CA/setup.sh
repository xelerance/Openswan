#!/bin/sh

echo self-signed root CA.
openssl genrsa -out rootCApriv.pem 2048
#echo TWO
#openssl req -new -sha256 -key rootCApriv.pem -out rootCApriv.req
echo THREE
openssl req -x509 -key rootCApriv.pem -out rootCA.pem -days 1024



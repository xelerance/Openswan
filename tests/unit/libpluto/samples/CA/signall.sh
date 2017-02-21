#!/bin/sh

ROOT=../
for HOSTNAME in dave carol moon
do
    CRT=${HOSTNAME}cert/certs/${HOSTNAME}Cert.pem
    KEY=${HOSTNAME}cert/private/${HOSTNAME}Key.pem
    REQ=${HOSTNAME}cert/private/${HOSTNAME}Key.req

    openssl x509 -CAcreateserial -req -in ${REQ} -CA rootCA.pem -CAkey rootCApriv.pem -out ${CRT} -days 1024

done


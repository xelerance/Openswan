#!/bin/sh

openssl x509 -in ../../x509/certs/west.crt -outform der -out westcert.der

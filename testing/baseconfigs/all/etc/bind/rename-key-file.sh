#!/bin/sh

for i in `/bin/ls K* | grep -v +12345`
do              
  nf=`echo $i | sed -e 's/\(K.*\)+001+[0-9]*\(\..*\)/\1+001+12345\2/'`
  mv $i $nf
done

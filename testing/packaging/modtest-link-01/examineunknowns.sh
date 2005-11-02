#!/bin/sh

mod=OUTPUT${KLIPS_MODULE}/module/ipsec.o

nm -u $mod >OUTPUT/unknowns.txt

if diff unknowns.txt OUTPUT/unknowns.txt
then
    success=true
else
    success=false
fi


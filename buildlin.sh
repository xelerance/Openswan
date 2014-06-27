#!/bin/sh

if [ ! -f /usr/include/gmp.h ];
then
    echo You need to install libgmp-dev.
    echo "    apt-get install libgmp-dev"
    echo "or  yum install gmp-dev"
    exit 1
fi

if [ -n "$WERROR" ];
then
    echo "Warning, you have \$WERROR set. I assume you are a developer"
    sleep 5
fi    

make USE_OBJDIR=true programs

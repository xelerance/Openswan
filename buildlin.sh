#!/bin/sh

fail=false

if [ ! -f /usr/include/gmp.h ];
then
    echo You need to install libgmp-dev.
    echo "    apt-get install libgmp-dev"
    echo "or  yum install gmp-dev"
    echo
    fail=true
fi
if [ ! -f /usr/bin/bison ];
then
    echo You need to install bison.
    echo "    apt-get install bison"
    echo "or  yum install bison"
    fail=true
fi

if [ ! -f /usr/bin/flex ];
then
    echo You need to install flex.
    echo "    apt-get install flex"
    echo "or  yum install flex"
    fail=true
fi

if [ ! -f /usr/bin/make ];
then
    echo You need to install make.
    echo "    apt-get install make"
    echo "or  yum install make"
    fail=true
fi

if $fail;
then 
   exit 1;
fi

if [ -n "$WERROR" ];
then
    echo "Warning, you have \$WERROR set. I assume you are a developer"
    sleep 5
fi    

make USE_OBJDIR=true programs

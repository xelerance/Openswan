all: programs

EXTRAFLAGS+=-I..
EXTRAFLAGS+=-I../../libpluto
EXTRAFLAGS+=-I../../libpluto/lp12-parentR2
EXTRAFLAGS+=-DSAMPLEDIR=\"${SAMPLEDIR}\"
include ../../libpluto/lp12-parentR2/Makefile

EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_crypto.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_rsa.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_psk.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/kernel.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/kernel_forces.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/signatures.o



all: programs

EXTRAFLAGS+=-I..
EXTRAFLAGS+=-I../../libpluto
EXTRAFLAGS+=-I../../libpluto/lp13-parentI3
include ../../libpluto/lp13-parentI3/Makefile
EXTRAFLAGS+=-DSAMPLEDIR=\"${SAMPLEDIR}\"

EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_crypto.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_rsa.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_psk.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/kernel.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/kernel_forces.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/signatures.o



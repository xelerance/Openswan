OPENSWANSRCDIR?=$(shell cd ../../..; pwd)

UNITTEST=rsa-v2
CFLAGS=-DUSE_3DES -I${OPENSWANSRCDIR}/programs/pluto
CFLAGS+=-I${OPENSWANSRCDIR}/testing/lib/libpluto

SOURCES=rsa-v2.c packetsI1.c 
SOURCES+=${OPENSWANSRCDIR}/programs/pluto/ikev2_rsa.c

PROGLIBS=${PLUTOLIB}
OBJS+=${OBJDIRTOP}/programs/pluto/crypto.o
OBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_twofish.o
OBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_serpent.o
OBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_aes.o
OBJS+=${OBJDIRTOP}/programs/pluto/ike_alg.o
OBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_blowfish.o
OBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_sha2.o
OBJS+=${OBJDIRTOP}/programs/pluto/keys.o
OBJS+=${OBJDIRTOP}/programs/pluto/defs.o
EXTRALIBS+=${PLUTOLIB} ${CRYPTOLIBS} ${WHACKLIB}

PROGRAM=rsa-v2

programs checkprograms: ${UNITTEST}
	@true

include ${OPENSWANSRCDIR}/programs/Makefile.program

packetsI1.c: ../../lib/libpluto/lib-parentI1/parentI1.pcap
	../../utils/pcap2skb/pcap2skb $< >packetsI1.c

rsa-v2.o: ${SOURCES}






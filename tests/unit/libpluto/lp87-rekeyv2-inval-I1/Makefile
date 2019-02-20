FILTER_OUT_EXTRAOBJS = %/ipsec_doi.o
EXTRAOBJS += weak_ipsec_doi.o

include ../lp13-parentI3/Makefile

weak_ipsec_doi.o: ${OBJDIRTOP}/programs/pluto/ipsec_doi.o
	objcopy --weaken-symbol=unpack_nonce $< $@

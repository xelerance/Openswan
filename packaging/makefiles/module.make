include ${OPENSWANSRCDIR}/Makefile.inc

version.c:	${LIBOPENSWANDIR}/version.in.c ${OPENSWANSRCDIR}/Makefile.ver
	sed '/"/s/xxx/$(IPSECVERSION)/' ${LIBOPENSWANDIR}/version.in.c >$@

KLIPS_TOP=${OPENSWANSRCDIR}/linux
VPATH+=${KLIPSSRC}
include ${KLIPSSRC}/Makefile

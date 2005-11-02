# I really am not happy about using symlinks to make this work.
#
# I think that there should be a better way to do this.
# see module26.sh in packaging/makefiles
#


ifndef OPENSWANSRCDIR
$(error You Must set OPENSWANSRCDIR)
endif

include ${OPENSWANSRCDIR}/Makefile.inc

KLIPS_TOP := ${OPENSWANSRCDIR}/linux

# include file with .h-style macros that would otherwise be created by
# config. Must occur before other includes.
ifneq ($(strip $(MODULE_DEF_INCLUDE)),)
EXTRA_CFLAGS += -include ${MODULE_DEF_INCLUDE}
endif

EXTRA_CFLAGS += -I${KLIPS_TOP}/include

# build version.c using version number from Makefile.ver
${BUILDDIR}/version.c:	${KLIPSSRC}/version.in.c ${OPENSWANSRCDIR}/Makefile.ver
	sed '/"/s/xxx/$(IPSECVERSION)/' ${KLIPSSRC}/version.in.c >$@

${BUILDDIR}/%.c : ${KLIPSSRC}/%.c
	ln -s -f $< $@

${BUILDDIR}/%.h : ${KLIPSSRC}/%.h
	ln -s -f $< $@

${BUILDDIR}/%.c : ${KLIPSSRC}/des/%.c
	ln -s -f $< $@

${BUILDDIR}/%.S : ${KLIPSSRC}/des/%.S
	ln -s -f $< $@

${BUILDDIR}/%.c : ${KLIPSSRC}/aes/%.c
	ln -s -f $< $@

${BUILDDIR}/%.c : ${KLIPSSRC}/alg/%.c
	ln -s -f $< $@

.PRECIOUS: ${BUILDDIR}/%.c ${BUILDDIR}/%.h

# I'm not fixing this in a better way, because we should use the
# in-kernel zlib!
${BUILDDIR}/deflate.c: ${BUILDDIR}/deflate.h
${BUILDDIR}/infblock.c: ${BUILDDIR}/infblock.h ${BUILDDIR}/inftrees.h
${BUILDDIR}/infblock.c: ${BUILDDIR}/infcodes.h  ${BUILDDIR}/infutil.h
${BUILDDIR}/infcodes.c: ${BUILDDIR}/inffast.h
${BUILDDIR}/inftrees.c: ${BUILDDIR}/inffixed.h
${BUILDDIR}/trees.c: ${BUILDDIR}/trees.h

include ${OPENSWANSRCDIR}/packaging/makefiles/module.defs 
include ${KLIPSSRC}/Makefile.fs2_6

ipsec-obj-$(CONFIG_KLIPS_AH)+= ipsec_ah.o
ipsec-obj-$(CONFIG_KLIPS_ESP)+= ipsec_esp.o
ipsec-obj-$(CONFIG_KLIPS_IPCOMP)+= ipsec_ipcomp.o
ipsec-obj-$(CONFIG_KLIPS_AUTH_HMAC_MD5) += ipsec_md5c.o
ipsec-obj-$(CONFIG_KLIPS_AUTH_HMAC_SHA1) += ipsec_sha1.o

# AH, if you really think you need it.
ipsec-obj-$(CONFIG_KLIPS_AH) += ipsec_ah.o

ipsec-obj-$(CONFIG_KLIPS_ALG)  += ipsec_alg.o

#ipsec-obj-$(CONFIG_KLIPS_ENC_3DES) += des/
#ipsec-obj-$(CONFIG_KLIPS_ENC_AES)  += aes/

ipsec-obj-$(CONFIG_KLIPS_ENC_CRYPTOAPI) += ipsec_alg_cryptoapi.o

obj-m := ipsec.o

ipsec-objs := ${base-klips-objs} ${base-ipcomp-objs} ${ipsec-obj-m} ${ipsec-obj-y}

# XXX and it seems that recursing into subdirs is a PITA for out-of-kernel
# module builds. At least, it never occurs for me.
aes-obj-${CONFIG_KLIPS_ENC_AES} += aes/ipsec_alg_aes.o
aes-obj-${CONFIG_KLIPS_ENC_AES} += aes/aes_xcbc_mac.o
aes-obj-${CONFIG_KLIPS_ENC_AES} += aes/aes_cbc.o

ifeq ($(strip ${SUBARCH}),)
SUBARCH:=${ARCH}
endif

ifeq (${SUBARCH},i386)
aes-obj-${CONFIG_KLIPS_ENC_AES} += aes/aes-i586.o
else
aes-obj-${CONFIG_KLIPS_ENC_AES} += aes/aes.o
endif

des-obj-$(CONFIG_KLIPS_ENC_3DES) += cbc_enc.o
des-obj-$(CONFIG_KLIPS_ENC_3DES) += ecb_enc.o
des-obj-$(CONFIG_KLIPS_ENC_3DES) += set_key.o

ifeq ($(strip ${SUBARCH}),)
SUBARCH:=${ARCH}
endif

# XXX and I still can't get the assembler to get invoked at the right time.
ifeq (${SUBARCH},i386)
des-obj-$(CONFIG_KLIPS_ENC_3DES) += dx86unix.o
else
des-obj-$(CONFIG_KLIPS_ENC_3DES) += des_enc.o
endif

ipsec-objs += ${des-obj-m} ${aes-obj-m}




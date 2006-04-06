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
EXTRA_CFLAGS += -I${KLIPSSRC}/.

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

MODULE26=true
include ${OPENSWANSRCDIR}/packaging/makefiles/module.defs 
ifneq ($(strip $(MODULE_DEFCONFIG)),)
include ${MODULE_DEFCONFIG}
endif
include ${KLIPSSRC}/Makefile.fs2_6


# XXX and it seems that recursing into subdirs is a PITA for out-of-kernel
# module builds. At least, it never occurs for me.
aes-obj-${CONFIG_KLIPS_ENC_AES} += aes/ipsec_alg_aes.o
aes-obj-${CONFIG_KLIPS_ENC_AES} += aes/aes_xcbc_mac.o
aes-obj-${CONFIG_KLIPS_ENC_AES} += aes/aes_cbc.o

ifeq ($(strip ${SUBARCH}),)
SUBARCH:=${ARCH}
endif

# the assembly version expects frame pointers, which are
# optional in many kernel builds. If you want speed, you should
# probably use cryptoapi code instead.
USEASSEMBLY=${SUBARCH}${CONFIG_FRAME_POINTER}
ifeq (${USEASSEMBLY},i386y)
aes-obj-${CONFIG_KLIPS_ENC_AES} += aes/aes-i586.o
des-obj-$(CONFIG_KLIPS_ENC_3DES) += dx86unix.o
else
aes-obj-${CONFIG_KLIPS_ENC_AES} += aes/aes.o
des-obj-$(CONFIG_KLIPS_ENC_3DES) += des_enc.o
endif

des-obj-$(CONFIG_KLIPS_ENC_3DES) += cbc_enc.o
des-obj-$(CONFIG_KLIPS_ENC_3DES) += ipsec_alg_3des.o
des-obj-$(CONFIG_KLIPS_ENC_3DES) += ecb_enc.o
des-obj-$(CONFIG_KLIPS_ENC_3DES) += set_key.o

ipsec-y += ${des-obj-y} ${aes-obj-y} ${des-obj-m} ${aes-obj-m}






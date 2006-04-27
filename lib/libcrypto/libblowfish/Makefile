OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver


BF_ASM-i586 := bf-586.pl
BF_ASM-i686 := bf-686.pl
BF_CORE_OBJ := bf_enc.o
BH_CORE_SRC := bf_enc.c

#ASM-$(ARCH_ASM):=1
#ASM_X86:=$(ASM-i586)$(ASM-i686)
#ifneq ($(strip $(ASM_X86)),)
#BF_CORE_OBJ:= asm/bx86-elf.o
#BF_CORE_ASM:= asm/$(BF_ASM-$(ARCH_ASM))
#BF_CORE_SRC:= 
#endif

BASE_SRCS=bf_skey.c
SRCS=${BASE_SRCS} ${BF_CORE_SRC}

OBJS=${BASE_SRCS:.c=.o} ${BF_CORE_OBJ}

ONEFILE=bf_skey.c
LIBRARY=crypto/libblowfish
LIB=libblowfish.a
INCLUDES+=-I${srcdir}../include

include ${srcdir}../../Makefile.library


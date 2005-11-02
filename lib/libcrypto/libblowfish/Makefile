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

HDRS=	

VPATH += ${SRCDIR}

LIB=libblowfish.a

# Original flags
CFLAGS=-I. -I${SRCDIR} -I${OPENSWANSRCDIR} ${PORTINCLUDE}
CFLAGS+=$(USERCOMPILE)
CFLAGS+=-O3 -fomit-frame-pointer -Wall  -Wcast-qual 
CFLAGS+= -Wmissing-prototypes
CFLAGS+= -Wpointer-arith
CFLAGS+= -Wcast-qual
#CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wstrict-prototypes
#CFLAGS+= -pedantic
#CFLAGS+= -W
#CFLAGS+= -Wwrite-strings
CFLAGS+= -Wbad-function-cast 

.PHONY:	all install clean check depend checkprograms

all:	$(LIB) 
programs: $(LIB)

asm/bx86unix.cpp: asm/$(BF_ASM) ../perlasm/x86asm.pl ../perlasm/cbc.pl
	(cd asm; $(PERL) $(BF_ASM) cpp $(PROCESSOR) >bx86unix.cpp)

# elf
asm/bx86-elf.o: asm/bx86unix.cpp
	$(CPP) -DELF -x c asm/bx86unix.cpp | as -o asm/bx86-elf.o

install install_file_list:
	@exit 0

$(LIB):	$(OBJS)
	$(AR) crs $(LIB) $(OBJS)

$(OBJS):	$(HDRS)

clean:
	rm -f $(LIB) *.o try* core *.core $(EXTHDRS) $(EXTLIBS) version.c

check:
	echo no checks in lib right now.

depend:
	makedepend -Y -- $(CFLAGS) -- $(SRCS)

checkprograms:

# DO NOT DELETE THIS LINE -- make depend depends on it.

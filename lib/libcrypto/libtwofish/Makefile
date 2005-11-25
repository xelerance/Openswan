OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

CFLAGS=${USERCOMPILE} $(EXTRA_CFLAGS)
INC=-I${srcdir}../include ${PORTINCLUDE}

LIBOBJ=twofish.o twofish_cbc.o
BLIB=libtwofish.a

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) -c $< -o $@

$(BLIB): $(LIBOBJ)
	$(AR) $(ARFLAGS) $(BLIB) $(LIBOBJ)

programs: $(BLIB)

install:
	@exit 0

test: test_main.o $(BLIB)
	$(CC) -o $@ $^ 

clean:
	rm -f *.[oa] core $(TARGET) test

check:
        echo no checks in lib right now.



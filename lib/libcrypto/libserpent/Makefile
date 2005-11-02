OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

CFLAGS=${USERCOMPILE} $(EXTRA_CFLAGS)
INC=-I${srcdir}../include ${PORTINCLUDE}

LIBOBJ=serpent.o serpent_cbc.o
BLIB=libserpent.a

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) -c $< -o $@

$(BLIB): $(LIBOBJ)
	/bin/rm -f $(BLIB)
	${AR} cr $(BLIB) $(LIBOBJ)

programs: $(BLIB)

install:
	@exit 0

test: test_main.o $(BLIB)
	$(CC) -o $@ $^ 

clean:
	rm -f *.[oa] core $(TARGET) test

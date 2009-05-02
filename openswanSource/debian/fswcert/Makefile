###################################################
# Adjust SSLDIR before make ...
SSLDIR=/usr

# Adjust IPSECDIR before make install ...
IPSECDIR=/usr/local/lib/ipsec

###################################################

VERSION = 0.6

CC = gcc
CFLAGS = -Wall -O2 -DVERSION=\"$(VERSION)\" -I$(SSLDIR)/include
LDFLAGS = -L$(SSLDIR)/lib
LDLIBS = -lcrypto

DISTFILES=Makefile README CHANGES fswcert.c _confread.patch

all : fswcert

fswcert : fswcert.o
	$(CC) $(LDFLAGS) -o fswcert fswcert.o $(LDLIBS)

fswcert.o: fswcert.c
	$(CC) $(CFLAGS) -c fswcert.c

clean :
	rm -f fswcert fswcert.o

dist :
	DIR=$$(pwd | sed -e 's,^.*/\([^/]*\)$$,\1,') ; \
	cd .. ; \
	tar cvfz $$DIR-$(VERSION).tar.gz $(DISTFILES:%=$$DIR/%)

install :
	mkdir -p $(IPSECDIR)
	install --strip fswcert $(IPSECDIR)
	mkdir -pm 700 /etc/ipsec.d/cacerts
	mkdir -pm 700 /etc/ipsec.d/crls

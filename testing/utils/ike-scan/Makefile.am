# $Id: Makefile.am,v 1.1.1.1 2005/01/13 18:45:12 mcr Exp $
# Process this file with automake to produce Makefile.in
#
AM_CPPFLAGS = -DIKEDATADIR=\"$(pkgdatadir)\"
#
dist_pkgdata_DATA = ike-backoff-patterns ike-vendor-ids psk-crack-dictionary
bin_PROGRAMS = ike-scan psk-crack
check_PROGRAMS = check-sizes check-hash
dist_check_SCRIPTS = check-run1 check-run2 check-run3 check-psk-crack-1 check-psk-crack-2
dist_man_MANS = ike-scan.1 psk-crack.1
ike_scan_SOURCES = ike-scan.c ike-scan.h error.c isakmp.c isakmp.h wrappers.c utils.c
ike_scan_LDADD = $(LIBOBJS)
psk_crack_SOURCES = psk-crack.c ike-scan.h error.c wrappers.c utils.c
psk_crack_LDADD = $(LIBOBJS)
check_sizes_SOURCES = check-sizes.c error.c ike-scan.h
check_hash_SOURCES = check-hash.c error.c utils.c wrappers.c ike-scan.h
check_hash_LDADD = $(LIBOBJS)
TESTS = $(check_PROGRAMS) $(dist_check_SCRIPTS)
EXTRA_DIST = udp-backoff-fingerprinting-paper.txt README-WIN32

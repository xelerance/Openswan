/* whack communicating routines -- store messages to disk
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2015 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef HOST_NAME_MAX   /* POSIX 1003.1-2001 says <unistd.h> defines this */
# define HOST_NAME_MAX  255 /* upper bound, according to SUSv2 */
#endif
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <fcntl.h>
#include <limits.h>  /* for PATH_MAX */
#include <time.h>

#include <openswan.h>
#include "openswan/pfkeyv2.h"

#include "pluto/defs.h"
#include "oswconf.h"
#include "constants.h"
#include "whack.h"
#include "oswlog.h"
#include "pluto/whackfile.h"

static char whackrecordname[PATH_MAX];
static FILE *whackrecordfile=NULL;

void close_whackrecordfile(void)
{
  if(whackrecordfile) {
    DBG(DBG_CONTROL
        , DBG_log("stopped recording whack messages to %s\n"
                  , whackrecordname));
    fclose(whackrecordfile);
  }
  whackrecordfile = NULL;
}

/*
 * writes out 64-bit time, even though we actually
 * only have 32-bit time here. Assumes that time will
 * be written out in big-endian format, with MSB word
 * being first.
 *
 */
bool writewhackrecord(char *buf, int buflen)
{
    u_int32_t header[3];
    time_t n;

    /* round up buffer length */
    int abuflen = (buflen + 3) & ~0x3;

    /* bail if we aren't writing anything */
    if(whackrecordfile == NULL) return TRUE;

    header[0]=buflen + sizeof(u_int32_t)*3;
    header[1]=0;
    time(&n);
    header[2]=n;

    DBG(DBG_CONTROL
	, DBG_log("writewhack record buflen: %u abuflen: %u\n", header[0], abuflen));

    if(fwrite(header, sizeof(u_int32_t)*3, 1, whackrecordfile) < 1) {
	DBG_log("writewhackrecord: fwrite error when writing header");
    }

    if(fwrite(buf, abuflen, 1, whackrecordfile) < 1) {
	DBG_log("writewhackrecord: fwrite error when writing buf");
    }
    fflush(whackrecordfile);

    return TRUE;
}


/*
 * we write out an empty record with the right WHACK magic.
 * this should permit a later mechanism to figure out the
 * endianess of the file, since we will get records from
 * other systems for analysis eventually.
 */
bool openwhackrecordfile(char *file)
{
    char when[256];
    char FQDN[HOST_NAME_MAX + 1];
    u_int32_t magic;
    struct tm tm1, *tm;
    time_t n;

    strcpy(FQDN, "unknown host");
    gethostname(FQDN, sizeof(FQDN));

    strncpy(whackrecordname, file, sizeof(whackrecordname));
    whackrecordfile = fopen(whackrecordname, "w");
    if(whackrecordfile==NULL) {
	openswan_log("Failed to open whack record file: '%s'\n"
		     , whackrecordname);
	return FALSE;
    }

    time(&n);
    tm = localtime_r(&n, &tm1);
    strftime(when, sizeof(when), "%F %T", tm);

    fprintf(whackrecordfile, "#!-pluto-whack-file- recorded on %s on %s\n",
	    FQDN, when);

    magic = WHACK_BASIC_MAGIC;
    writewhackrecord((char *)&magic, 4);
    fflush(whackrecordfile);

    DBG(DBG_CONTROL
	, DBG_log("writewhack started recording whack messages to %s\n"
		  , whackrecordname));
    return TRUE;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

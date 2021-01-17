#include <stdio.h>
#include <stdlib.h>
#include "constants.h"
#include "oswalloc.h"
#include "whack.h"
#include "oswlog.h"
#include "readwhackmsg.h"

/* returns number of messages processed */
int readwhackmsg(char *infile)
{
    int   iocount;
    int   msgcount=0;
    FILE *record;
    char  b1[8192];
    u_int32_t plen;

    if((record = fopen(infile, "r")) == NULL) {
	    perror(infile);
	    exit(9);
    }

    plen=0;
    while((iocount=fread(&plen, 4, 1, record))==1) {
	u_int32_t a[2];
	err_t ugh = NULL;
	struct whack_message m1;
	size_t abuflen;

        DBG_log("processing whack message of size: %u", plen);
        /* time stamp, MSB word first of time */
	if(fread(&a, 4, 2, record) == 0) /* eat time stamp */
		DBG(DBG_PARSING, DBG_log( "readwhackmsg: fread returned 0"));

	/* account for this header we just consumed */
        /* 4 bytes of plen,  8 bytes of time stamp  */
	plen -= 12;

	/* round up to multiple of 4 */
	abuflen = (plen + 3) & ~0x3;

	if(abuflen > sizeof(m1) || abuflen < plen) {
	    fprintf(stderr, "whackmsg file has too big a record=%zu > %zu\n"
		    , abuflen, sizeof(m1));
	    fclose(record);
	    exit(6);
	}

	if((iocount=fread(&m1, abuflen, 1, record)) != 1) {
	    if(feof(record)) break;
	    perror(infile);
	    fclose(record);
	    exit(5);
	}

	if(plen <= 4 || iocount != 1) {
	    /* empty message */
	    continue;
	}

        /* if it's a basic command, skip it */
        if(m1.magic == WHACK_BASIC_MAGIC) continue;

        if(m1.magic != WHACK_MAGIC) {
            fprintf(stderr, "this is whack message from different version: me %08lx file: %08lx\n",
                    (unsigned long)WHACK_MAGIC, (unsigned long)m1.magic);
            if((m1.magic & 0x80000000) != WHACK_MAGIC_INTVALUE) {
                unsigned int bit64 = (m1.magic & 0x80000000);
                unsigned int bits = bit64 ? 64 : 32;
                fprintf(stderr, "this is whack message from a %u-bit system, this system is %lu\n",
                        bits, (unsigned long)sizeof(void *)*8);
            }
            continue;
        }

        fprintf(stderr, "processing whack msg time: %u size: %d\n",
                a[1],plen);

#if 0
        fprintf(stderr, "m1: %p next: %p roof: %p\n",
                &m1, wp.str_next, wp.str_roof);
#endif
        if ((ugh = deserialize_whack_msg(&m1, plen)) != NULL)
        {
            fprintf(stderr, "failed to parse whack msg: %s\n", ugh);
	    continue;
	}

	/*
	 * okay, we have plen bytes in b1, so turn it into a whack
	 * message, and call whack_handle.
	 */
	whack_process(NULL_FD, m1);
        msgcount++;
    }

    if(iocount != 0 || !feof(record)) {
	fclose(record);
	perror(infile);
    }
    //fclose(record);

    return msgcount;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

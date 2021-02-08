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
    u_char  b1[8192];

    if((record = fopen(infile, "r")) == NULL) {
	    perror(infile);
	    exit(9);
    }

    while((iocount=fread(b1, 1, sizeof(b1), record)) > 0) {
	err_t ugh = NULL;
	struct whack_message m1;
        u_char *where = b1;
        size_t  plen  = 0;

        DBG_log("processing whack message of size: %u", iocount);

        memset(&m1, 0, sizeof(m1));
        while(iocount > 0) {
            plen = iocount;
            if ((ugh = whack_cbor_decode_msg(&m1, where, &plen)) != NULL)
                {
                    fprintf(stderr, "failed to parse whack msg: %s\n", ugh);
                    return msgcount;
                }

            /*
             * okay, we have plen bytes in b1, so turn it into a whack
             * message, and call whack_handle.
             */
            whack_process(NULL_FD, m1);
            msgcount++;

            where   += plen;
            iocount -= plen;
        }
    }

    if(iocount != 0 || !feof(record)) {
	fclose(record);
	perror(infile);
    }

    return msgcount;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

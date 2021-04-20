#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH 1
#define PRINT_SA_DEBUG 1
#define DEBUG 1
#include <stdlib.h>

#include "constants.h"
#include "defs.h"
#include "hexdump.c"
#include "sysdep.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "demux.h"
#include "pluto/state.h"
#include "pluto/ike_alg.h"
#include "pluto/crypto.h"
#include "pluto_crypt.h"

#include "../../libpluto/seam_gi_sha256_group14.c"

const char *progname;

void exit_tool(int stat)
{
    exit(stat);
}

void pluto_crypto_copyseamchunk(wire_chunk_t *spacetrack
			    , unsigned char *space
			    , wire_chunk_t *new
			    , struct seam_chunk data)
{
    /* allocate some space first */
    pluto_crypto_allocchunk(spacetrack, new, data.len);

    /* copy data into it */
    memcpy(space_chunk_ptr(space, new), data.ptr, data.len);
}

int main(int argc, char *argv[])
{
    int i;
    err_t e = NULL;
    const struct ike_integ_desc *sha256;
    struct pluto_crypto_req r;
    struct pcr_skeyid_q *dhq;

    progname = argv[0];
    leak_detective=1;
    tool_init_log();
    init_crypto();

    pcr_init(&r, pcr_compute_dh_v2, pcim_known_crypto);
    dhq = &r.pcr_d.dhq;
    /* convert appropriate data to dhq */
    dhq->auth         = 1; //st->st_oakley.auth;
    dhq->v2_prf       = SS(prf);
    dhq->v2_integ     = SS(integ);
    dhq->oakley_group = SS(oakleygroup);
    dhq->init         = TRUE;  /* initiator/ responder */
    dhq->keysize      = 16;    /* AES128 */

    passert(r.pcr_d.dhq.oakley_group != 0);

    pluto_crypto_copyseamchunk(&dhq->thespace, dhq->space, &dhq->ni,  SS(ni));
    pluto_crypto_copyseamchunk(&dhq->thespace, dhq->space, &dhq->nr,  SS(nr));
    pluto_crypto_copyseamchunk(&dhq->thespace, dhq->space, &dhq->gi,  SS(gi));
    pluto_crypto_copyseamchunk(&dhq->thespace, dhq->space, &dhq->gr,  SS(gr));
    pluto_crypto_copyseamchunk(&dhq->thespace, dhq->space
                               , &dhq->secret, SS(secret));

    calc_dh_v2(&r);

    tool_close_log();

    report_leaks();
    exit(0);
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */

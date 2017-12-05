#include "../lp12-parentR2/parentR2_head.c"
#include "seam_natt.c"
#include "seam_debug.c"
#include "seam_host_jamesjohnson.c"
#include "seam_x509.c"
#include "seam_gr_sha1_group14.c"
#include "seam_finish.c"
#include "seam_keys.c"
#include "seam_kernel.c"

#define TESTNAME "deleteChildSA-fromR2"

static void init_local_interface(void)
{
    init_jamesjohnson_interface();
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/jj.secrets"
			       , NULL, NULL);
}

static void init_loaded(void)
{   /* nothing */ }

void recv_pcap_packet2_and_delete(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    static int call_counter = 0;
    struct state *st, *pst;

    call_counter++;
    DBG_log("%s() call %d: enter", __func__, call_counter);

    enable_debugging();
    enable_debugging_on_sa(1);
    enable_debugging_on_sa(2);

    recv_pcap_packet2_with_ke(user, h, bytes);

    /* confirm that SA 1 is in R2 */
    pst = state_with_serialno(1);
    DBG_log("%s() call %d: #%lu st_state=%u\n",
	    __func__, call_counter, pst->st_serialno, pst->st_state);
    passert(pst != NULL);
    passert(pst->st_state == STATE_PARENT_R2);

    /* find st involved */
    st = state_with_serialno(2);
    DBG_log("%s() call %d: #%lu st_state=%u\n",
	    __func__, call_counter, st->st_serialno, st->st_state);
    passert(st != NULL);
    passert(st->st_state == STATE_CHILD_C1_KEYED);

    /* emulate EVENT_SA_EXPIRE */

    DBG_log("%s() call %d: start child delete", __func__, call_counter);

    /* forcing msgid of next message to zero to emulate what Strongswan does */
    pst->st_msgid_nextuse = 0;

    DBG_log("%s() call %d: (parent) st_msgid=%d st_msgid_lastack=%d st_msgid_nextuse=%d st_msgid_lastrecv=%d\n",
	    __func__, call_counter,
	    pst->st_msgid,
	    pst->st_msgid_lastack,
	    pst->st_msgid_nextuse,
	    pst->st_msgid_lastrecv);

    /* now arrange to delete the SA */
    delete_state(st);

    DBG_log("%s() call %d: exit", __func__, call_counter);
}


#ifndef PCAP_INPUT_COUNT
#define PCAP_INPUT_COUNT 2
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet_with_ke,
    recv_pcap_packet2_and_delete,
};
#endif

#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */

#define NAPT_ENABLED 1
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../lp13-parentI3/parentI3_head.c"
#include "seam_mockxfrm.c"
#include "seam_ke.c"
#include "seam_dh_v2.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_ikev1_crypto.c"
#include "seam_ikev2_sendI1.c"
#include "seam_cryptocontinue.c"

static void init_loaded(void)
{
    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE|DBG_NETKEY;
    xfrm_init_base_algorithms();

    passert(esp_aalg[IKEv2_AUTH_HMAC_SHA2_256_128].kernel_alg_info != NULL);
}

#define TESTNAME "cryptoI3"

void delete_cryptographic_continuation(struct state *st) {}

/* this is replicated in the unit test cases since the patching up of the crypto values is case specific */
void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct state *st = NULL;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    st = state_with_serialno(1);
    if(st != NULL) {
        passert(st != NULL);
        st->st_connection->extra_debugging = DBG_CONTROL|DBG_CONTROLMORE|DBG_NETKEY|DBG_PRIVATE|DBG_CRYPT;
    }
    cur_debugging = cur_debugging | DBG_CONTROL|DBG_CONTROLMORE|DBG_NETKEY|DBG_PRIVATE|DBG_CRYPT;

    recv_pcap_packet_gen(user, h, bytes);
    run_continuation(crypto_req);
}

/*
 * this routine accepts the I3 packet, and dumps the resulting SAs
*/
void recv_pcap_I3_process(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct state *st = NULL;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    /* create a socket for a possible whack process that is doing --up */
    int fake_whack_fd = open("/dev/null", O_RDWR);
    passert(fake_whack_fd != -1);

    st = state_with_serialno(2);
    if(st != NULL) {
        passert(st != NULL);
        st->st_connection->extra_debugging = DBG_CONTROL|DBG_CONTROLMORE|DBG_NETKEY|DBG_PRIVATE|DBG_CRYPT;
    }

    recv_pcap_packet(user, h, bytes);

    fprintf(stderr, "now look at the resulting SAs produced.\n");
    show_states_status();
}

#define PCAP_INPUT_COUNT 2
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet,
    recv_pcap_I3_process,
};



#include "../lp13-parentI3/parentI3_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */

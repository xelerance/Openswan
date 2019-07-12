#define NAPT_ENABLED 1

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../../libpluto/lp12-parentR2/parentR2_head.c"
#include "seam_host_jamesjohnson.c"
#include "seam_x509.c"
#include "seam_crypt.c"
#include "seam_pending.c"
#include "seam_ikev1.c"
#include "seam_ikev1_aggr.c"
#include "seam_dh_v2.c"
#include "seam_ke.c"
#include "seam_mockxfrm.c"
#include "seam_ikev1_crypto.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_cryptocontinue.c"
#include "seam_natt.c"

#define TESTNAME "xf12-parentR2"

void delete_cryptographic_continuation(struct state *st) {}

static void init_loaded(void)
{
    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE|DBG_NETKEY;
    xfrm_init_base_algorithms();

    passert(esp_aalg[IKEv2_AUTH_HMAC_SHA2_256_128].kernel_alg_info != NULL);
}

static void init_local_interface(void)
{
    init_jamesjohnson_interface();
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , SAMPLEDIR "/jj.secrets"
			       , NULL, NULL);
}

/* this is replicated in the unit test cases since the patching up of the crypto values is case specific */
void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    st = state_with_serialno(1);
    if(st) {
        st->st_connection->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE|DBG_CRYPT|DBG_PRIVATE;

        /* now fill in the KE values from a constant.. not calculated */
        clonetowirechunk(&kn->thespace, kn->space, &kn->n,      SS(ni.ptr), SS(ni.len));
        clonetowirechunk(&kn->thespace, kn->space, &kn->gi,     SS(gi.ptr), SS(gi.len));
    }

    run_continuation(crypto_req);
}

void recv_pcap_packet2(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;

    /* create a socket for a possible whack process that is doing --up */
    int fake_whack_fd = open("/dev/null", O_RDWR);
    passert(fake_whack_fd != -1);

    cur_debugging |= DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE|DBG_CRYPT|DBG_PRIVATE;
    recv_pcap_packet_gen(user, h, bytes);

    run_continuation(crypto_req);

    fprintf(stderr, "now look at the resulting SAs produced.\n");
    show_states_status();
}

#define PCAP_INPUT_COUNT 2
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet,
    recv_pcap_packet2,
};

#include "../../libpluto/lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */

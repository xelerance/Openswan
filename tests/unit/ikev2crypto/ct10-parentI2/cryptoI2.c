#include "../lp10-parentI2/parentI2_head.c"
#include "seam_keys2.c"
#include "seam_ke.c"
#include "seam_dh_v2.c"
#include "seam_x509.c"
#include "seam_host_parker.c"

#define TESTNAME "cryptoI2"

static void init_local_interface(void)
{
    init_parker_interface(TRUE);
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , SAMPLEDIR "/parker.secrets"
			       , NULL, NULL);
}

static void init_loaded(void) {}

void delete_cryptographic_continuation(struct state *st) {}

void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct state *st;

    recv_pcap_packet_gen(user, h, bytes);

    cur_debugging |= DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE|DBG_CRYPT|DBG_PRIVATE;
    run_continuation(crypto_req);
}

#include "../lp10-parentI2/parentI2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */

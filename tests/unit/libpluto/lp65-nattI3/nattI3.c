#define NAPT_ENABLED 1
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../lp13-parentI3/parentI3_head.c"
#include "seam_x509.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_rsasig.c"

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL, NULL);
}

static void init_loaded(void)
{   /* nothing */ }

#define TESTNAME "nattI3"

/* this is replicated in the unit test cases since the patching up of the crypto values is case specific */
void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
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
    /* create a socket for a possible whack process that is doing --up */
    int fake_whack_fd = open("/dev/null", O_RDWR);
    passert(fake_whack_fd != -1);

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

/*
 * PARENT I2 test case actually invokes the parent I1 test case
 * to get all of the states into the right order.
 *
 */

#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH 
#define MODECFG 
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "constants.h"
#include "oswalloc.h"
#include "whack.h"
#include "../../programs/pluto/rcv_whack.h"

#include "../../programs/pluto/connections.c"

#include "whackmsgtestlib.c"
#include "seam_timer.c"
#include "seam_pending.c"
#include "seam_ikev1.c"
#include "seam_crypt.c"
#include "seam_kernel.c"
#include "seam_rnd.c"
#include "seam_log.c"
#include "seam_xauth.c"
#include "seam_east.c"
#include "seam_initiate.c"
#include "seam_alg.c"
#include "seam_x509.c"
#include "seam_spdbstruct.c"
#include "seam_demux.c"
#include "seam_whack.c"
#include "seam_natt.c"
#include "seam_gi.c"

u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];
bool nat_traversal_support_non_ike = FALSE;
bool nat_traversal_support_port_floating = FALSE;

void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct pcr_kenonce *kn = &r->pcr_d.kn;
    struct msg_digest *md;
    u_int32_t *dlt;
    struct iphdr  *ip;
    struct udphdr *udp;
    u_char    *ike;
    struct state *st;
    const struct iface_port *ifp = &if1;
    int packet_len;
    err_t from_ugh;
    union
    {
	struct sockaddr sa;
	struct sockaddr_in sa_in4;
	struct sockaddr_in6 sa_in6;
    } from;

    md = alloc_md();
    dlt = (u_int32_t *)bytes;
    if(*dlt != PF_INET) return;

    ip  = (struct iphdr *)(dlt + 1);
    udp = (struct udphdr *)(dlt + ip->ihl + 1);
    ike = (u_char *)(udp+1);

    from.sa_in4.sin_addr.s_addr = ip->saddr;
    from.sa_in4.sin_port        = udp->source;

    md->iface = ifp;
    packet_len = h->len - (ike-bytes);

    happy(anyaddr(addrtypeof(&ifp->ip_addr), &md->sender));

    from_ugh = initaddr((void *) &from.sa_in4.sin_addr
			, sizeof(from.sa_in4.sin_addr)
			, AF_INET, &md->sender);
    setportof(from.sa_in4.sin_port, &md->sender);
    md->sender_port = ntohs(from.sa_in4.sin_port);

    cur_from      = &md->sender;
    cur_from_port = md->sender_port;

    /* Clone actual message contents
     * and set up md->packet_pbs to describe it.
     */
    init_pbs(&md->packet_pbs
	     , clone_bytes(ike, packet_len, "message buffer in comm_handle()")
	     , packet_len, "packet");

    DBG_log("*received %d bytes from %s:%u on %s (port=%d)"
	    , (int) pbs_room(&md->packet_pbs)
	    , ip_str(&md->sender), (unsigned) md->sender_port
	    , ifp->ip_dev->id_rname
	    , ifp->port);

    DBG_dump("", md->packet_pbs.start, pbs_room(&md->packet_pbs));

    process_packet(&md);

    if (md != NULL)
	release_md(md);

    cur_state = NULL;
    reset_cur_connection();
    cur_from = NULL;

    /* find st involved */
    st = state_with_serialno(1);
    st->st_connection->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;

    /* now fill in the KE values from a constant.. not calculated */
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, tc2_secret,tc2_secret_len);
    clonetowirechunk(&kn->thespace, kn->space, &kn->n,   tc2_nr, tc2_nr_len);
    clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  tc2_gr, tc2_gr_len);
    
    run_continuation(r);

}

main(int argc, char *argv[])
{
    int   len;
    char *infile;
    char *conn_name;
    int  lineno=0;
    struct connection *c1;
    pcap_t *pt;
    char   eb1[256];

    EF_PROTECT_FREE=1;
    EF_FREE_WIPES  =1;

    progname = argv[0];
    leak_detective = 1;

    init_crypto();

    if(argc != 4) {
	fprintf(stderr, "Usage: %s <whackrecord> <conn-name> <pcapin>\n", progname);
	exit(10);
    }
    /* argv[1] == "-r" */

    tool_init_log();
    init_pluto_vendorid();
    
    infile = argv[1];
    conn_name = argv[2];

    readwhackmsg(infile);

    send_packet_setup_pcap("parentI2.pcap");
 
    c1 = con_by_name(conn_name, TRUE);
    show_one_connection(c1);
    pt = pcap_open_offline(argv[3], eb1);



    cur_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
    pcap_dispatch(pt, 1, recv_pcap_packet, NULL);

    {
	struct state *st;

	/* find st involved */
	st = state_with_serialno(1);
	delete_state(st);
    }

    report_leaks();

    tool_close_log();
    exit(0);
}


/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make TEST=parentR1 one"
 * End:
 */

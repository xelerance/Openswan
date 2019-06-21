#ifndef __seam_demux_c__
#define __seam_demux_c__
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "pluto/log.h"
#include "id.h"

pb_stream      reply_stream;
time_t         packet_time=0;
pcap_dumper_t *packet_save = NULL;

void send_packet_close(void)
{
  if(packet_save != NULL) {
    pcap_dump_close(packet_save);
    packet_save = NULL;
  }
}

void send_packet_setup_pcap(char *file)
{
	pcap_t *pt;

        send_packet_close();

	pt = pcap_open_dead(DLT_NULL, 9000);
	packet_save = pcap_dump_open(pt, file);
}

bool send_packet_srcnat(struct state *st, const char *where, bool verbose, ip_address outsideoffirewall);

#ifdef NAPT_ENABLED
unsigned short outside_port500 = 55044;
unsigned short outside_port4500= 55045;

bool
send_packet(struct state *st, const char *where, bool verbose)
{
    ip_address outsideoffirewall;

    /* example.com: 93.184.216.34 */
    outsideoffirewall = st->st_interface->ip_addr;
    inet_pton(AF_INET, "93.184.216.34", &outsideoffirewall.u.v4.sin_addr);

    if(ntohs(outsideoffirewall.u.v4.sin_port) == pluto_port500) {
      outsideoffirewall.u.v4.sin_port = htons(outside_port500);
    } else if(ntohs(outsideoffirewall.u.v4.sin_port) == pluto_port4500) {
      outsideoffirewall.u.v4.sin_port = htons(outside_port4500);
    }

    return send_packet_srcnat(st, where, verbose, outsideoffirewall);
}

#else
bool
send_packet(struct state *st, const char *where, bool verbose)
{
    ip_address outsideoffirewall;

    /* just copy real values */
    outsideoffirewall = st->st_interface->ip_addr;
    outsideoffirewall.u.v4.sin_port = htons(st->st_interface->port);

    return send_packet_srcnat(st, where, verbose, outsideoffirewall);
}
#endif

bool
send_packet_srcnat(struct state *st, const char *where, bool verbose, ip_address outsideoffirewall)
{
    u_int8_t *ptr;
    unsigned long len;
    char b1[ADDRTOT_BUF], b2[ADDRTOT_BUF];

    ptr = st->st_tpacket.ptr;
    len = (unsigned long) st->st_tpacket.len;

    addrtot(&outsideoffirewall, 0, b1, sizeof(b1));
    addrtot(&st->st_remoteaddr, 0, b2, sizeof(b2));

    fprintf(stderr
	    , "sending %lu bytes for %s through %s:%u [%s:%u] to %s:%u (using #%lu)\n"
	   , (unsigned long) st->st_tpacket.len
	   , where
	   , st->st_interface->ip_dev->id_rname
	   , st->st_interface->port
            , b1
            , ntohs(outsideoffirewall.u.v4.sin_port)
            , b2
	   , st->st_remoteport
	   , st->st_serialno);

    DBG_dump(NULL, ptr, len);

    if(packet_save) {
	    char buf[9000];
	    struct pcap_pkthdr pp;
	    struct iphdr  *ip;
	    struct udphdr *udp;
            u_char    *ulp;
	    u_int32_t *dlt;
	    int caplen = sizeof(struct iphdr)+sizeof(struct udphdr)+len;
            int shimlen = 0;

            if ((st->st_interface->ike_float == TRUE) && (st->st_tpacket.len != 1)) {
              shimlen = 4;
            }

	    dlt = (u_int32_t*)buf;
	    *dlt = PF_INET;

	    ip  = (struct iphdr *)&buf[4];
	    ip->version = 4;
	    ip->ihl     = 5;
	    ip->tos     = 0;
	    ip->tot_len = htons(caplen+shimlen);
	    ip->id      = 0;
	    ip->frag_off= 0;
	    ip->ttl     = 64;
	    ip->protocol= IPPROTO_UDP;
	    ip->check   = 0;
	    ip->saddr   = outsideoffirewall.u.v4.sin_addr.s_addr;
	    ip->daddr   = st->st_remoteaddr.u.v4.sin_addr.s_addr;
	    udp = (struct udphdr *)&buf[sizeof(struct iphdr)+4];
	    udp->source = outsideoffirewall.u.v4.sin_port;
	    udp->dest   = htons(st->st_remoteport);
	    udp->len    = htons(sizeof(struct udphdr)+len+shimlen);
	    udp->check  = 0;

            ulp = &buf[sizeof(struct iphdr)+sizeof(struct udphdr)+4];  /* +4 because of pcap_pkthdr */
            if ((st->st_interface->ike_float == TRUE) && (st->st_tpacket.len != 1)) {
              /* insert UDP encap shim of 4 bytes of zeros, and advance pointer */
              ulp[0]=0; ulp[1]=0; ulp[2]=0; ulp[3]=0;
              ulp+=4;
            }

	    memcpy(ulp,ptr,len);

	    packet_time  = packet_time + 86400;
	    pp.ts.tv_sec = packet_time;
	    pp.ts.tv_usec= 0;
	    pp.caplen = caplen+4+shimlen;
	    pp.len    = caplen+4+shimlen;
	    pcap_dump((u_char *)packet_save, &pp, buf);
    }

    return TRUE;
}

bool
check_msg_errqueue(const struct iface_port *ifp, short interest)
{
	return TRUE;
}

void
complete_state_transition(struct msg_digest **mdp, stf_status result)
{
	fprintf(stderr, "transitioning on result: %s\n"
		, stf_status_name(result));
}

#ifndef INCLUDE_IKEV1_PROCESSING
void
complete_v1_state_transition(struct msg_digest **mdp, stf_status result)
{
	fprintf(stderr, "v1 transitioning on result: %s\n"
		, stf_status_name(result));
}
#endif
#endif

#ifndef __seam_commhandle_c__
#define __seam_commhandle_c__
#include "demux.h"

#include "seam_io.c"
unsigned int dlt_type;
pcap_t *pt;


void recv_pcap_setup(char *file)
{
    char   eb1[256];  /* error buffer for pcap open */

    pt = pcap_open_offline(file, eb1);
    DBG_log("  =========== input from pcap file %s ========", file);
    if(!pt) {
	fprintf(stderr, "can not open %s: %s\n", file, eb1);
	exit(50);
    }

    dlt_type = pcap_datalink(pt);
}


extern unsigned short outside_port500;
extern unsigned short outside_port4500;

void recv_pcap_packet_gen(u_char *user
			  , const struct pcap_pkthdr *h
			  , const u_char *bytes)
{
    struct msg_digest *md;
    u_int32_t *dlt;
    struct iphdr  *ip;
    struct udphdr *udp;
    u_char    *ike;
    const struct iface_port *ifp = interfaces;  /* take first interface */
    int packet_len;
    err_t from_ugh;
    union
    {
	struct sockaddr sa;
	struct sockaddr_in sa_in4;
	struct sockaddr_in6 sa_in6;
    } from;

    md = alloc_md();
    switch(dlt_type) {
    case DLT_NULL:
      dlt = (u_int32_t *)bytes;
      if(*dlt != PF_INET) {
        fprintf(stderr, "DLT_NULL - can not process packet in DLT=%08x\n", *dlt);
        return;
      }
      dlt++;
      break;

    case DLT_EN10MB:
      dlt = (u_int32_t *)(bytes+14);
      break;

    case DLT_LINUX_SLL:

    default:
      fprintf(stderr, "can not process packet with DLT=%08x\n", dlt_type);
      return;
    }

    ip  = (struct iphdr *)(dlt);
    udp = (struct udphdr *)(dlt + ip->ihl);
    ike = (u_char *)(udp+1);

    from.sa_in4.sin_addr.s_addr = ip->saddr;
    from.sa_in4.sin_port        = udp->source;

    while(ifp && (ifp->port != ntohs(udp->dest)

#ifdef NAPT_ENABLED
                  && !(ifp->ike_float==0 && outside_port500 == ntohs(udp->dest))
                  && !(ifp->ike_float==1 && outside_port4500 == ntohs(udp->dest))
#endif
                  )) {

#ifdef NAPT_ENABLED
      fprintf(stderr, "skipping: %s:%u %s outside: %u <=> d: %u\n"
              , ifp->ip_dev->id_rname, ifp->port
              , ifp->ike_float ? "float" : ""
              , (ifp->ike_float ? outside_port4500 : outside_port500)
              , ntohs(udp->dest));
#endif
      ifp = ifp->next;
    }
    if(ifp == NULL) {
      printf("did not find an interface with port=%u \n", ntohs(udp->dest));
      exit(10);
    }

#ifdef NAPT_ENABLED
    fprintf(stderr, "picking: %s:%u %s outside: %u <=> d: %u\n"
              , ifp->ip_dev->id_rname, ifp->port
              , ifp->ike_float ? "float" : ""
              , (ifp->ike_float ? outside_port4500 : outside_port500)
              , ntohs(udp->dest));
#endif
    md->iface = ifp;


    packet_len = h->len - (ike-bytes);

    happy(anyaddr(addrtypeof(&ifp->ip_addr), &md->sender));

    from_ugh = initaddr((void *) &from.sa_in4.sin_addr
			, sizeof(from.sa_in4.sin_addr)
			, AF_INET, &md->sender);
    (void)from_ugh;
    setportof(from.sa_in4.sin_port, &md->sender);
    md->sender_port = ntohs(from.sa_in4.sin_port);

    cur_from      = &md->sender;
    cur_from_port = md->sender_port;

    if(natt_skip_nonesp(ifp, cur_from, cur_from_port
                        , &ike, &packet_len) != TRUE) {
      exit(11);
    }

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
}




#endif

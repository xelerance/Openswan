#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH
#define MODECFG
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include "unit_test_includes.h"

#include "whackmsgtestlib.c"
#include "seam_debug.c"
#include "seam_timer.c"
#include "seam_fakevendor.c"
#include "seam_pending.c"
#include "seam_ikev1.c"
#include "seam_crypt.c"
#include "seam_rnd.c"
#include "seam_log.c"
#include "seam_xauth.c"
#include "seam_terminate.c"
#include "seam_spdbstruct.c"
#include "seam_demux.c"
#include "seam_commhandle.c"
#include "seam_whack.c"
#include "seam_initiate.c"
#include "seam_exitlog.c"
#include "seam_dnskey.c"
#include "seam_kernelalgs.c"
#include "seam_rsasig.c"

void recv_pcap_packet_with_ke(u_char *user
                              , const struct pcap_pkthdr *h
                              , const u_char *bytes);
void recv_pcap_packet2_with_ke(u_char *user
                               , const struct pcap_pkthdr *h
                               , const u_char *bytes);

#include <stdlib.h>
#include "constants.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "whack.h"

#include "seam_exitlog.c"

const char *progname=NULL;
int verbose=0;
int warningsarefatal = 0;

/* sysdep_*.c */
bool use_interface(const char *rifn) {}

int main(int argc, char *argv[])
{
    err_t err = NULL;
    char  wm_buf[4096];
    char *conn_name;
    struct whack_message wm1;
    size_t outsize = 0;

    char *ip4ex1 = "192.0.1.2";
    char *ip4ex2 = "192.0.1.3";
    char *ip6ex3 = "2001:db8::4";
    char *ip6net4 = "2001:db8:0:1::0/64";
    progname = argv[0];
    leak_detective = 1;

    if(argc != 1) {
	fprintf(stderr, "Usage: %s .. \n", progname);
	exit(10);
    }

    tool_init_log();

    /* */
    memset(&wm1, 0, sizeof(wm1));
    wm1.left.id = "test1";
    wm1.left.cert="test2";
    wm1.left.ca  ="test3";
    wm1.left.host_type = KH_DEFAULTROUTE;

    ttoaddr_num(ip4ex1, strlen(ip4ex1), AF_INET, &wm1.left.host_addr);
    ttoaddr_num(ip4ex2, strlen(ip4ex2), AF_INET, &wm1.left.host_nexthop);
    ttoaddr_num(ip6ex3, strlen(ip6ex3), AF_INET6, &wm1.left.host_srcip);

    ttosubnet(ip6net4, strlen(ip6net4), AF_INET6, &wm1.left.client);
    wm1.left.has_client = TRUE;
    wm1.left.has_client_wildcard = FALSE;
    wm1.left.has_port_wildcard = FALSE;
    wm1.left.updown = "/bin/true";
    wm1.left.host_port = 1234;
    wm1.left.port      = 3456;
    wm1.left.protocol  = 98;
    wm1.left.virt  = "192.168.1.0/24";
    wm1.left.xauth_server = TRUE;
    wm1.left.xauth_client = FALSE;
    wm1.left.xauth_name   = "hello";
    wm1.left.modecfg_server = TRUE;
    wm1.left.modecfg_client = FALSE;
    wm1.left.tundev         = 1234;
    wm1.left.sendcert       = 0;
    wm1.left.certtype       = 1;
    wm1.left.host_addr_name = "example.com";

    wm1.right = wm1.left;

    wm1.magic = WHACK_MAGIC;
    wm1.whack_shutdown = TRUE;
    wm1.name_len = 12;
    wm1.name     = "abcde_abcde_";

    chunk_t wmchunk = { wm_buf, sizeof(wm_buf) };
    err_t ugh = whack_cbor_encode_msg(&wm1, &wmchunk );
    if(ugh) { printf("error: %s\n", ugh); exit(3); }

    FILE *omsg = fopen("OUTPUT/wm1.bin", "wb");
    if(omsg == NULL) { perror("output"); exit(4); }
    fwrite(wmchunk.ptr, wmchunk.len, 1, omsg);
    fclose(omsg);

    /* now decode it again */
    memset(&wm1, 0, sizeof(wm1));
    err = whack_cbor_decode_msg(&wm1, wmchunk.ptr, &wmchunk.len);
    if(err) { printf("decode error: %s\n", err); exit(6); }

    passert(wm1.whack_shutdown == TRUE);

    tool_close_log();

    report_leaks();
    exit(0);
}


/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */

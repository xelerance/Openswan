#include <stdlib.h>
#include "constants.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "whack.h"

#include "seam_exitlog.c"

/* include to be able to get at static functions */
#include "../../../lib/libwhack/whackwrite.c"

const char *progname=NULL;
int verbose=0;
int warningsarefatal = 0;

/* sysdep_*.c */
bool use_interface(const char *rifn) {}

int main(int argc, char *argv[])
{
    err_t err = NULL;
    char  qcbuf[4096];
    size_t outsize = 0;

    ip_address ip1;
    ip_subnet  ipS;
    char *ip4ex1 = "192.0.1.2";
    char *ip4ex2 = "192.0.1.3";
    char *ip6ex3 = "2001:db8::4";
    char *ip6ex4 = "2001:db8::";
    char *ip6net5 = "2001:db8:0:1::0/64";
    char *ip6net6 = "2001:db8:0::/128";
    char *ip6net7 = "::/128";
    char *ip6net8 = "::/0";
    progname = argv[0];
    leak_detective = 1;

    QCBOREncodeContext qec;
    UsefulBuf into = {qcbuf, (unsigned long)sizeof(qcbuf)};
    QCBOREncode_Init(&qec, into);
    QCBORError e;

    if(argc != 1) {
	fprintf(stderr, "Usage: %s .. \n", progname);
	exit(10);
    }

    tool_init_log();

    zero(&ip1);
    ttoaddr_num(ip4ex1, strlen(ip4ex1), AF_INET, &ip1);
    whack_cbor_encode_ipaddress(&qec, &ip1);

    zero(&ip1);
    ttoaddr_num(ip4ex2, strlen(ip4ex2), AF_INET, &ip1);
    whack_cbor_encode_ipaddress(&qec, &ip1);

    zero(&ip1);
    ttoaddr_num(ip6ex3, strlen(ip6ex3), AF_INET6, &ip1);
    whack_cbor_encode_ipaddress(&qec, &ip1);

    zero(&ip1);
    ttoaddr_num(ip6ex4, strlen(ip6ex4), AF_INET6, &ip1);
    whack_cbor_encode_ipaddress(&qec, &ip1);

    QCBOREncode_OpenMap(&qec);
    zero(&ipS);
    ttosubnet(ip6net5, strlen(ip6net5), AF_INET6, &ipS);
    whack_cbor_encode_some_ipsubnet_ToMapN(&qec, 5, &ipS);

    zero(&ipS);
    ttosubnet(ip6net6, strlen(ip6net6), AF_INET6, &ipS);
    whack_cbor_encode_some_ipsubnet_ToMapN(&qec, 6, &ipS);

    zero(&ipS);
    ttosubnet(ip6net7, strlen(ip6net7), AF_INET6, &ipS);
    whack_cbor_encode_some_ipsubnet_ToMapN(&qec, 7, &ipS);

    zero(&ipS);
    ttosubnet(ip6net8, strlen(ip6net8), AF_INET6, &ipS);
    whack_cbor_encode_some_ipsubnet_ToMapN(&qec, 8, &ipS);
    QCBOREncode_CloseMap(&qec);

    e = QCBOREncode_FinishGetSize(&qec, &outsize);
    if(e != QCBOR_SUCCESS) {
        fprintf(stderr, "failure: %d\n", e);
        exit(5);
    }

    FILE *omsg = fopen("OUTPUT/wm08.bin", "wb");
    if(omsg == NULL) { perror("output"); exit(4); }
    fwrite(qcbuf, outsize, 1, omsg);
    fclose(omsg);

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

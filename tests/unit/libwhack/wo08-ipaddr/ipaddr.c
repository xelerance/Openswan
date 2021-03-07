#include <stdlib.h>
#include "constants.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "whack.h"

#include "seam_exitlog.c"

/* include to be able to get at static functions */
#include "../../../lib/libwhack/whackwrite.c"
#include "../../../lib/libpluto/plutoctrl_cbor.c"

const char *progname=NULL;
int verbose=0;
int warningsarefatal = 0;

/* sysdep_*.c */
bool use_interface(const char *rifn) {}

void test_decode(const char *runname, const char *input1, unsigned int length)
{
    UsefulBufC todecode = {input1, (unsigned long)length};
    QCBORDecodeContext qdc;
    QCBORItem   item;
    QCBORError e;
    ip_subnet o1;
    char b1[SUBNETTOT_BUF+1];

    QCBORDecode_Init(&qdc, todecode, QCBOR_DECODE_MODE_NORMAL);
    if((e = QCBORDecode_GetNext(&qdc, &item)) == QCBOR_SUCCESS) {
        whack_cbor_decode_ipsubnet(&qdc, "right", &item, &o1);
        subnettot(&o1, 0, b1, sizeof(b1));
        printf("decoded %s: %s\n", runname, b1);
    } else {
        printf("failed to decode %s\n", runname);
    }
}


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

    unsigned char input1[15] = {
                                0xD9, 0x01, 0x05,   //   # tag(261)
                                0x82,               //   # array(2)
                                0x18, 0x31,         //   # unsigned(49)
                                0x48,               //   # bytes(8)
                                0x20,0x01,0x0D,0xB8,
                                0x12,0x34,0xFE,0xDC //  # " \x01\r\xB8\x124\xFE\xDC"
    };
    test_decode("input1", input1, sizeof(input1));

    unsigned char input2[15] = {
                                0xD9, 0x01, 0x05,   //   # tag(261)
                                0x82,               //   # array(2)
                                0x18, 0x31,         //   # unsigned(49)
                                0x46,               //   # bytes(8)
                                0x20,0x01,0x0D,0xB8,
                                0x12,0x34
    };
    test_decode("input2", input2, sizeof(input2));

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

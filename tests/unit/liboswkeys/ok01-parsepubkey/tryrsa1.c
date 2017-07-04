#define DEBUG
#include <stdlib.h>
#include "openswan.h"
#include "openswan/passert.h"
#include "constants.h"
#include "openswan/ipsec_policy.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "oswkeys.h"
#include "secrets.h"
const char *progname;

void exit_tool(int stat)
{
    exit(stat);
}

/* parse a public key from a string into a pubkey structure */
void t1(void)
{
  const char *key1 = "0sAQOkietplPhkvb/uE9j2UhlB1dSMb3YMgXXQ5r6xMVzHGjASxbMeWCtUbkMI2jGmJzRjUzRvQOIHg14yC3lE4O2j";
  osw_public_key opk;
  err_t ugh = str2pubkey(key1, PUBKEY_ALG_RSA, &opk);

  assert(ugh == NULL);

  printf("ckaid: %s\n", opk.key_ckaid_print_buf);
  assert(strcmp(opk.key_ckaid_print_buf, "F913 DF26 FD82 CFA0 4173 B4CB D0DA 676E 6D98 36F3")==0);
}


int main(int argc, char *argv[])
{
    int i;
    struct id one;

    progname = argv[0];

    tool_init_log();

    t1();

    report_leaks();
    tool_close_log();
    exit(0);
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */

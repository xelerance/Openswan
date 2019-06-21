#define DEBUG
#include <stdlib.h>
#include "openswan.h"
#include "openswan/passert.h"
#include "constants.h"
#include "openswan/ipsec_policy.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "id.h"
const char *progname;

void exit_tool(int stat)
{
    exit(stat);
}

/* an ID_NONE will same_exact_id() match only another ID_NONE */
void t1(void)
{
    struct id a,b;
    zero(&a); zero(&b);
    printf("t1\n");

    a.kind = ID_NONE;
    b.kind = ID_NONE;

    passert(same_exact_id(&a,&b) == 1);
}

/* an ID_MYID will same_exact_id() match only another ID_MYID */
void t2(void)
{
    struct id a,b;
    zero(&a); zero(&b);
    printf("t2\n");

    a.kind = ID_MYID;
    b.kind = ID_MYID;

    passert(same_exact_id(&a,&b) == 1);
}

/* an ID_MYID will same_exact_id() match only another ID_MYID */
void t3(void)
{
    struct id a,b;
    zero(&a); zero(&b);
    printf("t3\n");

    a.kind = ID_MYID;
    b.kind = ID_NONE;

    passert(same_exact_id(&a,&b) == 0);
}

/* an ID_NONE will same_id() match anything */
void t4(void)
{
    struct id a,b;
    zero(&a); zero(&b);
    printf("t4\n");

    a.kind = ID_MYID;
    b.kind = ID_NONE;

    passert(same_exact_id(&a,&b) == 0);
}

/* an FQDN will match another FQDN with a trailing .  */
void t5(void)
{
    struct id a,b;
    zero(&a); zero(&b);
    printf("t5\n");

    atoid("example.com", &a, FALSE);
    atoid("example.com.", &b,FALSE);

    passert(same_exact_id(&a,&b) == 1);
}

/* an FROMCERT will not match FQDN  */
void t6(void)
{
    struct id a,b;
    zero(&a); zero(&b);
    printf("t6\n");

    atoid("%fromcert", &a, FALSE);
    atoid("example.com", &b,FALSE);

    passert(same_exact_id(&a,&b) == 0);
}


int main(int argc, char *argv[])
{
    progname = argv[0];

    tool_init_log();

    t1();
    t2();
    t3();
    t4();
    t5(); t6();

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

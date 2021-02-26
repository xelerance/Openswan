#include "add2sa-del1sa_head.c"

#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_demux.c"
#include "seam_pending.c"
#include "seam_whack.c"
#include "seam_initiate.c"
#include "seam_dnskey.c"
#include "seam_x509.c"
#include "seam_keys.c"
#include "seam_rsasig.c"
#include "seam_host_parker.c"

/* template state structures */
#include "h2hI3-statetable.c"

#define TESTNAME "add2sa-del1sa"

const char *progname;

static void init_local_interface(void)
{
    init_parker_interface(TRUE);
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL, NULL);
}

static struct state * create_test_state(int num, const struct state *template,
					int parent,
                                        u_int8_t *icookie, u_int8_t *rcookie)
{
    struct state *st;
    st = new_state();
    assert( st->st_serialno == num);

    *st = *template;

    st->st_hashchain_prev = NULL;
    st->st_hashchain_next = NULL;
    st->st_serialno = num;
    st->st_clonedfrom = parent;

    if (icookie)
        memcpy(st->st_icookie, icookie, sizeof(st->st_icookie));
    if (rcookie)
        memcpy(st->st_rcookie, rcookie, sizeof(st->st_rcookie));

    insert_state( st );

    return st;
}

static void output_cookie(const char *prefix, const u_int8_t *cookie)
{
    int i;

    printf("%s{ ", prefix);

    for (i=0; i<COOKIE_SIZE; i++)
        printf("0x%02x%s ", cookie[i], i==COOKIE_SIZE-1 ? "" : ",");

    printf("}\n");
}

#define STATE_TABLE_SIZE 32
static void find_cookie_collision(u_int8_t *out_icookie, u_int8_t *out_rcookie,
                      const u_int8_t *in_icookie, const u_int8_t *in_rcookie)
{
    long loops = 0;
    u_int in_bucket, out_bucket;

    in_bucket = compute_icookie_rcookie_hash(in_icookie, in_rcookie);
    in_bucket %= STATE_TABLE_SIZE;

    printf("looking for collision for cookies, which has to bucket %d\n",
           in_bucket);
    output_cookie("st_icookie = ", in_icookie);
    output_cookie("st_rcookie = ", in_rcookie);

    srandom(time(NULL));

    do {
        int i;

        for (i=0; i<COOKIE_SIZE; i++) {
            int r = rand();
            out_icookie[i] = r;
            out_rcookie[i] = r >> 8;
        }
        loops ++;

        out_bucket = compute_icookie_rcookie_hash(out_icookie, out_rcookie);
        out_bucket %= STATE_TABLE_SIZE;

    } while (in_bucket != out_bucket);

    printf("it took %ld loops to find a collision, in bucket %d\n",
           loops, out_bucket);
    output_cookie("st_icookie = ", out_icookie);
    output_cookie("st_rcookie = ", out_rcookie);
}

int main(int argc, char *argv[])
{
    int argi;
    int regression = 0;
    struct state *st1 = NULL;
    struct state *st2 = NULL;
    struct state *st3 = NULL;
    struct state *st4 = NULL;

    (void)st2;
    (void)st3;
    (void)st4;

    /* these cookies were chosen randomly to hash to the same bucket as those
     * obtained from the "h2hI3-statetable.c" template. */
    u_int8_t st3_icookie[COOKIE_SIZE] = { 0x81, 0x03, 0x3d, 0x77, 0xf9, 0xe9, 0x4d, 0x44 };
    u_int8_t st3_rcookie[COOKIE_SIZE] = { 0xa9, 0xe0, 0xb6, 0x71, 0x7b, 0xa8, 0x07, 0x09 };

    progname = argv[0];
    leak_detective=1;

    /* arguments */
    argi = 1;
    if(argi<argc && !strcmp(argv[argi], "-r")) {
        regression = 1;
        argi++;
    }
    assert( (argv[argi] == NULL) && "unexpected command line options" );

    /* init */
    tool_init_log();
    init_crypto();
    load_oswcrypto();
    init_fake_vendorid();
    init_fake_secrets();
    init_local_interface();
    enable_debugging();

    /* add first parent SA, and it's child */
    st1 = create_test_state(1, &h2h_sa_1001, 0, NULL, NULL);
    st2 = create_test_state(2, &h2h_sa_1002, 1, NULL, NULL);

    /* in regression mode, we use the st3_rcookie, otherwise we find a collision */
    if (!regression) {
        find_cookie_collision(st3_icookie, st3_rcookie,
                              st1->st_icookie, st1->st_rcookie);
    }

    /* add second parent SA, and it's child */
    st3 = create_test_state(3, &h2h_sa_1001, 0, st3_icookie, st3_rcookie);
    st4 = create_test_state(4, &h2h_sa_1002, 3, st3_icookie, st3_rcookie);

    /* dump the states */
    show_states_status();

    /* delete the first family */
    delete_state_family(st1, TRUE);

    /* dump the states */
    show_states_status();

    /* done */
    tool_close_log();

    report_leaks();
    exit(0);
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */


const char *progname;

void exit_tool(int stat)
{
    exit(stat);
}

int main(int argc, char *argv[])
{
    int i;
    err_t e = NULL;
    struct db2_context *dc;
    struct db_sa *sadb;
    struct alg_info_ike *ai;
    const char *ikepolicy;

    unsetenv("TZ"); tzset();
    progname = argv[0];
    leak_detective=1;

    cur_debugging = DBG_ALL;

    tool_init_log();
    init_crypto();

    setbuf(stdout, NULL);  /* make stdout unbuffered so stdout/stderr interleave */

#if 1
    {
        struct db_context *ctx = db_prop_new(PROTO_ISAKMP,
                                             10,/* transforms */
                                             10 /* attributes */);
        passert(v2tov1_encr(IKEv2_ENCR_AES_CBC) == OAKLEY_AES_CBC);
        passert(v2tov1_integ(IKEv2_AUTH_HMAC_SHA1_96)== OAKLEY_SHA1);

        printf("testing db1 ops\n");

        db_trans_add(ctx, KEY_IKE);
        db_attr_add_values(ctx, OAKLEY_ENCRYPTION_ALGORITHM,
                           OAKLEY_AES_CBC);
        db_attr_add_values(ctx, OAKLEY_HASH_ALGORITHM,
                           OAKLEY_SHA1);
        db_attr_add_values(ctx, OAKLEY_GROUP_DESCRIPTION,
                           OAKLEY_GROUP_MODP2048);

        db_print(ctx);
        db_destroy(ctx);
    }


    ikepolicy="aes128-sha1-prfsha1-modp2048";
    DBG_log("for input ike=%s", ikepolicy);
    ai = alg_info_ike_create_from_str(ikepolicy, &e);

    if(e) {
        DBG_log("failed to parse %s: %s\n", ikepolicy, e);
        exit(10);
    }
    passert(ai != NULL);

    printf("\nPSK:\n");
    sadb = alginfo2parent_db2(ai);
    sadb->parentSA = TRUE;

    sa_v2_print(sadb);

    if(!extrapolate_v1_from_v2(sadb, POLICY_PSK, INITIATOR)) {
        DBG_log("failed to create v1");
        exit(11);
    }
    printf("v1 (PSK):");
    sa_print(sadb);
    free_sa(sadb);

    printf("\nRSA:\n");
    sadb = alginfo2parent_db2(ai);
    sadb->parentSA = TRUE;

    sa_v2_print(sadb);
    if(!extrapolate_v1_from_v2(sadb, POLICY_RSASIG, INITIATOR)) {
        DBG_log("failed to create v1");
        exit(11);
    }
    printf("v1 (RSA):");
    sa_print(sadb);

    free_sa(sadb);

    printf("\nRSA+PSK:\n");
    sadb = alginfo2parent_db2(ai);
    sadb->parentSA = TRUE;

    sa_v2_print(sadb);
    if(!extrapolate_v1_from_v2(sadb, POLICY_PSK|POLICY_RSASIG, INITIATOR)) {
        DBG_log("failed to create v1");
        exit(11);
    }
    printf("v1 (RSA+PSK):");
    sa_print(sadb);

    free_sa(sadb);
    alg_info_free((struct alg_info *)ai);
#endif

    printf("\ndefault RSA:\n");
    sadb = alginfo2parent_db2(NULL);
    sadb->parentSA = TRUE;

    sa_v2_print(sadb);
    if(!extrapolate_v1_from_v2(sadb, POLICY_RSASIG, INITIATOR)) {
        DBG_log("failed to create v1");
        exit(11);
    }
    printf("default v1 (RSA):");
    sa_print(sadb);

    free_sa(sadb);

#if 1
    ikepolicy="aes128-sha1-sha1-modp2048";
    DBG_log("for input ike=%s", ikepolicy);
    ai = alg_info_ike_create_from_str(ikepolicy, &e);

    if(e) {
        DBG_log("failed to parse %s: %s\n", ikepolicy, e);
        exit(10);
    }
    passert(ai != NULL);

    sadb = alginfo2parent_db2(ai);
    alg_info_free((struct alg_info *)ai);

    sa_v2_print(sadb);
    free_sa(sadb);

    /* now do the defaults */
    DBG_log("IKEv2 defaults\n");
    ai = alg_info_ike_defaults();

    if(e) {
        DBG_log("failed to parse %s: %s\n", ikepolicy, e);
        exit(10);
    }
    passert(ai != NULL);

    sadb = alginfo2parent_db2(ai);
    alg_info_free((struct alg_info *)ai);

    sa_v2_print(sadb);
    free_sa(sadb);
#endif

#if 1
    ikepolicy="aes256-sha2_512-modp2048";
    DBG_log("for input ike=%s", ikepolicy);
    ai = alg_info_ike_create_from_str(ikepolicy, &e);

    if(e) {
        DBG_log("failed to parse %s: %s\n", ikepolicy, e);
        exit(10);
    }
    passert(ai != NULL);

    sadb = alginfo2parent_db2(ai);
    sadb->parentSA = TRUE;
    sa_v2_print(sadb);

    if(!extrapolate_v1_from_v2(sadb, POLICY_RSASIG, INITIATOR)) {
        DBG_log("failed to create v1");
        exit(11);
    }
    printf("strong v1 (RSA):");
    sa_print(sadb);

    free_sa(sadb);
#endif

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

#include "../lp07-orient/orienttest_head.c"
#include "seam_host_bob.c"

#define TESTNAME "loadbob"

static void init_local_interface(bool doipv6)
{
    init_bob_interface(doipv6);
    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE;
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir_str("../../../functional/10-defaultroute/bob");

    rnd_offset = 13;

    osw_load_preshared_secrets(&pluto_secrets
                               , TRUE
                               , "../../../functional/10-defaultroute/bob.secrets"
                               , NULL, NULL);
}

#include "../lp07-orient/orienttest_main.c"

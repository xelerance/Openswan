#include "../lp07-orient/orienttest_head.c"
#include "seam_host_moon.c"
#include "seam_rsasig.c"

#define TESTNAME "orientmoon"

static void init_local_interface(bool doipv6)
{
    init_moon_interface(doipv6);
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir_str("../samples/moon");

    rnd_offset = 13;

    osw_load_preshared_secrets(&pluto_secrets
                               , TRUE
                               , "../samples/moon.secrets"
                               , NULL, NULL);
}

#include "../lp07-orient/orienttest_main.c"

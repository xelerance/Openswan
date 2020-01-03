#ifndef __seam_kernelalgs_c__
#define __seam_kernelalgs_c__
#include "kernel_alg.h"

static void
init_seam_kernelalgs(void)
{
	int ret;
	struct sadb_alg sa;

        kernel_alg_init();

	memset(&sa, 0, sizeof(sa));
	sa.sadb_alg_id      = ESP_AES;    /* this is a kernel algorithm ID */
	sa.sadb_alg_ivlen   = 16;
	sa.sadb_alg_minbits = 128;
	sa.sadb_alg_maxbits = 512;
	ret=kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT,&sa);

	sa.sadb_alg_id = ESP_3DES;
	sa.sadb_alg_ivlen = 8;
	sa.sadb_alg_minbits = 24*8;
	sa.sadb_alg_maxbits = 24*8;
	ret=kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT,&sa);

	sa.sadb_alg_id = AH_SHA;
	sa.sadb_alg_minbits = 20*8;
	sa.sadb_alg_maxbits = 20*8;
	ret=kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_AUTH, &sa);

	sa.sadb_alg_id = AH_MD5;
	sa.sadb_alg_minbits = 16*8;
	sa.sadb_alg_maxbits = 16*8;
	ret=kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_AUTH, &sa);

	sa.sadb_alg_id = AH_SHA2_256;
	sa.sadb_alg_minbits = 32*8;
	sa.sadb_alg_maxbits = 32*8;
	ret=kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_AUTH, &sa);

	sa.sadb_alg_id = AH_SHA2_512;
	sa.sadb_alg_minbits = 32*8;
	sa.sadb_alg_maxbits = 32*8;
	ret=kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_AUTH, &sa);

}


#endif

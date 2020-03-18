#ifndef __seam_x509_c__
#define __seam_x509_c__
#include "seam_x509_list.c"

void
decode_cert(struct msg_digest *md)
{
	DBG_log( "%s: %s() not implemented", __FILE__, __func__);
}

void
ikev1_decode_cr(struct msg_digest *md, generalName_t **requested_ca)
{
	DBG_log( "%s: %s() not implemented", __FILE__, __func__);
}

void
ikev2_decode_cert(struct msg_digest *md)
{
	DBG_log( "%s: %s() not implemented", __FILE__, __func__);
}

/* Decode the IKEv2 CR payload of Phase 1. */
void
ikev2_decode_cr(struct msg_digest *md, generalName_t **requested_ca)
{
	DBG_log( "%s: %s() not implemented", __FILE__, __func__);
}

bool
ikev2_build_and_ship_CR(u_int8_t type, chunk_t ca, pb_stream *outs
			, u_int8_t np)
{
	DBG_log( "%s: %s() not implemented, returns FALSE", __FILE__, __func__);
	return FALSE;
}

bool
collect_rw_ca_candidates(struct msg_digest *md, generalName_t **top)
{
	DBG_log( "%s: %s() not implemented, returns FALSE", __FILE__, __func__);
	return FALSE;
}

bool
build_and_ship_CR(u_int8_t type, chunk_t ca, pb_stream *outs, u_int8_t np)
{
	DBG_log( "%s: %s() not implemented, returns FALSE", __FILE__, __func__);
	return FALSE;
}
#endif

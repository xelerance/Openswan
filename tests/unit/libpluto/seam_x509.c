#ifndef __seam_x509_c__
#define __seam_x509_c__
#include "seam_x509_list.c"

void
decode_cert(struct msg_digest *md)
{
}

void
decode_cr(struct msg_digest *md, generalName_t **requested_ca)
{
}

void
ikev2_decode_cert(struct msg_digest *md)
{
}

/* Decode the IKEv2 CR payload of Phase 1. */
void
ikev2_decode_cr(struct msg_digest *md, generalName_t **requested_ca)
{
}

bool
ikev2_build_and_ship_CR(u_int8_t type, chunk_t ca, pb_stream *outs
			, u_int8_t np)
{
	return FALSE;
}

bool
collect_rw_ca_candidates(struct msg_digest *md, generalName_t **top)
{
	return FALSE;
}

bool
build_and_ship_CR(u_int8_t type, chunk_t ca, pb_stream *outs, u_int8_t np)
{
	return FALSE;
}
#endif

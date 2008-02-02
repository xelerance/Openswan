#ifndef  NO_X509_SEAM
void
decode_cert(struct msg_digest *md)
{
}

void
decode_cr(struct msg_digest *md, generalName_t **requested_ca)
{
}
/* Send v2CERT and v2 CERT */
stf_status ikev2_send_cert( struct state *st
                                  , enum phase1_role role
                                  , unsigned int np
                                  , pb_stream *outpbs)
{
return STF_OK;
}
void
ikev2_decode_cert(struct msg_digest *md)
{
}
bool
doi_send_ikev2_cert_thinking( struct state *st) {
	return FALSE;
}
#endif

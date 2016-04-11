/* xauth.c SEAM */
oakley_auth_t xauth_calcbaseauth(oakley_auth_t baseauth) { return baseauth; }

stf_status xauth_send_request(struct state *st)
{
  return STF_OK;
}

stf_status modecfg_send_request(struct state *st)
{
  return STF_OK;
}

stf_status modecfg_start_set(struct state *st)
{
  return STF_OK;
}

stf_status xauth_inI0(struct msg_digest *md) { return STF_OK; }
stf_status xauth_inI1(struct msg_digest *md) { return STF_OK; }
stf_status xauth_inR0(struct msg_digest *md) { return STF_OK; }
stf_status xauth_inR1(struct msg_digest *md) { return STF_OK; }
stf_status modecfg_inR0(struct msg_digest *md) { return STF_OK; }
stf_status modecfg_inR1(struct msg_digest *md) { return STF_OK; }



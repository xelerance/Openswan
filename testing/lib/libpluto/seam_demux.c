bool
send_packet(struct state *st, const char *where, bool verbose)
{
    u_int8_t *ptr;
    unsigned long len;

    ptr = st->st_tpacket.ptr;
    len = (unsigned long) st->st_tpacket.len;

    printf("sending %lu bytes for %s through %s:%d to %s:%u (using #%lu)"
	   , (unsigned long) st->st_tpacket.len
	   , where
	   , st->st_interface->ip_dev->id_rname
	   , st->st_interface->port
	   , ip_str(&st->st_remoteaddr)
	   , st->st_remoteport
	   , st->st_serialno);

    DBG_dump(NULL, ptr, len);
}



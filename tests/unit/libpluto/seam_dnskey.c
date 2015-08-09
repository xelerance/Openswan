void gw_addref(struct gw_info *gw) {}
void gw_delref(struct gw_info **gwp) {}

bool in_pending_use(struct connection *c) { return FALSE; }
void kick_adns_connection_lookup(struct connection *c UNUSED
                                 , struct end *end UNUSED) {}



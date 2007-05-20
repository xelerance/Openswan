struct host_pair {
    struct {
	ip_address addr;
	u_int16_t  host_port;	        /* IKE port */
	bool       host_port_specific;	/* if above is interesting */
    } me, him;
    bool initial_connection_sent;
    struct connection *connections;	/* connections with this pair */
    struct pending *pending;	/* awaiting Keying Channel */
    struct host_pair *next;
};

extern struct host_pair *host_pairs;

extern void connect_to_host_pair(struct connection *c);
extern struct connection *find_host_pair_connections(const char *func
						     , const ip_address *myaddr
						     , u_int16_t myport			   
						     , const ip_address *hisaddr
						     , u_int16_t hisport);

extern struct host_pair *find_host_pair(const ip_address *myaddr
					, u_int16_t myport
					, const ip_address *hisaddr
					, u_int16_t hisport);


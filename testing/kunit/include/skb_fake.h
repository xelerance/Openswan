extern struct sk_buff *skbFromArray(const unsigned char *buf,
				    const unsigned int len);

extern void skb_ethernet_ip_setup(struct sk_buff *skb);


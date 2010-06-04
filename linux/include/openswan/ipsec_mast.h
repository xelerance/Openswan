#ifndef _IPSEC_MAST_H
#define _IPSEC_MAST_H

struct net_device;

#define DB_MAST_INIT	0x0001
#define DB_MAST_PROCFS	0x0002
#define DB_MAST_XMIT	0x0010
#define DB_MAST_OHDR	0x0020
#define DB_MAST_CROUT	0x0040
#define DB_MAST_OXFS	0x0080
#define DB_MAST_REVEC	0x0100
#define DB_MAST_ENCAP   0x0200

struct ipsecmastconf {
	__u32	cf_cmd;
	union
	{
		char 	cfu_name[12];
	} cf_u;
#define cf_name cf_u.cfu_name
};

struct mastpriv
{
	struct sk_buff_head sendq;
	struct wait_queue *wait_queue;
	int  (*hard_header) (struct sk_buff *skb,
			     struct net_device *dev,
			     unsigned short type,
			     void *daddr,
			     void *saddr,
			     unsigned len);
#if 0
	char locked;
	int  (*hard_start_xmit) (struct sk_buff *skb,
				 struct net_device *dev);
	int  (*rebuild_header)(struct sk_buff *skb);
	int  (*set_mac_address)(struct net_device *dev, void *addr);
	void (*header_cache_bind)(struct hh_cache **hhp, struct net_device *dev,
				  unsigned short htype, __u32 daddr);
	void (*header_cache_update)(struct hh_cache *hh,
				    struct net_device *dev,
				    unsigned char *  haddr);
	struct net_device_stats *(*get_stats)(struct net_device *dev);
#endif
	struct net_device_stats mystats;
	int mtu;	/* What is the desired MTU? */
};

extern int ipsec_mast_init_devices(void);
extern int ipsec_mast_cleanup_devices(void);
extern int ipsec_mast_deletenum(int vifnum);
extern int ipsec_mast_createnum(int vifnum);
extern struct net_device *ipsec_mast_get_device(int vifnum);
extern unsigned int ipsec_mast_is_transport(int vifnum);
extern int ipsec_is_mast_device(const struct net_device *dev);

extern int ipsec_mast_init_saref(void);
extern void ipsec_mast_cleanup_saref(void);


#endif

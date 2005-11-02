/*
 * receive code
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

char ipsec_rcv_c_version[] = "RCSID $Id: ipsec_rcv.c,v 1.133 2003/10/31 02:27:55 mcr Exp $";

#include <linux/config.h>
#include <linux/version.h>

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */

#include "freeswan/ipsec_param.h"

#ifdef MALLOC_SLAB
# include <linux/slab.h> /* kmalloc() */
#else /* MALLOC_SLAB */
# include <linux/malloc.h> /* kmalloc() */
#endif /* MALLOC_SLAB */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>	/* struct device, and other headers */
#include <linux/etherdevice.h>	/* eth_type_trans */
#include <linux/ip.h>		/* struct iphdr */
#include <linux/skbuff.h>
#include <freeswan.h>
#ifdef SPINLOCK
# ifdef SPINLOCK_23
#  include <linux/spinlock.h> /* *lock* */
# else /* SPINLOCK_23 */
#  include <asm/spinlock.h> /* *lock* */
# endif /* SPINLOCK_23 */
#endif /* SPINLOCK */
#ifdef NET_21
# include <asm/uaccess.h>
# include <linux/in6.h>
# define proto_priv cb
#endif /* NET21 */
#include <asm/checksum.h>
#include <net/ip.h>

#include "freeswan/radij.h"
#include "freeswan/ipsec_encap.h"
#include "freeswan/ipsec_sa.h"

#include "freeswan/ipsec_radij.h"
#include "freeswan/ipsec_xform.h"
#include "freeswan/ipsec_tunnel.h"
#include "freeswan/ipsec_rcv.h"

#if defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH)
#include "freeswan/ipsec_ah.h"
#endif /* defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH) */

#ifdef CONFIG_IPSEC_ESP
#include "freeswan/ipsec_esp.h"
#endif /* !CONFIG_IPSEC_ESP */

#ifdef CONFIG_IPSEC_IPCOMP
#include "freeswan/ipcomp.h"
#endif /* CONFIG_IPSEC_COMP */

#include <pfkeyv2.h>
#include <pfkey.h>

#include "freeswan/ipsec_proto.h"

#ifdef CONFIG_IPSEC_DEBUG
int debug_ah = 0;
int debug_esp = 0;
int debug_rcv = 0;
#endif /* CONFIG_IPSEC_DEBUG */

int sysctl_ipsec_inbound_policy_check = 1;

#ifdef CONFIG_IPSEC_DEBUG
static void
rcv_dmp(char *s, caddr_t bb, int len)
{
	int i;
	unsigned char *b = bb;
  
	if (debug_rcv && sysctl_ipsec_debug_verbose) {
		printk(KERN_INFO "klips_debug:ipsec_tunnel_:dmp: "
		       "at %s, len=%d:",
		       s,
		       len);
		for (i=0; i < len; i++) {
			if(!(i%16)){
				printk("\nklips_debug:  ");
			}
			printk(" %02x", *b++);
		}
		printk("\n");
	}
}
#else /* CONFIG_IPSEC_DEBUG */
#define rcv_dmp(_x, _y, _z) 
#endif /* CONFIG_IPSEC_DEBUG */


#if defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH)
__u32 zeroes[AH_AMAX];
#endif /* defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH) */

/*
 * Check-replay-window routine, adapted from the original
 * by J. Hughes, from draft-ietf-ipsec-esp-des-md5-03.txt
 *
 *  This is a routine that implements a 64 packet window. This is intend-
 *  ed on being an implementation sample.
 */

DEBUG_NO_STATIC int
ipsec_checkreplaywindow(struct ipsec_sa*ipsp, __u32 seq)
{
	__u32 diff;

	if (ipsp->ips_replaywin == 0)	/* replay shut off */
		return 1;
	if (seq == 0)
		return 0;		/* first == 0 or wrapped */

	/* new larger sequence number */
	if (seq > ipsp->ips_replaywin_lastseq) {
		return 1;		/* larger is good */
	}
	diff = ipsp->ips_replaywin_lastseq - seq;

	/* too old or wrapped */ /* if wrapped, kill off SA? */
	if (diff >= ipsp->ips_replaywin) {
		return 0;
	}
	/* this packet already seen */
	if (ipsp->ips_replaywin_bitmap & (1 << diff))
		return 0;
	return 1;			/* out of order but good */
}

DEBUG_NO_STATIC int
ipsec_updatereplaywindow(struct ipsec_sa*ipsp, __u32 seq)
{
	__u32 diff;

	if (ipsp->ips_replaywin == 0)	/* replay shut off */
		return 1;
	if (seq == 0)
		return 0;		/* first == 0 or wrapped */

	/* new larger sequence number */
	if (seq > ipsp->ips_replaywin_lastseq) {
		diff = seq - ipsp->ips_replaywin_lastseq;

		/* In win, set bit for this pkt */
		if (diff < ipsp->ips_replaywin)
			ipsp->ips_replaywin_bitmap =
				(ipsp->ips_replaywin_bitmap << diff) | 1;
		else
			/* This packet has way larger seq num */
			ipsp->ips_replaywin_bitmap = 1;

		if(seq - ipsp->ips_replaywin_lastseq - 1 > ipsp->ips_replaywin_maxdiff) {
			ipsp->ips_replaywin_maxdiff = seq - ipsp->ips_replaywin_lastseq - 1;
		}
		ipsp->ips_replaywin_lastseq = seq;
		return 1;		/* larger is good */
	}
	diff = ipsp->ips_replaywin_lastseq - seq;

	/* too old or wrapped */ /* if wrapped, kill off SA? */
	if (diff >= ipsp->ips_replaywin) {
/*
		if(seq < 0.25*max && ipsp->ips_replaywin_lastseq > 0.75*max) {
			ipsec_sa_delchain(ipsp);
		}
*/
		return 0;
	}
	/* this packet already seen */
	if (ipsp->ips_replaywin_bitmap & (1 << diff))
		return 0;
	ipsp->ips_replaywin_bitmap |= (1 << diff);	/* mark as seen */
	return 1;			/* out of order but good */
}

#ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
struct auth_alg ipsec_rcv_md5[]={
	{MD5Init, MD5Update, MD5Final, AHMD596_ALEN}
};

#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */

#ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
struct auth_alg ipsec_rcv_sha1[]={
	{SHA1Init, SHA1Update, SHA1Final, AHSHA196_ALEN}
};
#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */

enum ipsec_rcv_value {
	IPSEC_RCV_LASTPROTO=1,
	IPSEC_RCV_OK=0,
	IPSEC_RCV_BADPROTO=-1,
	IPSEC_RCV_BADLEN=-2,
	IPSEC_RCV_ESP_BADALG=-3,
	IPSEC_RCV_3DES_BADBLOCKING=-4,
	IPSEC_RCV_ESP_DECAPFAIL=-5,
	IPSEC_RCV_DECAPFAIL=-6,
	IPSEC_RCV_SAIDNOTFOUND=-7,
	IPSEC_RCV_IPCOMPALONE=-8,
	IPSEC_RCV_IPCOMPFAILED=-10,
	IPSEC_RCV_SAIDNOTLIVE=-11,
	IPSEC_RCV_FAILEDINBOUND=-12,
	IPSEC_RCV_LIFETIMEFAILED=-13,
	IPSEC_RCV_BADAUTH=-14,
	IPSEC_RCV_REPLAYFAILED=-15,
	IPSEC_RCV_AUTHFAILED=-16,
	IPSEC_RCV_REPLAYROLLED=-17
};

struct ipsec_rcv_state {
	struct sk_buff *skb;
	struct net_device_stats *stats;
	struct iphdr *ipp;
	struct ipsec_sa *ipsp;
	int len;
	int ilen;
	int authlen;
	int hard_header_len;
	int iphlen;
	struct auth_alg *authfuncs;
	ip_said said;
	char   sa[SATOT_BUF];
	size_t sa_len;
	__u8 next_header;
	__u8 hash[AH_AMAX];
	char ipsaddr_txt[ADDRTOA_BUF];
	char ipdaddr_txt[ADDRTOA_BUF];
	__u8 *octx;
	__u8 *ictx;
	int ictx_len;
	int octx_len;
	union {
		struct {
			struct esphdr *espp;
		} espstuff;
		struct {
			struct ahhdr *ahp;
		} ahstuff;
		struct {
			struct ipcomphdr *compp;
		} ipcompstuff;
	} protostuff;
};

struct xform_functions {
	enum ipsec_rcv_value (*checks)(struct ipsec_rcv_state *irs,
				       struct sk_buff *skb);
        enum ipsec_rcv_value (*decrypt)(struct ipsec_rcv_state *irs);

	enum ipsec_rcv_value (*setup_auth)(struct ipsec_rcv_state *irs,
					   struct sk_buff *skb,
					   __u32          *replay,
					   unsigned char **authenticator);
	enum ipsec_rcv_value (*calc_auth)(struct ipsec_rcv_state *irs,
					struct sk_buff *skb);
};

#ifdef CONFIG_IPSEC_ESP
enum ipsec_rcv_value
ipsec_rcv_esp_checks(struct ipsec_rcv_state *irs,
		     struct sk_buff *skb)
{
	__u8 proto;
	int len;	/* packet length */

	len = skb->len;
	proto = irs->ipp->protocol;

	/* XXX this will need to be 8 for IPv6 */
	if ((proto == IPPROTO_ESP) && ((len - irs->iphlen) % 4)) {
		printk("klips_error:ipsec_rcv: "
		       "got packet with content length = %d from %s -- should be on 4 octet boundary, packet dropped\n",
		       len - irs->iphlen,
		       irs->ipsaddr_txt);
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADLEN;
	}

	if(skb->len < (irs->hard_header_len + sizeof(struct iphdr) + sizeof(struct esphdr))) {
		KLIPS_PRINT(debug_rcv & DB_RX_INAU,
			    "klips_debug:ipsec_rcv: "
			    "runt esp packet of skb->len=%d received from %s, dropped.\n",
			    skb->len,
			    irs->ipsaddr_txt);
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADLEN;
	}

	irs->protostuff.espstuff.espp = (struct esphdr *)(skb->data + irs->iphlen);
	irs->said.spi = irs->protostuff.espstuff.espp->esp_spi;

	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value
ipsec_rcv_esp_decrypt_setup(struct ipsec_rcv_state *irs,
			    struct sk_buff *skb,
			    __u32          *replay,
			    unsigned char **authenticator)
{
	struct esphdr *espp = irs->protostuff.espstuff.espp;

	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "packet from %s received with seq=%d (iv)=0x%08x%08x iplen=%d esplen=%d sa=%s\n",
		    irs->ipsaddr_txt,
		    (__u32)ntohl(espp->esp_rpl),
		    (__u32)ntohl(*((__u32 *)(espp->esp_iv)    )),
		    (__u32)ntohl(*((__u32 *)(espp->esp_iv) + 1)),
		    irs->len,
		    irs->ilen,
		    irs->sa_len ? irs->sa : " (error)");

	*replay = ntohl(espp->esp_rpl);
	*authenticator = &(skb->data[irs->len - irs->authlen]);

	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value
ipsec_rcv_esp_authcalc(struct ipsec_rcv_state *irs,
		       struct sk_buff *skb)
{
	struct auth_alg *aa;
	struct esphdr *espp = irs->protostuff.espstuff.espp;
	union {
		MD5_CTX		md5;
		SHA1_CTX	sha1;
	} tctx;

	aa = irs->authfuncs;

	/* copy the initialized keying material */
	memcpy(&tctx, irs->ictx, irs->ictx_len);

	(*aa->update)((void *)&tctx, (caddr_t)espp, irs->ilen);

	(*aa->final)(irs->hash, (void *)&tctx);

	memcpy(&tctx, irs->octx, irs->octx_len);

	(*aa->update)((void *)&tctx, irs->hash, aa->hashlen);
	(*aa->final)(irs->hash, (void *)&tctx);

	return IPSEC_RCV_OK;
}


enum ipsec_rcv_value
ipsec_rcv_esp_decrypt(struct ipsec_rcv_state *irs)
{
	struct ipsec_sa *ipsp = irs->ipsp;
	struct esphdr *espp = irs->protostuff.espstuff.espp;
	int esphlen = 0;
	__u8 *idat;	/* pointer to content to be decrypted/authenticated */
	__u32 iv[2];
	int pad = 0, padlen;
	int badpad = 0;
	int i;
	struct sk_buff *skb;

	skb=irs->skb;

	idat = skb->data + irs->iphlen;

	switch(ipsp->ips_encalg) {
	case ESP_3DES:
		iv[0] = *((__u32 *)(espp->esp_iv)    );
		iv[1] = *((__u32 *)(espp->esp_iv) + 1);
		esphlen = sizeof(struct esphdr);
		break;
	default:
		ipsp->ips_errs.ips_alg_errs += 1;
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_ESP_BADALG;
	}

	idat += esphlen;
	irs->ilen -= esphlen;

	switch(ipsp->ips_encalg) {
	case ESP_3DES:
		if ((irs->ilen) % 8) {
			ipsp->ips_errs.ips_encsize_errs += 1;
			printk("klips_error:ipsec_rcv: "
			       "got packet with esplen = %d from %s -- should be on 8 octet boundary, packet dropped\n",
			       irs->ilen,
			       irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_errors++;
			}
			return IPSEC_RCV_3DES_BADBLOCKING;
		}
		des_ede3_cbc_encrypt((des_cblock *)idat,
				     (des_cblock *)idat,
				     irs->ilen,
				     ((struct des_eks *)(ipsp->ips_key_e))[0].ks,
				     ((struct des_eks *)(ipsp->ips_key_e))[1].ks,
				     ((struct des_eks *)(ipsp->ips_key_e))[2].ks,
				     (des_cblock *)iv, 0);
		break;
	}

	rcv_dmp("postdecrypt", skb->data, skb->len);

	irs->next_header = idat[irs->ilen - 1];
	padlen = idat[irs->ilen - 2];
	pad = padlen + 2 + irs->authlen;

	KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
		    "klips_debug:ipsec_rcv: "
		    "padlen=%d, contents: 0x<offset>: 0x<value> 0x<value> ...\n",
		    padlen);

	for (i = 1; i <= padlen; i++) {
		if((i % 16) == 1) {
			KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
				    "klips_debug:           %02x:",
				    i - 1);
		}
		KLIPS_PRINTMORE(debug_rcv & DB_RX_IPAD,
				" %02x",
				idat[irs->ilen - 2 - padlen + i - 1]);
		if(i != idat[irs->ilen - 2 - padlen + i - 1]) {
			badpad = 1;
		}
		if((i % 16) == 0) {
			KLIPS_PRINTMORE(debug_rcv & DB_RX_IPAD,
					"\n");
		}
	}
	if((i % 16) != 1) {
		KLIPS_PRINTMORE(debug_rcv & DB_RX_IPAD,
						"\n");
	}
	if(badpad) {
		KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
			    "klips_debug:ipsec_rcv: "
			    "warning, decrypted packet from %s has bad padding\n",
			    irs->ipsaddr_txt);
		KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
			    "klips_debug:ipsec_rcv: "
			    "...may be bad decryption -- not dropped\n");
		ipsp->ips_errs.ips_encpad_errs += 1;
	}

	KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
		    "klips_debug:ipsec_rcv: "
		    "packet decrypted from %s: next_header = %d, padding = %d\n",
		    irs->ipsaddr_txt,
		    irs->next_header,
		    pad - 2 - irs->authlen);

	irs->ipp->tot_len = htons(ntohs(irs->ipp->tot_len) - (esphlen + pad));

	/*
	 * move the IP header forward by the size of the ESP header, which
	 * will remove the the ESP header from the packet.
	 */
	memmove((void *)(skb->data + esphlen),
		(void *)(skb->data), irs->iphlen);

	rcv_dmp("esp postmove", skb->data, skb->len);

	/* skb_pull below, will move up by esphlen */

	/* XXX not clear how this can happen, as the message indicates */
	if(skb->len < esphlen) {
		printk(KERN_WARNING
		       "klips_error:ipsec_rcv: "
		       "tried to skb_pull esphlen=%d, %d available.  This should never happen, please report.\n",
		       esphlen, (int)(skb->len));
		return IPSEC_RCV_ESP_DECAPFAIL;
	}
	skb_pull(skb, esphlen);

	irs->ipp = (struct iphdr *)skb->data;

	rcv_dmp("esp postpull", skb->data, skb->len);

	/* now, trip off the padding from the end */
	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv: "
		    "trimming to %d.\n",
		    irs->len - esphlen - pad);
	if(pad + esphlen <= irs->len) {
		skb_trim(skb, irs->len - esphlen - pad);
	} else {
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "bogus packet, size is zero or negative, dropping.\n");
		return IPSEC_RCV_DECAPFAIL;
	}

	return IPSEC_RCV_OK;
}


struct xform_functions esp_rcv_funcs[]={
	{	checks:         ipsec_rcv_esp_checks,
		setup_auth:     ipsec_rcv_esp_decrypt_setup,
		calc_auth:      ipsec_rcv_esp_authcalc,
		decrypt:        ipsec_rcv_esp_decrypt,
	},
};
#endif /* !CONFIG_IPSEC_ESP */

#ifdef CONFIG_IPSEC_AH
enum ipsec_rcv_value
ipsec_rcv_ah_checks(struct ipsec_rcv_state *irs,
		    struct sk_buff *skb)
{
	int ahminlen;

	ahminlen = irs->hard_header_len + sizeof(struct iphdr);

	/* take care not to deref this pointer until we check the minlen though */
	irs->protostuff.ahstuff.ahp = (struct ahhdr *) (skb->data + irs->iphlen);

	if((skb->len < ahminlen+sizeof(struct ahhdr)) ||
	   (skb->len < ahminlen+(irs->protostuff.ahstuff.ahp->ah_hl << 2))) {
		KLIPS_PRINT(debug_rcv & DB_RX_INAU,
			    "klips_debug:ipsec_rcv: "
			    "runt ah packet of skb->len=%d received from %s, dropped.\n",
			    skb->len,
			    irs->ipsaddr_txt);
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADLEN;
	}

	irs->said.spi = irs->protostuff.ahstuff.ahp->ah_spi;

	/* XXX we only support the one 12-byte authenticator for now */
	if(irs->protostuff.ahstuff.ahp->ah_hl != ((AHHMAC_HASHLEN+AHHMAC_RPLLEN) >> 2)) {
		KLIPS_PRINT(debug_rcv & DB_RX_INAU,
			    "klips_debug:ipsec_rcv: "
			    "bad authenticator length %ld, expected %lu from %s.\n",
			    (long)(irs->protostuff.ahstuff.ahp->ah_hl << 2),
			    (unsigned long) sizeof(struct ahhdr),
			    irs->ipsaddr_txt);
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADLEN;
	}

	return IPSEC_RCV_OK;
}


enum ipsec_rcv_value
ipsec_rcv_ah_setup_auth(struct ipsec_rcv_state *irs,
			struct sk_buff *skb,
			__u32          *replay,
			unsigned char **authenticator)
{
	struct ahhdr *ahp = irs->protostuff.ahstuff.ahp;

	*replay = ntohl(ahp->ah_rpl);
	*authenticator = ahp->ah_data;

	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value
ipsec_rcv_ah_authcalc(struct ipsec_rcv_state *irs,
		      struct sk_buff *skb)
{
	struct auth_alg *aa;
	struct ahhdr *ahp = irs->protostuff.ahstuff.ahp;
	union {
		MD5_CTX		md5;
		SHA1_CTX	sha1;
	} tctx;
	struct iphdr ipo;
	int ahhlen;

	aa = irs->authfuncs;

	/* copy the initialized keying material */
	memcpy(&tctx, irs->ictx, irs->ictx_len);

	ipo = *irs->ipp;
	ipo.tos = 0;	/* mutable RFC 2402 3.3.3.1.1.1 */
	ipo.frag_off = 0;
	ipo.ttl = 0;
	ipo.check = 0;


	/* do the sanitized header */
	(*aa->update)((void*)&tctx, (caddr_t)&ipo, sizeof(struct iphdr));

	/* XXX we didn't do the options here! */

	/* now do the AH header itself */
	ahhlen = AH_BASIC_LEN + (ahp->ah_hl << 2);
	(*aa->update)((void*)&tctx, (caddr_t)ahp,  ahhlen - AHHMAC_HASHLEN);

	/* now, do some zeroes */
	(*aa->update)((void*)&tctx, (caddr_t)zeroes,  AHHMAC_HASHLEN);

	/* finally, do the packet contents themselves */
	(*aa->update)((void*)&tctx,
		      (caddr_t)skb->data + irs->iphlen + ahhlen,
		      skb->len - irs->iphlen - ahhlen);

	(*aa->final)(irs->hash, (void *)&tctx);

	memcpy(&tctx, irs->octx, irs->octx_len);

	(*aa->update)((void *)&tctx, irs->hash, aa->hashlen);
	(*aa->final)(irs->hash, (void *)&tctx);

	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value
ipsec_rcv_ah_decap(struct ipsec_rcv_state *irs)
{
	struct ahhdr *ahp = irs->protostuff.ahstuff.ahp;
	struct sk_buff *skb;
	int ahhlen;

	skb=irs->skb;

	ahhlen = AH_BASIC_LEN + (ahp->ah_hl << 2);

	irs->ipp->tot_len = htons(ntohs(irs->ipp->tot_len) - ahhlen);
	irs->next_header  = ahp->ah_nh;

	/*
	 * move the IP header forward by the size of the AH header, which
	 * will remove the the AH header from the packet.
	 */
	memmove((void *)(skb->data + ahhlen),
		(void *)(skb->data), irs->iphlen);

	rcv_dmp("ah postmove", skb->data, skb->len);

	/* skb_pull below, will move up by ahhlen */

	/* XXX not clear how this can happen, as the message indicates */
	if(skb->len < ahhlen) {
		printk(KERN_WARNING
		       "klips_error:ipsec_rcv: "
		       "tried to skb_pull ahhlen=%d, %d available.  This should never happen, please report.\n",
		       ahhlen,
		       (int)(skb->len));
		return IPSEC_RCV_DECAPFAIL;
	}
	skb_pull(skb, ahhlen);

	irs->ipp = (struct iphdr *)skb->data;

	rcv_dmp("ah postpull", skb->data, skb->len);

	return IPSEC_RCV_OK;
}


struct xform_functions ah_rcv_funcs[]={
	{	checks:         ipsec_rcv_ah_checks,
		setup_auth:     ipsec_rcv_ah_setup_auth,
		calc_auth:      ipsec_rcv_ah_authcalc,
		decrypt:        ipsec_rcv_ah_decap,
	},
};

#endif /* CONFIG_IPSEC_AH */

#ifdef CONFIG_IPSEC_IPCOMP
enum ipsec_rcv_value
ipsec_rcv_ipcomp_checks(struct ipsec_rcv_state *irs,
			struct sk_buff *skb)
{
	int ipcompminlen;

	ipcompminlen = irs->hard_header_len + sizeof(struct iphdr);

	if(skb->len < (ipcompminlen + sizeof(struct ipcomphdr))) {
		KLIPS_PRINT(debug_rcv & DB_RX_INAU,
			    "klips_debug:ipsec_rcv: "
			    "runt comp packet of skb->len=%d received from %s, dropped.\n",
			    skb->len,
			    irs->ipsaddr_txt);
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADLEN;
	}

	irs->protostuff.ipcompstuff.compp = (struct ipcomphdr *)(skb->data + irs->iphlen);
	irs->said.spi = htonl((__u32)ntohs(irs->protostuff.ipcompstuff.compp->ipcomp_cpi));
	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value
ipsec_rcv_ipcomp_decomp(struct ipsec_rcv_state *irs)
{
	unsigned int flags = 0;
	struct ipsec_sa *ipsp = irs->ipsp;
	struct sk_buff *skb;

	skb=irs->skb;

	rcv_dmp("ipcomp", skb->data, skb->len);

	if(ipsp == NULL) {
		return IPSEC_RCV_SAIDNOTFOUND;
	}

#if 0
	/* we want to check that this wasn't the first SA on the list, because
	 * we don't support bare IPCOMP, for unexplained reasons. MCR
	 */
	if (ipsp->ips_onext != NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "Incoming packet with outer IPCOMP header SA:%s: not yet supported by KLIPS, dropped\n",
			    irs->sa_len ? irs->sa : " (error)");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}

		return IPSEC_RCV_IPCOMPALONE;
	}
#endif

	if(sysctl_ipsec_inbound_policy_check &&
	   ((((ntohl(ipsp->ips_said.spi) & 0x0000ffff) != ntohl(irs->said.spi)) &&
	     (ipsp->ips_encalg != ntohl(irs->said.spi))   /* this is a workaround for peer non-compliance with rfc2393 */
		    ))) {
		char sa2[SATOT_BUF];
		size_t sa_len2 = 0;

		sa_len2 = satot(&ipsp->ips_said, 0, sa2, sizeof(sa2));

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "Incoming packet with SA(IPCA):%s does not match policy SA(IPCA):%s cpi=%04x cpi->spi=%08x spi=%08x, spi->cpi=%04x for SA grouping, dropped.\n",
			    irs->sa_len ? irs->sa : " (error)",
			    ipsp != NULL ? (sa_len2 ? sa2 : " (error)") : "NULL",
			    ntohs(irs->protostuff.ipcompstuff.compp->ipcomp_cpi),
			    (__u32)ntohl(irs->said.spi),
			    ipsp != NULL ? (__u32)ntohl((ipsp->ips_said.spi)) : 0,
			    ipsp != NULL ? (__u16)(ntohl(ipsp->ips_said.spi) & 0x0000ffff) : 0);
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		return IPSEC_RCV_SAIDNOTFOUND;
	}

	ipsp->ips_comp_ratio_cbytes += ntohs(irs->ipp->tot_len);
	irs->next_header = irs->protostuff.ipcompstuff.compp->ipcomp_nh;

	skb = skb_decompress(skb, ipsp, &flags);
	if (!skb || flags) {
		spin_unlock(&tdb_lock);
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "skb_decompress() returned error flags=%x, dropped.\n",
			    flags);
		if (irs->stats) {
			if (flags)
				irs->stats->rx_errors++;
			else
				irs->stats->rx_dropped++;
		}
		return IPSEC_RCV_IPCOMPFAILED;
	}

	/* make sure we update the pointer */
	irs->skb = skb;
	
#ifdef NET_21
	irs->ipp = skb->nh.iph;
#else /* NET_21 */
	irs->ipp = skb->ip_hdr;
#endif /* NET_21 */

	ipsp->ips_comp_ratio_dbytes += ntohs(irs->ipp->tot_len);

	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "packet decompressed SA(IPCA):%s cpi->spi=%08x spi=%08x, spi->cpi=%04x, nh=%d.\n",
		    irs->sa_len ? irs->sa : " (error)",
		    (__u32)ntohl(irs->said.spi),
		    ipsp != NULL ? (__u32)ntohl((ipsp->ips_said.spi)) : 0,
		    ipsp != NULL ? (__u16)(ntohl(ipsp->ips_said.spi) & 0x0000ffff) : 0,
		    irs->next_header);
	KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, irs->ipp);

	return IPSEC_RCV_OK;
}


struct xform_functions ipcomp_rcv_funcs[]={
	{checks:  ipsec_rcv_ipcomp_checks,
	 decrypt: ipsec_rcv_ipcomp_decomp,
	},
};

#endif /* CONFIG_IPSEC_IPCOMP */

enum ipsec_rcv_value
ipsec_rcv_decap_once(struct ipsec_rcv_state *irs)
{
	int iphlen;
	unsigned char *dat;
	__u8 proto;
	struct in_addr ipsaddr;
	struct in_addr ipdaddr;
	int replay = 0;	/* replay value in AH or ESP packet */
	struct ipsec_sa* ipsnext = NULL;	/* next SA towards inside of packet */
	struct xform_functions *proto_funcs;
	struct ipsec_sa *newipsp;
	struct iphdr *ipp;
	struct sk_buff *skb;

	skb = irs->skb;
	irs->len = skb->len;
	dat = skb->data;
	ipp = irs->ipp;
	proto = ipp->protocol;
	ipsaddr.s_addr = ipp->saddr;
	addrtoa(ipsaddr, 0, irs->ipsaddr_txt, sizeof(irs->ipsaddr_txt));
	ipdaddr.s_addr = ipp->daddr;
	addrtoa(ipdaddr, 0, irs->ipdaddr_txt, sizeof(irs->ipdaddr_txt));

	iphlen = ipp->ihl << 2;
	irs->iphlen=iphlen;
	ipp->check = 0;			/* we know the sum is good */
	
	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv_decap_once: "
		    "decap (%d) from %s -> %s\n",
		    proto, irs->ipsaddr_txt, irs->ipdaddr_txt);

	switch(proto) {
#ifdef CONFIG_IPSEC_ESP
	case IPPROTO_ESP:
		proto_funcs = esp_rcv_funcs;
		break;
#endif /* !CONFIG_IPSEC_ESP */

#ifdef CONFIG_IPSEC_AH
	case IPPROTO_AH:
		proto_funcs = ah_rcv_funcs;
		break;
#endif /* !CONFIG_IPSEC_AH */

#ifdef CONFIG_IPSEC_IPCOMP
	case IPPROTO_COMP:
		proto_funcs = ipcomp_rcv_funcs;
		break;
#endif /* !CONFIG_IPSEC_IPCOMP */
	default:
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADPROTO;
	}

	/*
	 * Find tunnel control block and (indirectly) call the
	 * appropriate tranform routine. The resulting sk_buf
	 * is a valid IP packet ready to go through input processing.
	 */

	irs->said.dst.u.v4.sin_addr.s_addr = ipp->daddr;

	if(proto_funcs->checks) {
		enum ipsec_rcv_value retval = (*proto_funcs->checks)(irs, skb);

		if(retval < 0) {
			return retval;
		}
	}

	irs->said.proto = proto;
	irs->sa_len = satot(&irs->said, 0, irs->sa, sizeof(irs->sa));
	if(irs->sa_len == 0) {
		strcpy(irs->sa, "(error)");
	}

	newipsp = ipsec_sa_getbyid(&irs->said);
	if (newipsp == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "no ipsec_sa for SA:%s: incoming packet with no SA dropped\n",
			    irs->sa_len ? irs->sa : " (error)");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		return IPSEC_RCV_SAIDNOTFOUND;
	}

	/* MCR - XXX this is bizarre. ipsec_sa_getbyid returned it, having incremented the refcount,
	 * why in the world would we decrement it here?

	 ipsec_sa_put(irs->ipsp);*/ /* incomplete */

	/* If it is in larval state, drop the packet, we cannot process yet. */
	if(newipsp->ips_state == SADB_SASTATE_LARVAL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "ipsec_sa in larval state, cannot be used yet, dropping packet.\n");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		ipsec_sa_put(newipsp);
		return IPSEC_RCV_SAIDNOTLIVE;
	}

	if(newipsp->ips_state == SADB_SASTATE_DEAD) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "ipsec_sa in dead state, cannot be used any more, dropping packet.\n");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		ipsec_sa_put(newipsp);
		return IPSEC_RCV_SAIDNOTLIVE;
	}

	if(sysctl_ipsec_inbound_policy_check) {
		if(irs->ipp->saddr != ((struct sockaddr_in*)(newipsp->ips_addr_s))->sin_addr.s_addr) {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, src=%s of pkt does not agree with expected SA source address policy.\n",
				    irs->sa_len ? irs->sa : " (error)",
				    irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			ipsec_sa_put(newipsp);
			return IPSEC_RCV_FAILEDINBOUND;
		}

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "SA:%s, src=%s of pkt agrees with expected SA source address policy.\n",
			    irs->sa_len ? irs->sa : " (error)",
			    irs->ipsaddr_txt);

		/*
		 * at this point, we have looked up a new SA, and we want to make sure that if this
		 * isn't the first SA in the list, that the previous SA actually points at this one.
		 */
		if(irs->ipsp) {
			if(irs->ipsp->ips_inext != newipsp) {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "unexpected SA:%s: does not agree with ips->inext policy, dropped\n",
					    irs->sa_len ? irs->sa : " (error)");
				if(irs->stats) {
					irs->stats->rx_dropped++;
				}
				ipsec_sa_put(newipsp);
				return IPSEC_RCV_FAILEDINBOUND;
			}
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s grouping from previous SA is OK.\n",
				    irs->sa_len ? irs->sa : " (error)");
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s First SA in group.\n",
				    irs->sa_len ? irs->sa : " (error)");
		}

		/*
		 * previously, at this point, we checked if the back pointer from the new SA that
		 * we just found matched the back pointer. But, we won't do this check anymore,
		 * because we want to be able to nest SAs
		 */
	}

	/* okay, SA checks out, so free any previous SA, and record a new one */

	if(irs->ipsp) {
		ipsec_sa_put(irs->ipsp);
	}
	irs->ipsp=newipsp;

	/* note that the outer code will free the irs->ipsp if there is an error */


	/* now check the lifetimes */
	if(ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_bytes,   "bytes",  irs->sa,
				ipsec_life_countbased, ipsec_incoming, irs->ipsp) == ipsec_life_harddied ||
	   ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_addtime, "addtime",irs->sa,
				ipsec_life_timebased,  ipsec_incoming, irs->ipsp) == ipsec_life_harddied ||
	   ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_addtime, "usetime",irs->sa,
				ipsec_life_timebased,  ipsec_incoming, irs->ipsp) == ipsec_life_harddied ||
	   ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_packets, "packets",irs->sa,
				ipsec_life_countbased, ipsec_incoming, irs->ipsp) == ipsec_life_harddied) {
		ipsec_sa_delchain(irs->ipsp);
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_decap_once: "
			    "decap (%d) failed lifetime check\n",
			    proto);

		return IPSEC_RCV_LIFETIMEFAILED;
	}

	irs->authfuncs=NULL;
	/* authenticate, if required */
	switch(irs->ipsp->ips_authalg) {
#ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
	case AH_MD5:
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = ipsec_rcv_md5;
		irs->ictx = (void *)&((struct md5_ctx*)(irs->ipsp->ips_key_a))->ictx;
		irs->octx = (void *)&((struct md5_ctx*)(irs->ipsp->ips_key_a))->octx;
		irs->ictx_len = sizeof(((struct md5_ctx*)(irs->ipsp->ips_key_a))->ictx);
		irs->octx_len = sizeof(((struct md5_ctx*)(irs->ipsp->ips_key_a))->octx);
		break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */
#ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
	case AH_SHA:
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = ipsec_rcv_sha1;
		irs->ictx = (void *)&((struct sha1_ctx*)(irs->ipsp->ips_key_a))->ictx;
		irs->octx = (void *)&((struct sha1_ctx*)(irs->ipsp->ips_key_a))->octx;
		irs->ictx_len = sizeof(((struct sha1_ctx*)(irs->ipsp->ips_key_a))->ictx);
		irs->octx_len = sizeof(((struct sha1_ctx*)(irs->ipsp->ips_key_a))->octx);
		break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */
	case AH_NONE:
		irs->authlen = 0;
		break;
	default:
		irs->ipsp->ips_errs.ips_alg_errs += 1;
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADAUTH;
	}

	if(irs->authfuncs) {
		unsigned char *authenticator = NULL;

		irs->ilen = irs->len - iphlen - irs->authlen;
		if(irs->ilen <= 0) {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "runt %s packet with no data, dropping.\n",
				    (proto == IPPROTO_ESP ? "esp" : "ah"));
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_BADLEN;
		}

		if(proto_funcs->setup_auth) {
			enum ipsec_rcv_value retval
			    = (*proto_funcs->setup_auth)(irs, skb,
							 &replay,
							 &authenticator);
			if(retval < 0) {
				return retval;
			}
		}

		if(!authenticator) {
			irs->ipsp->ips_errs.ips_auth_errs += 1;
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_BADAUTH;
		}

		if(!ipsec_checkreplaywindow(irs->ipsp, replay)) {
			irs->ipsp->ips_errs.ips_replaywin_errs += 1;
			KLIPS_PRINT(debug_rcv & DB_RX_REPLAY,
				    "klips_debug:ipsec_rcv: "
				    "duplicate frame from %s, packet dropped\n",
				    irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REPLAYFAILED;
		}

		/*
		 * verify authenticator
		 */

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "encalg = %d, authalg = %d.\n",
			    irs->ipsp->ips_encalg,
			    irs->ipsp->ips_authalg);

		/* calculate authenticator */
		if(proto_funcs->calc_auth == NULL) {
			return IPSEC_RCV_BADAUTH;
		}
		(*proto_funcs->calc_auth)(irs, skb);

		if (memcmp(irs->hash, authenticator, irs->authlen)) {
			irs->ipsp->ips_errs.ips_auth_errs += 1;
			KLIPS_PRINT(debug_rcv & DB_RX_INAU,
				    "klips_debug:ipsec_rcv: "
				    "auth failed on incoming packet from %s: hash=%08x%08x%08x auth=%08x%08x%08x, dropped\n",
				    irs->ipsaddr_txt,
				    ntohl(*(__u32*)&irs->hash[0]),
				    ntohl(*(__u32*)&irs->hash[4]),
				    ntohl(*(__u32*)&irs->hash[8]),
				    ntohl(*(__u32*)authenticator),
				    ntohl(*((__u32*)authenticator + 1)),
				    ntohl(*((__u32*)authenticator + 2)));
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_AUTHFAILED;
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "authentication successful.\n");
		}

		/* Crypto hygiene: clear memory used to calculate autheticator.
		 * The length varies with the algorithm.
		 */
		memset(irs->hash, 0, irs->authlen);

		/* If the sequence number == 0, expire SA, it had rolled */
		if(irs->ipsp->ips_replaywin && !replay /* !irs->ipsp->ips_replaywin_lastseq */) {
			ipsec_sa_delchain(irs->ipsp);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "replay window counter rolled, expiring SA.\n");
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REPLAYROLLED;
		}

		/* now update the replay counter */
		if (!ipsec_updatereplaywindow(irs->ipsp, replay)) {
			irs->ipsp->ips_errs.ips_replaywin_errs += 1;
			KLIPS_PRINT(debug_rcv & DB_RX_REPLAY,
				    "klips_debug:ipsec_rcv: "
				    "duplicate frame from %s, packet dropped\n",
				    irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REPLAYROLLED;
		}
	}

	if(proto_funcs->decrypt) {
		enum ipsec_rcv_value retval =
		  (*proto_funcs->decrypt)(irs);

		if(retval != IPSEC_RCV_OK) {
			return retval;
		}
	}

	/*
	 *	Adjust pointers
	 */
	skb = irs->skb;
	irs->len = skb->len;
	dat = skb->data;

#ifdef NET_21
/*		skb->h.ipiph=(struct iphdr *)skb->data; */
	skb->nh.raw = skb->data;
	skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl << 2);

	memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
#else /* NET_21 */
	skb->h.iph=(struct iphdr *)skb->data;
	skb->ip_hdr=(struct iphdr *)skb->data;
	memset(skb->proto_priv, 0, sizeof(struct options));
#endif /* NET_21 */

	ipp = (struct iphdr *)dat;
	ipsaddr.s_addr = ipp->saddr;
	addrtoa(ipsaddr, 0, irs->ipsaddr_txt, sizeof(irs->ipsaddr_txt));
	ipdaddr.s_addr = ipp->daddr;
	addrtoa(ipdaddr, 0, irs->ipdaddr_txt, sizeof(irs->ipdaddr_txt));
	/*
	 *	Discard the original ESP/AH header
	 */
	ipp->protocol = irs->next_header;

	ipp->check = 0;	/* NOTE: this will be included in checksum */
	ipp->check = ip_fast_csum((unsigned char *)dat, iphlen >> 2);

	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv: "
		    "after <%s%s%s>, SA:%s:\n",
		    IPS_XFORM_NAME(irs->ipsp),
		    irs->sa_len ? irs->sa : " (error)");
	KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

	skb->protocol = htons(ETH_P_IP);
	skb->ip_summed = 0;

	ipsnext = irs->ipsp->ips_inext;
	if(sysctl_ipsec_inbound_policy_check) {
		if(ipsnext) {
			if(
				ipp->protocol != IPPROTO_AH
				&& ipp->protocol != IPPROTO_ESP
#ifdef CONFIG_IPSEC_IPCOMP
				&& ipp->protocol != IPPROTO_COMP
				&& (ipsnext->ips_said.proto != IPPROTO_COMP
				    || ipsnext->ips_inext)
#endif /* CONFIG_IPSEC_IPCOMP */
				&& ipp->protocol != IPPROTO_IPIP
				) {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "packet with incomplete policy dropped, last successful SA:%s.\n",
					    irs->sa_len ? irs->sa : " (error)");
				if(irs->stats) {
					irs->stats->rx_dropped++;
				}
				return IPSEC_RCV_FAILEDINBOUND;
			}
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, Another IPSEC header to process.\n",
				    irs->sa_len ? irs->sa : " (error)");
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "No ips_inext from this SA:%s.\n",
				    irs->sa_len ? irs->sa : " (error)");
		}
	}

#ifdef CONFIG_IPSEC_IPCOMP
	/* update ipcomp ratio counters, even if no ipcomp packet is present */
	if (ipsnext
	    && ipsnext->ips_said.proto == IPPROTO_COMP
	    && ipp->protocol != IPPROTO_COMP) {
		ipsnext->ips_comp_ratio_cbytes += ntohs(ipp->tot_len);
		ipsnext->ips_comp_ratio_dbytes += ntohs(ipp->tot_len);
	}
#endif /* CONFIG_IPSEC_IPCOMP */

	irs->ipsp->ips_life.ipl_bytes.ipl_count += irs->len;
	irs->ipsp->ips_life.ipl_bytes.ipl_last   = irs->len;

	if(!irs->ipsp->ips_life.ipl_usetime.ipl_count) {
		irs->ipsp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
	}
	irs->ipsp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
	irs->ipsp->ips_life.ipl_packets.ipl_count += 1;

#ifdef CONFIG_NETFILTER
	if(proto == IPPROTO_ESP || proto == IPPROTO_AH) {
		skb->nfmark = (skb->nfmark & (~(IPsecSAref2NFmark(IPSEC_SA_REF_MASK))))
			| IPsecSAref2NFmark(IPsecSA2SAref(irs->ipsp));
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "%s SA sets skb->nfmark=0x%x.\n",
			    proto == IPPROTO_ESP ? "ESP" : "AH",
			    (unsigned)skb->nfmark);
	}
#endif /* CONFIG_NETFILTER */

	return IPSEC_RCV_OK;
}


int
#ifdef PROTO_HANDLER_SINGLE_PARM
ipsec_rcv(struct sk_buff *skb)
#else /* PROTO_HANDLER_SINGLE_PARM */
#ifdef NET_21
ipsec_rcv(struct sk_buff *skb, unsigned short xlen)
#else /* NET_21 */
ipsec_rcv(struct sk_buff *skb, struct device *dev, struct options *opt,
		__u32 daddr_unused, unsigned short xlen, __u32 saddr,
				   int redo, struct inet_protocol *protocol)
#endif /* NET_21 */
#endif /* PROTO_HANDLER_SINGLE_PARM */
{
#ifdef NET_21
#ifdef CONFIG_IPSEC_DEBUG
	struct device *dev = skb->dev;
#endif /* CONFIG_IPSEC_DEBUG */
#endif /* NET_21 */
	unsigned char protoc;
	struct iphdr *ipp;
#if defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH)
#endif /* defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH) */

	struct ipsec_sa *ipsp = NULL;
	struct net_device_stats *stats = NULL;		/* This device's statistics */
	struct device *ipsecdev = NULL, *prvdev;
	struct ipsecpriv *prv;
	char name[9];
	int i;
	struct in_addr ipsaddr;
	struct in_addr ipdaddr;

	struct ipsec_sa* ipsnext = NULL;	/* next SA towards inside of packet */
	struct ipsec_rcv_state irs;

	/* Don't unlink in the middle of a turnaround */
	MOD_INC_USE_COUNT;

	memset(&irs, 0, sizeof(struct ipsec_rcv_state));

	if (skb == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb passed in.\n");
		goto rcvleave;
	}

	if (skb->data == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb->data passed in, packet is bogus, dropping.\n");
		goto rcvleave;
	}

#ifdef IPH_is_SKB_PULLED
	/* In Linux 2.4.4, the IP header has been skb_pull()ed before the
	   packet is passed to us. So we'll skb_push() to get back to it. */
	if (skb->data == skb->h.raw) {
		skb_push(skb, skb->h.raw - skb->nh.raw);
	}
#endif /* IPH_is_SKB_PULLED */

	/* dev->hard_header_len is unreliable and should not be used */
	irs.hard_header_len = skb->mac.raw ? (skb->data - skb->mac.raw) : 0;
	if((irs.hard_header_len < 0) || (irs.hard_header_len > skb_headroom(skb)))
		irs.hard_header_len = 0;

#ifdef NET_21
	/* if skb was cloned (most likely due to a packet sniffer such as
	   tcpdump being momentarily attached to the interface), make
	   a copy of our own to modify */
	if(skb_cloned(skb)) {
		/* include any mac header while copying.. */
		if(skb_headroom(skb) < irs.hard_header_len) {
			printk(KERN_WARNING "klips_error:ipsec_rcv: "
			       "tried to skb_push hhlen=%d, %d available.  This should never happen, please report.\n",
			       irs.hard_header_len,
			       skb_headroom(skb));
			goto rcvleave;
		}
		skb_push(skb, irs.hard_header_len);
		if
#ifdef SKB_COW_NEW
		  (skb_cow(skb, skb_headroom(skb)) != 0)
#else /* SKB_COW_NEW */
		  ((skb = skb_cow(skb, skb_headroom(skb))) == NULL)
#endif /* SKB_COW_NEW */
		{
			goto rcvleave;
		}
		if(skb->len < irs.hard_header_len) {
			printk(KERN_WARNING "klips_error:ipsec_rcv: "
			       "tried to skb_pull hhlen=%d, %d available.  This should never happen, please report.\n",
			       irs.hard_header_len,
			       skb->len);
			goto rcvleave;
		}
		skb_pull(skb, irs.hard_header_len);
	}

#endif /* NET_21 */

#if IP_FRAGMENT_LINEARIZE
	/* In Linux 2.4.4, we may have to reassemble fragments. They are
	   not assembled automatically to save TCP from having to copy
	   twice.
	*/
	if (skb_is_nonlinear(skb)) {
		if (skb_linearize(skb, GFP_ATOMIC) != 0) {
			goto rcvleave;
		}
	}
#endif /* IP_FRAGMENT_LINEARIZE */

	ipp = skb->nh.iph;
	ipsaddr.s_addr = ipp->saddr;
	addrtoa(ipsaddr, 0, irs.ipsaddr_txt, sizeof(irs.ipsaddr_txt));
	ipdaddr.s_addr = ipp->daddr;
	addrtoa(ipdaddr, 0, irs.ipdaddr_txt, sizeof(irs.ipdaddr_txt));
	irs.iphlen = ipp->ihl << 2;

	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "<<< Info -- ");
	KLIPS_PRINTMORE(debug_rcv && skb->dev, "skb->dev=%s ",
			skb->dev->name ? skb->dev->name : "NULL");
	KLIPS_PRINTMORE(debug_rcv && dev, "dev=%s ",
			dev->name ? dev->name : "NULL");
	KLIPS_PRINTMORE(debug_rcv, "\n");

	KLIPS_PRINT(debug_rcv && !(skb->dev && dev && (skb->dev == dev)),
		    "klips_debug:ipsec_rcv: "
		    "Informational -- **if this happens, find out why** skb->dev:%s is not equal to dev:%s\n",
		    skb->dev ? (skb->dev->name ? skb->dev->name : "NULL") : "NULL",
		    dev ? (dev->name ? dev->name : "NULL") : "NULL");

	protoc = ipp->protocol;
#ifndef NET_21
	if((!protocol) || (protocol->protocol != protoc)) {
		KLIPS_PRINT(debug_rcv & DB_RX_IPSA,
			    "klips_debug:ipsec_rcv: "
			    "protocol arg is NULL or unequal to the packet contents, this is odd, using value in packet.\n");
	}
#endif /* !NET_21 */

	if( (protoc != IPPROTO_AH) &&
#ifdef CONFIG_IPSEC_IPCOMP_disabled_until_we_register_IPCOMP_HANDLER
	    (protoc != IPPROTO_COMP) &&
#endif /* CONFIG_IPSEC_IPCOMP */
	    (protoc != IPPROTO_ESP) ) {
		KLIPS_PRINT(debug_rcv & DB_RX_IPSA,
			    "klips_debug:ipsec_rcv: Why the hell is someone "
			    "passing me a non-ipsec protocol = %d packet? -- dropped.\n",
			    protoc);
		goto rcvleave;
	}

	if(skb->dev) {
		for(i = 0; i < IPSEC_NUM_IF; i++) {
			sprintf(name, IPSEC_DEV_FORMAT, i);
			if(!strcmp(name, skb->dev->name)) {
				prv = (struct ipsecpriv *)(skb->dev->priv);
				if(prv) {
					stats = (struct net_device_stats *) &(prv->mystats);
				}
				ipsecdev = skb->dev;
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "Info -- pkt already proc'ed a group of ipsec headers, processing next group of ipsec headers.\n");
				break;
			}
			if((ipsecdev = __ipsec_dev_get(name)) == NULL) {
				KLIPS_PRINT(debug_rcv,
					    "klips_error:ipsec_rcv: "
					    "device %s does not exist\n",
					    name);
			}
			prv = ipsecdev ? (struct ipsecpriv *)(ipsecdev->priv) : NULL;
			prvdev = prv ? (struct device *)(prv->dev) : NULL;

#if 0
			KLIPS_PRINT(debug_rcv && prvdev,
				    "klips_debug:ipsec_rcv: "
				    "physical device for device %s is %s\n",
				    name,
				    prvdev->name);
#endif
			if(prvdev && skb->dev &&
			   !strcmp(prvdev->name, skb->dev->name)) {
				stats = prv ? ((struct net_device_stats *) &(prv->mystats)) : NULL;
				skb->dev = ipsecdev;
				KLIPS_PRINT(debug_rcv && prvdev,
					    "klips_debug:ipsec_rcv: "
					    "assigning packet ownership to virtual device %s from physical device %s.\n",
					    name, prvdev->name);
				if(stats) {
					stats->rx_packets++;
				}
				break;
			}
		}
	} else {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "device supplied with skb is NULL\n");
	}

	if(stats == NULL) {
		KLIPS_PRINT((debug_rcv),
			    "klips_error:ipsec_rcv: "
			    "packet received from physical I/F (%s) not connected to ipsec I/F.  Cannot record stats.  May not have SA for decoding.  Is IPSEC traffic expected on this I/F?  Check routing.\n",
			    skb->dev ? (skb->dev->name ? skb->dev->name : "NULL") : "NULL");
	}
		
	KLIPS_IP_PRINT(debug_rcv, ipp);

	/* begin decapsulating loop here */

	/*
	  The spinlock is to prevent any other process from
	  accessing or deleting the ipsec_sa hash table or any of the
	  ipsec_sa s while we are using and updating them.

	  This is not optimal, but was relatively straightforward
	  at the time.  A better way to do it has been planned for
	  more than a year, to lock the hash table and put reference
	  counts on each ipsec_sa instead.  This is not likely to happen
	  in KLIPS1 unless a volunteer contributes it, but will be
	  designed into KLIPS2.
	*/
	spin_lock(&tdb_lock);

	/* set up for decap loop */
	irs.stats= stats;
	irs.ipp  = ipp;
	irs.ipsp = NULL;
	irs.ilen = 0;
	irs.authlen=0;
	irs.authfuncs=NULL;
	irs.skb = skb;

	do {
	        int decap_stat;

	        decap_stat = ipsec_rcv_decap_once(&irs);

		if(decap_stat != IPSEC_RCV_OK) {
			spin_unlock(&tdb_lock);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: decap_once failed: %d\n",
				    decap_stat);
		
			goto rcvleave;
		}
	/* end decapsulation loop here */
	} while(   (irs.ipp->protocol == IPPROTO_ESP )
		|| (irs.ipp->protocol == IPPROTO_AH  )
#ifdef CONFIG_IPSEC_IPCOMP
		|| (irs.ipp->protocol == IPPROTO_COMP)
#endif /* CONFIG_IPSEC_IPCOMP */
		);

	/* set up for decap loop */
	ipp  =irs.ipp;
	ipsp =irs.ipsp;
	ipsnext = ipsp->ips_inext;
	skb = irs.skb;

	/* if there is an IPCOMP, but we don't have an IPPROTO_COMP,
	 * then we can just skip it
	 */
#ifdef CONFIG_IPSEC_IPCOMP
	if(ipsnext && ipsnext->ips_said.proto == IPPROTO_COMP) {
		ipsp = ipsnext;
		ipsnext = ipsp->ips_inext;
	}
#endif /* CONFIG_IPSEC_IPCOMP */

	/*
	 * XXX this needs to be locked from when it was first looked
	 * up in the decapsulation loop.  Perhaps it is better to put
	 * the IPIP decap inside the loop.
	 */
	if(ipsnext) {
		ipsp = ipsnext;
		irs.sa_len = satot(&irs.said, 0, irs.sa, sizeof(irs.sa));
		if(ipp->protocol != IPPROTO_IPIP) {
			spin_unlock(&tdb_lock);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, Hey!  How did this get through?  Dropped.\n",
				    irs.sa_len ? irs.sa : " (error)");
			if(stats) {
				stats->rx_dropped++;
			}
			goto rcvleave;
		}
		if(sysctl_ipsec_inbound_policy_check) {
			if((ipsnext = ipsp->ips_inext)) {
				char sa2[SATOT_BUF];
				size_t sa_len2;
				sa_len2 = satot(&ipsnext->ips_said, 0, sa2, sizeof(sa2));
				spin_unlock(&tdb_lock);
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "unexpected SA:%s after IPIP SA:%s\n",
					    sa_len2 ? sa2 : " (error)",
					    irs.sa_len ? irs.sa : " (error)");
				if(stats) {
					stats->rx_dropped++;
				}
				goto rcvleave;
			}
			if(ipp->saddr != ((struct sockaddr_in*)(ipsp->ips_addr_s))->sin_addr.s_addr) {
				spin_unlock(&tdb_lock);
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "SA:%s, src=%s of pkt does not agree with expected SA source address policy.\n",
					    irs.sa_len ? irs.sa : " (error)",
					    irs.ipsaddr_txt);
				if(stats) {
					stats->rx_dropped++;
				}
				goto rcvleave;
			}
		}

		/*
		 * XXX this needs to be locked from when it was first looked
		 * up in the decapsulation loop.  Perhaps it is better to put
		 * the IPIP decap inside the loop.
		 */
		ipsp->ips_life.ipl_bytes.ipl_count += skb->len;
		ipsp->ips_life.ipl_bytes.ipl_last   = skb->len;

		if(!ipsp->ips_life.ipl_usetime.ipl_count) {
			ipsp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
		}
		ipsp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
		ipsp->ips_life.ipl_packets.ipl_count += 1;

		if(skb->len < irs.iphlen) {
			spin_unlock(&tdb_lock);
			printk(KERN_WARNING "klips_debug:ipsec_rcv: "
			       "tried to skb_pull iphlen=%d, %d available.  This should never happen, please report.\n",
			       irs.iphlen,
			       (int)(skb->len));

			goto rcvleave;
		}
		skb_pull(skb, irs.iphlen);

#ifdef NET_21
		ipp = (struct iphdr *)skb->nh.raw = skb->data;
		skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl << 2);

		memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
#else /* NET_21 */
		ipp = skb->ip_hdr = skb->h.iph = (struct iphdr *)skb->data;

		memset(skb->proto_priv, 0, sizeof(struct options));
#endif /* NET_21 */
		ipsaddr.s_addr = ipp->saddr;
		addrtoa(ipsaddr, 0, irs.ipsaddr_txt, sizeof(irs.ipsaddr_txt));
		ipdaddr.s_addr = ipp->daddr;
		addrtoa(ipdaddr, 0, irs.ipdaddr_txt, sizeof(irs.ipdaddr_txt));

		skb->protocol = htons(ETH_P_IP);
		skb->ip_summed = 0;
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "IPIP tunnel stripped.\n");
		KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

		if(sysctl_ipsec_inbound_policy_check
		   /*
		      Note: "xor" (^) logically replaces "not equal"
		      (!=) and "bitwise or" (|) logically replaces
		      "boolean or" (||).  This is done to speed up
		      execution by doing only bitwise operations and
		      no branch operations
		   */
		   && (((ipp->saddr & ipsp->ips_mask_s.u.v4.sin_addr.s_addr)
				    ^ ipsp->ips_flow_s.u.v4.sin_addr.s_addr)
		       | ((ipp->daddr & ipsp->ips_mask_d.u.v4.sin_addr.s_addr)
				      ^ ipsp->ips_flow_d.u.v4.sin_addr.s_addr)) )
		{
			char sflow_txt[SUBNETTOA_BUF], dflow_txt[SUBNETTOA_BUF];

			subnettoa(ipsp->ips_flow_s.u.v4.sin_addr,
				ipsp->ips_mask_s.u.v4.sin_addr,
				0, sflow_txt, sizeof(sflow_txt));
			subnettoa(ipsp->ips_flow_d.u.v4.sin_addr,
				ipsp->ips_mask_d.u.v4.sin_addr,
				0, dflow_txt, sizeof(dflow_txt));
			spin_unlock(&tdb_lock);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, inner tunnel policy [%s -> %s] does not agree with pkt contents [%s -> %s].\n",
				    irs.sa_len ? irs.sa : " (error)",
				    sflow_txt,
				    dflow_txt,
				    irs.ipsaddr_txt,
				    irs.ipdaddr_txt);
			if(stats) {
				stats->rx_dropped++;
			}
			goto rcvleave;
		}
#ifdef CONFIG_NETFILTER
		skb->nfmark = (skb->nfmark & (~(IPsecSAref2NFmark(IPSEC_SA_REF_TABLE_MASK))))
			| IPsecSAref2NFmark(IPsecSA2SAref(ipsp));
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "IPIP SA sets skb->nfmark=0x%x.\n",
			    (unsigned)skb->nfmark);
#endif /* CONFIG_NETFILTER */
	}

	spin_unlock(&tdb_lock);

#ifdef NET_21
	if(stats) {
		stats->rx_bytes += skb->len;
	}
	if(skb->dst) {
		dst_release(skb->dst);
		skb->dst = NULL;
	}
	skb->pkt_type = PACKET_HOST;
	if(irs.hard_header_len &&
	   (skb->mac.raw != (skb->data - irs.hard_header_len)) &&
	   (irs.hard_header_len <= skb_headroom(skb))) {
		/* copy back original MAC header */
		memmove(skb->data - irs.hard_header_len, skb->mac.raw, irs.hard_header_len);
		skb->mac.raw = skb->data - irs.hard_header_len;
	}
#endif /* NET_21 */

#ifdef CONFIG_IPSEC_IPCOMP
	if(ipp->protocol == IPPROTO_COMP) {
		unsigned int flags = 0;

		if(sysctl_ipsec_inbound_policy_check) {
			KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
				"klips_debug:ipsec_rcv: "
				"inbound policy checking enabled, IPCOMP follows IPIP, dropped.\n");
			if (stats) {
				stats->rx_errors++;
			}
			goto rcvleave;
		}
		/*
		  XXX need a ipsec_sa for updating ratio counters but it is not
		  following policy anyways so it is not a priority
		*/
		skb = skb_decompress(skb, NULL, &flags);
		if (!skb || flags) {
			KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
				"klips_debug:ipsec_rcv: "
				"skb_decompress() returned error flags: %d, dropped.\n",
				flags);
			if (stats) {
				stats->rx_errors++;
			}
			goto rcvleave;
		}
	}
#endif /* CONFIG_IPSEC_IPCOMP */

#ifdef SKB_RESET_NFCT
	nf_conntrack_put(skb->nfct);
	skb->nfct = NULL;
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif /* CONFIG_NETFILTER_DEBUG */
#endif /* SKB_RESET_NFCT */
	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv: "
		    "netif_rx() called.\n");
	netif_rx(skb);

	MOD_DEC_USE_COUNT;
	return(0);

 rcvleave:
	if(skb) {
		ipsec_kfree_skb(skb);
	}

	MOD_DEC_USE_COUNT;
	return(0);
}

struct inet_protocol ah_protocol =
{
	ipsec_rcv,				/* AH handler */
	NULL,				/* TUNNEL error control */
#ifdef NETDEV_25
	1,				/* no policy */
#else
	0,				/* next */
	IPPROTO_AH,			/* protocol ID */
	0,				/* copy */
	NULL,				/* data */
	"AH"				/* name */
#endif
};

struct inet_protocol esp_protocol =
{
	ipsec_rcv,			/* ESP handler		*/
	NULL,				/* TUNNEL error control */
#ifdef NETDEV_25
	1,				/* no policy */
#else
	0,				/* next */
	IPPROTO_ESP,			/* protocol ID */
	0,				/* copy */
	NULL,				/* data */
	"ESP"				/* name */
#endif
};

#if 0
/* We probably don't want to install a pure IPCOMP protocol handler, but
   only want to handle IPCOMP if it is encapsulated inside an ESP payload
   (which is already handled) */
#ifdef CONFIG_IPSEC_IPCOMP
struct inet_protocol comp_protocol =
{
	ipsec_rcv,			/* COMP handler		*/
	NULL,				/* COMP error control	*/
#ifdef NETDEV_25
	1,				/* no policy */
#else
	0,				/* next */
	IPPROTO_COMP,			/* protocol ID */
	0,				/* copy */
	NULL,				/* data */
	"COMP"				/* name */
#endif
};
#endif /* CONFIG_IPSEC_IPCOMP */
#endif

/*
 * $Log: ipsec_rcv.c,v $
 * Revision 1.133  2003/10/31 02:27:55  mcr
 * 	pulled up port-selector patches and sa_id elimination.
 *
 * Revision 1.132.2.1  2003/10/29 01:30:41  mcr
 * 	elimited "struct sa_id".
 *
 * Revision 1.132  2003/09/02 19:51:48  mcr
 * 	fixes for PR#252.
 *
 * Revision 1.131  2003/07/31 22:47:16  mcr
 * 	preliminary (untested by FS-team) 2.5 patches.
 *
 * Revision 1.130  2003/04/03 17:38:25  rgb
 * Centralised ipsec_kfree_skb and ipsec_dev_{get,put}.
 * Clarified logic for non-connected devices.
 *
 * Revision 1.129  2003/02/06 02:21:34  rgb
 *
 * Moved "struct auth_alg" from ipsec_rcv.c to ipsec_ah.h .
 * Changed "struct ah" to "struct ahhdr" and "struct esp" to "struct esphdr".
 * Removed "#ifdef INBOUND_POLICY_CHECK_eroute" dead code.
 *
 * Revision 1.128  2002/12/13 20:58:03  rgb
 * Relegated MCR's recent "_dmp" routine to debug_verbose.
 * Cleaned up printing of source and destination addresses in debug output.
 *
 * Revision 1.127  2002/12/04 16:00:16  rgb
 *
 * Fixed AH decapsulation pointer update bug and added some comments and
 * debugging.
 * This bug was caught by west-ah-0[12].
 *
 * Revision 1.126  2002/11/04 05:03:43  mcr
 * 	fixes for IPCOMP. There were two problems:
 * 	1) the irs->ipp pointer was not being updated properly after
 * 	   the ESP descryption. The meant nothing for IPIP, as the
 * 	   later IP header overwrote the earlier one.
 *  	2) the more serious problem was that skb_decompress will
 * 	   usually allocate a new SKB, so we have to make sure that
 * 	   it doesn't get lost.
 * 	#2 meant removing the skb argument from the ->decrypt routine
 * 	and moving it to the irs->skb, so it could be value/result.
 *
 * Revision 1.125  2002/11/01 01:53:35  dhr
 *
 * fix typo
 *
 * Revision 1.124  2002/10/31 22:49:01  dhr
 *
 * - eliminate unused variable "hash"
 * - reduce scope of variable "authenticator"
 * - add comment on a couple of tricky bits
 *
 * Revision 1.123  2002/10/31 22:39:56  dhr
 *
 * use correct type for result of function calls
 *
 * Revision 1.122  2002/10/31 22:36:25  dhr
 *
 * simplify complex test
 *
 * Revision 1.121  2002/10/31 22:34:04  dhr
 *
 * ipsprev is never used: ditch it
 *
 * Revision 1.120  2002/10/31 22:30:21  dhr
 *
 * eliminate redundant assignments
 *
 * Revision 1.119  2002/10/31 22:27:43  dhr
 *
 * make whitespace canonical
 *
 * Revision 1.118  2002/10/30 05:47:17  rgb
 * Fixed cut-and-paste error mis-identifying comp runt as ah.
 *
 * Revision 1.117  2002/10/17 16:37:45  rgb
 * Remove compp intermediate variable and in-line its contents
 * where used
 *
 * Revision 1.116  2002/10/12 23:11:53  dhr
 *
 * [KenB + DHR] more 64-bit cleanup
 *
 * Revision 1.115  2002/10/07 19:06:58  rgb
 * Minor fixups and activation to west-rcv-nfmark-set-01 test to check for SA reference properly set on incoming.
 *
 * Revision 1.114  2002/10/07 18:31:31  rgb
 * Set saref on incoming packets.
 *
 * Revision 1.113  2002/09/16 21:28:12  mcr
 * 	adjust hash length for HMAC calculation - must look at whether
 * 	it is MD5 or SHA1.
 *
 * Revision 1.112  2002/09/16 21:19:15  mcr
 * 	fixes for west-ah-icmp-01 - length of AH header must be
 * 	calculated properly, and next_header field properly copied.
 *
 * Revision 1.111  2002/09/10 02:45:56  mcr
 * 	re-factored the ipsec_rcv function into several functions,
 * 	ipsec_rcv_decap_once, and a set of functions for AH, ESP and IPCOMP.
 * 	In addition, the MD5 and SHA1 functions are replaced with pointers.
 *
 * Revision 1.110  2002/08/30 06:34:33  rgb
 * Fix scope of shift in AH header length check.
 *
 * Revision 1.109  2002/08/27 16:49:20  rgb
 * Fixed ESP short packet DOS (and AH and IPCOMP).
 *
 * Revision 1.108  2002/07/24 18:44:54  rgb
 * Type fiddling to tame ia64 compiler.
 *
 * Revision 1.107  2002/05/27 18:58:18  rgb
 * Convert to dynamic ipsec device allocation.
 * Remove final vistiges of tdb references via IPSEC_KLIPS1_COMPAT.
 *
 * Revision 1.106  2002/05/23 07:15:21  rgb
 * Pointer clean-up.
 * Added refcount code.
 *
 * Revision 1.105  2002/05/14 02:35:06  rgb
 * Change all references to tdb, TDB or Tunnel Descriptor Block to ips,
 * ipsec_sa or ipsec_sa.
 * Change references to _TDB to _IPSA.
 *
 * Revision 1.104  2002/04/24 07:55:32  mcr
 * 	#include patches and Makefiles for post-reorg compilation.
 *
 * Revision 1.103  2002/04/24 07:36:30  mcr
 * Moved from ./klips/net/ipsec/ipsec_rcv.c,v
 *
 * Revision 1.102  2002/01/29 17:17:56  mcr
 * 	moved include of ipsec_param.h to after include of linux/kernel.h
 * 	otherwise, it seems that some option that is set in ipsec_param.h
 * 	screws up something subtle in the include path to kernel.h, and
 * 	it complains on the snprintf() prototype.
 *
 * Revision 1.101  2002/01/29 04:00:52  mcr
 * 	more excise of kversions.h header.
 *
 * Revision 1.100  2002/01/29 02:13:17  mcr
 * 	introduction of ipsec_kversion.h means that include of
 * 	ipsec_param.h must preceed any decisions about what files to
 * 	include to deal with differences in kernel source.
 *
 * Revision 1.99  2002/01/28 21:40:59  mcr
 * 	should use #if to test boolean option rather than #ifdef.
 *
 * Revision 1.98  2002/01/20 20:19:36  mcr
 * 	renamed option to IP_FRAGMENT_LINEARIZE.
 *
 * Revision 1.97  2002/01/12 02:55:36  mcr
 * 	fix for post-2.4.4 to linearize skb's when ESP packet
 * 	was assembled from fragments.
 *
 * Revision 1.96  2001/11/26 09:23:49  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.93.2.2  2001/10/22 20:54:07  mcr
 * 	include des.h, removed phony prototypes and fixed calling
 * 	conventions to match real prototypes.
 *
 * Revision 1.93.2.1  2001/09/25 02:22:22  mcr
 * 	struct tdb -> struct ipsec_sa.
 * 	lifetime checks moved to ipsec_life.c
 * 	some sa(tdb) manipulation functions renamed.
 *
 * Revision 1.95  2001/11/06 19:49:07  rgb
 * Added variable descriptions.
 * Removed unauthenticated sequence==0 check to prevent DoS.
 *
 * Revision 1.94  2001/10/18 04:45:20  rgb
 * 2.4.9 kernel deprecates linux/malloc.h in favour of linux/slab.h,
 * lib/freeswan.h version macros moved to lib/kversions.h.
 * Other compiler directive cleanups.
 *
 * Revision 1.93  2001/09/07 22:17:24  rgb
 * Fix for removal of transport layer protocol handler arg in 2.4.4.
 * Fix to accomodate peer non-conformance to IPCOMP rfc2393.
 *
 * Revision 1.92  2001/08/27 19:44:41  rgb
 * Fix error in comment.
 *
 * Revision 1.91  2001/07/20 19:31:48  dhr
 * [DHR] fix source and destination subnets of policy in diagnostic
 *
 * Revision 1.90  2001/07/06 19:51:09  rgb
 * Added inbound policy checking code for IPIP SAs.
 * Renamed unused function argument for ease and intuitive naming.
 *
 * Revision 1.89  2001/06/22 19:35:23  rgb
 * Disable ipcomp processing if we are handed a ipcomp packet with no esp
 * or ah header.
 * Print protocol if we are handed a non-ipsec packet.
 *
 * Revision 1.88  2001/06/20 06:30:47  rgb
 * Fixed transport mode IPCOMP policy check bug.
 *
 * Revision 1.87  2001/06/13 20:58:40  rgb
 * Added parentheses around assignment used as truth value to silence
 * compiler.
 *
 * Revision 1.86  2001/06/07 22:25:23  rgb
 * Added a source address policy check for tunnel mode.  It still does
 * not check client addresses and masks.
 * Only decapsulate IPIP if it is expected.
 *
 * Revision 1.85  2001/05/30 08:14:02  rgb
 * Removed vestiges of esp-null transforms.
 *
 * Revision 1.84  2001/05/27 06:12:11  rgb
 * Added structures for pid, packet count and last access time to eroute.
 * Added packet count to beginning of /proc/net/ipsec_eroute.
 *
 * Revision 1.83  2001/05/04 16:45:47  rgb
 * Remove unneeded code.  ipp is not used after this point.
 *
 * Revision 1.82  2001/05/04 16:36:00  rgb
 * Fix skb_cow() call for 2.4.4. (SS)
 *
 * Revision 1.81  2001/05/02 14:46:53  rgb
 * Fix typo for compiler directive to pull IPH back.
 *
 * Revision 1.80  2001/04/30 19:46:34  rgb
 * Update for 2.4.4.  We now receive the skb with skb->data pointing to
 * h.raw.
 *
 * Revision 1.79  2001/04/23 15:01:15  rgb
 * Added spin_lock() check to prevent double-locking for multiple
 * transforms and hence kernel lock-ups with SMP kernels.
 * Minor spin_unlock() adjustments to unlock before non-dependant prints
 * and IPSEC device stats updates.
 *
 * Revision 1.78  2001/04/21 23:04:24  rgb
 * Check if soft expire has already been sent before sending another to
 * prevent ACQUIRE flooding.
 *
 * Revision 1.77  2001/03/16 07:35:20  rgb
 * Ditch extra #if 1 around now permanent policy checking code.
 *
 * Revision 1.76  2001/02/27 22:24:54  rgb
 * Re-formatting debug output (line-splitting, joining, 1arg/line).
 * Check for satoa() return codes.
 *
 * Revision 1.75  2001/02/19 22:28:30  rgb
 * Minor change to virtual device discovery code to assert which I/F has
 * been found.
 *
 * Revision 1.74  2000/11/25 03:50:36  rgb
 * Oops fix by minor re-arrangement of code to avoid accessing a freed tdb.
 *
 * Revision 1.73  2000/11/09 20:52:15  rgb
 * More spinlock shuffling, locking earlier and unlocking later in rcv to
 * include ipcomp and prevent races, renaming some tdb variables that got
 * forgotten, moving some unlocks to include tdbs and adding a missing
 * unlock.  Thanks to Svenning for some of these.
 *
 * Revision 1.72  2000/11/09 20:11:22  rgb
 * Minor shuffles to fix non-standard kernel config option selection.
 *
 * Revision 1.71  2000/11/06 04:36:18  rgb
 * Ditched spin_lock_irqsave in favour of spin_lock.
 * Minor initial protocol check rewrite.
 * Clean up debug printing.
 * Clean up tdb handling on ipcomp.
 * Fixed transport mode null pointer de-reference without ipcomp.
 * Add Svenning's adaptive content compression.
 * Disabled registration of ipcomp handler.
 *
 * Revision 1.70  2000/10/30 23:41:43  henry
 * Hans-Joerg Hoexer's null-pointer fix
 *
 * Revision 1.69  2000/10/10 18:54:16  rgb
 * Added a fix for incoming policy check with ipcomp enabled but
 * uncompressible.
 *
 * Revision 1.68  2000/09/22 17:53:12  rgb
 * Fixed ipcomp tdb pointers update for policy checking.
 *
 * Revision 1.67  2000/09/21 03:40:58  rgb
 * Added more debugging to try and track down the cpi outward copy problem.
 *
 * Revision 1.66  2000/09/20 04:00:10  rgb
 * Changed static functions to DEBUG_NO_STATIC to reveal function names for
 * debugging oopsen.
 *
 * Revision 1.65  2000/09/19 07:07:16  rgb
 * Added debugging to inbound policy check for ipcomp.
 * Added missing spin_unlocks (thanks Svenning!).
 * Fixed misplaced tdbnext pointers causing mismatched ipip policy check.
 * Protect ipcomp policy check following ipip decap with sysctl switch.
 *
 * Revision 1.64  2000/09/18 21:27:29  rgb
 * 2.0 fixes.
 *
 * Revision 1.63  2000/09/18 02:35:50  rgb
 * Added policy checking to ipcomp and re-enabled policy checking by
 * default.
 * Optimised satoa calls.
 *
 * Revision 1.62  2000/09/17 21:02:32  rgb
 * Clean up debugging, removing slow timestamp debug code.
 *
 * Revision 1.61  2000/09/16 01:07:55  rgb
 * Fixed erroneous ref from struct ipcomp to struct ipcomphdr.
 *
 * Revision 1.60  2000/09/15 11:37:01  rgb
 * Merge in heavily modified Svenning Soerensen's <svenning@post5.tele.dk>
 * IPCOMP zlib deflate code.
 *
 * Revision 1.59  2000/09/15 04:56:20  rgb
 * Remove redundant satoa() call, reformat comment.
 *
 * Revision 1.58  2000/09/13 08:00:52  rgb
 * Flick on inbound policy checking.
 *
 * Revision 1.57  2000/09/12 03:22:19  rgb
 * Converted inbound_policy_check to sysctl.
 * Re-enabled policy backcheck.
 * Moved policy checks to top and within tdb lock.
 *
 * Revision 1.56  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.55  2000/08/28 18:15:46  rgb
 * Added MB's nf-debug reset patch.
 *
 * Revision 1.54  2000/08/27 01:41:26  rgb
 * More minor tweaks to the bad padding debug code.
 *
 * Revision 1.53  2000/08/24 16:54:16  rgb
 * Added KLIPS_PRINTMORE macro to continue lines without KERN_INFO level
 * info.
 * Tidied up device reporting at the start of ipsec_rcv.
 * Tidied up bad padding debugging and processing.
 *
 * Revision 1.52  2000/08/20 21:36:03  rgb
 * Activated pfkey_expire() calls.
 * Added a hard/soft expiry parameter to pfkey_expire().
 * Added sanity checking to avoid propagating zero or smaller-length skbs
 * from a bogus decryption.
 * Re-arranged the order of soft and hard expiry to conform to RFC2367.
 * Clean up references to CONFIG_IPSEC_PFKEYv2.
 *
 * Revision 1.51  2000/08/18 21:23:30  rgb
 * Improve bad padding warning so that the printk buffer doesn't get
 * trampled.
 *
 * Revision 1.50  2000/08/01 14:51:51  rgb
 * Removed _all_ remaining traces of DES.
 *
 * Revision 1.49  2000/07/28 13:50:53  rgb
 * Changed enet_statistics to net_device_stats and added back compatibility
 * for pre-2.1.19.
 *
 * Revision 1.48  2000/05/10 19:14:40  rgb
 * Only check usetime against soft and hard limits if the tdb has been
 * used.
 * Cast output of ntohl so that the broken prototype doesn't make our
 * compile noisy.
 *
 * Revision 1.47  2000/05/09 17:45:43  rgb
 * Fix replay bitmap corruption bug upon receipt of bogus packet
 * with correct SPI.  This was a DoS.
 *
 * Revision 1.46  2000/03/27 02:31:58  rgb
 * Fixed authentication failure printout bug.
 *
 * Revision 1.45  2000/03/22 16:15:37  rgb
 * Fixed renaming of dev_get (MB).
 *
 * Revision 1.44  2000/03/16 08:17:24  rgb
 * Hardcode PF_KEYv2 support.
 * Fixed minor bug checking AH header length.
 *
 * Revision 1.43  2000/03/14 12:26:59  rgb
 * Added skb->nfct support for clearing netfilter conntrack bits (MB).
 *
 * Revision 1.42  2000/01/26 10:04:04  rgb
 * Fixed inbound policy checking on transport mode bug.
 * Fixed noisy 2.0 printk arguments.
 *
 * Revision 1.41  2000/01/24 20:58:02  rgb
 * Improve debugging/reporting support for (disabled) inbound
 * policy checking.
 *
 * Revision 1.40  2000/01/22 23:20:10  rgb
 * Fixed up inboud policy checking code.
 * Cleaned out unused crud.
 *
 * Revision 1.39  2000/01/21 06:15:29  rgb
 * Added sanity checks on skb_push(), skb_pull() to prevent panics.
 * Fixed cut-and-paste debug_tunnel to debug_rcv.
 * Added inbound policy checking code, disabled.
 * Simplified output code by updating ipp to post-IPIP decapsulation.
 *
 * Revision 1.38  1999/12/22 05:08:36  rgb
 * Checked for null skb, skb->dev, skb->data, skb->dev->name, dev->name,
 * protocol and take appropriate action for sanity.
 * Set ipsecdev to NULL if device could not be determined.
 * Fixed NULL stats access bug if device could not be determined.
 *
 * Revision 1.37  1999/12/14 20:07:59  rgb
 * Added a default switch case to catch bogus encalg values.
 *
 * Revision 1.36  1999/12/07 18:57:57  rgb
 * Fix PFKEY symbol compile error (SADB_*) without pfkey enabled.
 *
 * Revision 1.35  1999/12/01 22:15:35  rgb
 * Add checks for LARVAL and DEAD SAs.
 * Change state of SA from MATURE to DYING when a soft lifetime is
 * reached and print debug warning.
 *
 * Revision 1.34  1999/11/23 23:04:03  rgb
 * Use provided macro ADDRTOA_BUF instead of hardcoded value.
 * Sort out pfkey and freeswan headers, putting them in a library path.
 *
 * Revision 1.33  1999/11/19 01:10:06  rgb
 * Enable protocol handler structures for static linking.
 *
 * Revision 1.32  1999/11/18 04:09:19  rgb
 * Replaced all kernel version macros to shorter, readable form.
 *
 * Revision 1.31  1999/11/17 15:53:39  rgb
 * Changed all occurrences of #include "../../../lib/freeswan.h"
 * to #include <freeswan.h> which works due to -Ilibfreeswan in the
 * klips/net/ipsec/Makefile.
 *
 * Revision 1.30  1999/10/26 15:09:07  rgb
 * Used debug compiler directives to shut up compiler for decl/assign
 * statement.
 *
 * Revision 1.29  1999/10/16 18:25:37  rgb
 * Moved SA lifetime expiry checks before packet processing.
 * Expire SA on replay counter rollover.
 *
 * Revision 1.28  1999/10/16 04:23:07  rgb
 * Add stats for replaywin_errs, replaywin_max_sequence_difference,
 * authentication errors, encryption size errors, encryption padding
 * errors, and time since last packet.
 *
 * Revision 1.27  1999/10/16 00:30:47  rgb
 * Added SA lifetime counting.
 *
 * Revision 1.26  1999/10/15 22:14:37  rgb
 * Add debugging.
 *
 * Revision 1.25  1999/10/08 18:37:34  rgb
 * Fix end-of-line spacing to sate whining PHMs.
 *
 * Revision 1.24  1999/10/03 18:54:51  rgb
 * Spinlock support for 2.3.xx.
 * Don't forget to undo spinlocks on error!
 *
 * Revision 1.23  1999/10/01 15:44:53  rgb
 * Move spinlock header include to 2.1> scope.
 *
 * Revision 1.22  1999/10/01 00:01:54  rgb
 * Added tdb structure locking.
 *
 * Revision 1.21  1999/09/18 11:42:12  rgb
 * Add Marc Boucher's tcpdump cloned packet fix.
 *
 * Revision 1.20  1999/09/17 23:50:25  rgb
 * Add Marc Boucher's hard_header_len patches.
 *
 * Revision 1.19  1999/09/10 05:31:36  henry
 * tentative fix for 2.0.38-crash bug (move chunk of new code into 2.2 #ifdef)
 *
 * Revision 1.18  1999/08/28 08:28:06  rgb
 * Delete redundant sanity check.
 *
 * Revision 1.17  1999/08/28 02:00:58  rgb
 * Add an extra sanity check for null skbs.
 *
 * Revision 1.16  1999/08/27 05:21:38  rgb
 * Clean up skb->data/raw/nh/h manipulation.
 * Add Marc Boucher's mods to aid tcpdump.
 *
 * Revision 1.15  1999/08/25 14:22:40  rgb
 * Require 4-octet boundary check only for ESP.
 *
 * Revision 1.14  1999/08/11 08:36:44  rgb
 * Add compiler directives to allow configuring out AH, ESP or transforms.
 *
 * Revision 1.13  1999/08/03 17:10:49  rgb
 * Cosmetic fixes and clarification to debug output.
 *
 * Revision 1.12  1999/05/09 03:25:36  rgb
 * Fix bug introduced by 2.2 quick-and-dirty patch.
 *
 * Revision 1.11  1999/05/08 21:23:57  rgb
 * Add casting to silence the 2.2.x compile.
 *
 * Revision 1.10  1999/05/05 22:02:31  rgb
 * Add a quick and dirty port to 2.2 kernels by Marc Boucher <marc@mbsi.ca>.
 *
 * Revision 1.9  1999/04/29 15:18:01  rgb
 * hange debugging to respond only to debug_rcv.
 * Change gettdb parameter to a pointer to reduce stack loading and
 * facilitate parameter sanity checking.
 *
 * Revision 1.8  1999/04/15 15:37:24  rgb
 * Forward check changes from POST1_00 branch.
 *
 * Revision 1.4.2.2  1999/04/13 20:32:45  rgb
 * Move null skb sanity check.
 * Silence debug a bit more when off.
 * Use stats more effectively.
 *
 * Revision 1.4.2.1  1999/03/30 17:10:32  rgb
 * Update AH+ESP bugfix.
 *
 * Revision 1.7  1999/04/11 00:28:59  henry
 * GPL boilerplate
 *
 * Revision 1.6  1999/04/06 04:54:27  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.5  1999/03/17 15:39:23  rgb
 * Code clean-up.
 * Bundling bug fix.
 * ESP_NULL esphlen and IV bug fix.
 *
 * Revision 1.4  1999/02/17 16:51:02  rgb
 * Ditch NET_IPIP dependancy.
 * Decapsulate recursively for an entire bundle.
 *
 * Revision 1.3  1999/02/12 21:22:47  rgb
 * Convert debugging printks to KLIPS_PRINT macro.
 * Clean-up cruft.
 * Process IPIP tunnels internally.
 *
 * Revision 1.2  1999/01/26 02:07:36  rgb
 * Clean up debug code when switched off.
 * Remove references to INET_GET_PROTOCOL.
 *
 * Revision 1.1  1999/01/21 20:29:11  rgb
 * Converted from transform switching to algorithm switching.
 *
 *
 * Id: ipsec_esp.c,v 1.16 1998/12/02 03:08:11 rgb Exp $
 *
 * Log: ipsec_esp.c,v $
 * Revision 1.16  1998/12/02 03:08:11  rgb
 * Fix incoming I/F bug in AH and clean up inconsistencies in the I/F
 * discovery routine in both AH and ESP.
 *
 * Revision 1.15  1998/11/30 13:22:51  rgb
 * Rationalised all the klips kernel file headers.  They are much shorter
 * now and won't conflict under RH5.2.
 *
 * Revision 1.14  1998/11/10 05:55:37  rgb
 * Add even more detail to 'wrong I/F' debug statement.
 *
 * Revision 1.13  1998/11/10 05:01:30  rgb
 * Clean up debug output to be quiet when disabled.
 * Add more detail to 'wrong I/F' debug statement.
 *
 * Revision 1.12  1998/10/31 06:39:32  rgb
 * Fixed up comments in #endif directives.
 * Tidied up debug printk output.
 * Convert to addrtoa and satoa where possible.
 *
 * Revision 1.11  1998/10/27 00:49:30  rgb
 * AH+ESP bundling bug has been squished.
 * Cosmetic brace fixing in code.
 * Newlines added before calls to ipsec_print_ip.
 * Fix debug output function ID's.
 *
 * Revision 1.10  1998/10/22 06:37:22  rgb
 * Fixed run-on error message to fit 80 columns.
 *
 * Revision 1.9  1998/10/20 02:41:04  rgb
 * Fixed a replay window size sanity test bug.
 *
 * Revision 1.8  1998/10/19 18:55:27  rgb
 * Added inclusion of freeswan.h.
 * sa_id structure implemented and used: now includes protocol.
 * \n bugfix to printk debug message.
 *
 * Revision 1.7  1998/10/09 04:23:03  rgb
 * Fixed possible DoS caused by invalid transform called from an ESP
 * packet.  This should not be a problem when protocol is added to the SA.
 * Sanity check added for null xf_input routine.  Sanity check added for null
 * socket buffer returned from xf_input routine.
 * Added 'klips_debug' prefix to all klips printk debug statements.
 *
 * Revision 1.6  1998/07/14 15:56:04  rgb
 * Set sdb->dev to virtual ipsec I/F.
 *
 * Revision 1.5  1998/06/30 18:07:46  rgb
 * Change for ah/esp_protocol stuct visible only if module.
 *
 * Revision 1.4  1998/06/30 00:12:46  rgb
 * Clean up a module compile error.
 *
 * Revision 1.3  1998/06/25 19:28:06  rgb
 * Readjust premature unloading of module on packet receipt.
 * Make protocol structure abailable to rest of kernel.
 * Use macro for protocol number.
 *
 * Revision 1.2  1998/06/23 02:49:34  rgb
 * Fix minor #include bug that prevented compiling without debugging.
 * Added code to check for presence of IPIP protocol if an incoming packet
 * is IPIP encapped.
 *
 * Revision 1.1  1998/06/18 21:27:44  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.9  1998/06/14 23:48:42  rgb
 * Fix I/F name comparison oops bug.
 *
 * Revision 1.8  1998/06/11 07:20:04  rgb
 * Stats fixed for rx_packets.
 *
 * Revision 1.7  1998/06/11 05:53:34  rgb
 * Added stats for rx error and good packet reporting.
 *
 * Revision 1.6  1998/06/05 02:27:28  rgb
 * Add rx_errors stats.
 * Fix DoS bug:  skb's not being freed on dropped packets.
 *
 * Revision 1.5  1998/05/27 21:21:29  rgb
 * Fix DoS potential bug.  skb was not being freed if the packet was bad.
 *
 * Revision 1.4  1998/05/18 22:31:37  rgb
 * Minor change in debug output and comments.
 *
 * Revision 1.3  1998/04/21 21:29:02  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.2  1998/04/12 22:03:19  rgb
 * Updated ESP-3DES-HMAC-MD5-96,
 * 	ESP-DES-HMAC-MD5-96,
 * 	AH-HMAC-MD5-96,
 * 	AH-HMAC-SHA1-96 since Henry started freeswan cvs repository
 * from old standards (RFC182[5-9] to new (as of March 1998) drafts.
 *
 * Fixed eroute references in /proc/net/ipsec*.
 *
 * Started to patch module unloading memory leaks in ipsec_netlink and
 * radij tree unloading.
 *
 * Revision 1.1  1998/04/09 03:05:59  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:04  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * Minor cosmetic changes.
 *
 * Revision 0.3  1996/11/20 14:35:48  ji
 * Minor Cleanup.
 * Rationalized debugging code.
 *
 * Revision 0.2  1996/11/02 00:18:33  ji
 * First limited release.
 *
 *
 */

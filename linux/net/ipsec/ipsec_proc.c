/*
 * @(#) /proc file system interface code.
 *
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs <rgb@freeswan.org>
 *                                 2001  Michael Richardson <mcr@freeswan.org>
 * Copyright (C) 2005 Michael Richardson <mcr@sandelman.ca>
 * Copyright (C) 2005-2008  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2006-2012 David McCullough <david_mccullough@mcafee.com>
 * Copyright (C) 2006-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2011 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2012  Paul Wouters  <paul@libreswan.org>
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

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38) && !defined(AUTOCONF_INCLUDED)
# include <linux/config.h>
#endif
#define __NO_VERSION__
#include <linux/module.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,26)
# include <linux/moduleparam.h>
#endif
#include <linux/kernel.h> /* printk() */
#include <linux/ip.h>          /* struct iphdr */

#include "openswan/ipsec_kversion.h"
#include "openswan/ipsec_param.h"

#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/in.h>          /* struct sockaddr_in */
#include <linux/skbuff.h>
#include <asm/uaccess.h>       /* copy_from_user */
#include <openswan.h>
#include <linux/spinlock.h> /* *lock* */

#include <net/ip.h>
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#endif /* CONFIG_PROC_FS */
#include <linux/netlink.h>

#include "openswan/radij.h"

#include "openswan/ipsec_life.h"
#include "openswan/ipsec_stats.h"
#include "openswan/ipsec_sa.h"

#include "openswan/ipsec_encap.h"
#include "openswan/ipsec_radij.h"
#include "openswan/ipsec_xform.h"
#include "openswan/ipsec_tunnel.h"
#include "openswan/ipsec_xmit.h"

#include "openswan/ipsec_rcv.h"
#include "openswan/ipsec_ah.h"
#include "openswan/ipsec_esp.h"
#include "openswan/ipsec_alg.h"

#ifdef CONFIG_KLIPS_IPCOMP
#include "openswan/ipcomp.h"
#endif /* CONFIG_KLIPS_IPCOMP */

#include "openswan/ipsec_proto.h"

#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>

#include <linux/in.h>
#if defined(IP_IPSEC_REFINFO) || defined(IP_IPSEC_BINDREF)
#define IPSEC_PROC_SHOW_SAREF_INFO
#endif

#ifdef CONFIG_PROC_FS

#ifdef IPSEC_PROC_SUBDIRS
static struct proc_dir_entry *proc_net_ipsec_dir = NULL;
static struct proc_dir_entry *proc_eroute_dir    = NULL;
static struct proc_dir_entry *proc_spi_dir       = NULL;
static struct proc_dir_entry *proc_spigrp_dir    = NULL;
static struct proc_dir_entry *proc_stats_dir     = NULL;
#endif

struct ipsec_birth_reply ipsec_ipv4_birth_packet;
struct ipsec_birth_reply ipsec_ipv6_birth_packet;

int debug_esp = 0;
int debug_ah = 0;
int sysctl_ipsec_inbound_policy_check = 1;
int debug_xmit = 0;
int debug_xform = 0;
int debug_eroute = 0;
int debug_spi = 0;
int debug_radij = 0;
int debug_pfkey = 0;
int debug_rcv = 0;
int debug_netlink = 0;
int sysctl_ipsec_debug_verbose = 0;
int sysctl_ipsec_debug_ipcomp =0;
int sysctl_ipsec_icmp = 0;
int sysctl_ipsec_tos = 0;

/*
 * this structure declares a single proc entry, saying where the parent is, etc.
 */
struct ipsec_proc_list {
	char                   *name;
	struct proc_dir_entry **parent;
	struct proc_dir_entry **dir;
        struct file_operations  seq_fsop;
	void                   *data;
};

#define DECREMENT_UNSIGNED(X, amount) ((amount < (X)) ? (X)-amount : 0)

#ifdef CONFIG_KLIPS_ALG
extern int ipsec_xform_get_info(char *buffer, char **start,
				off_t offset, int length IPSEC_PROC_LAST_ARG);
#endif

static void * proc_eroute_start(struct seq_file *m, loff_t *pos)
{
        struct rj_walkstate     *rjws = kmalloc(sizeof(struct rj_walkstate), GFP_KERNEL);
	if (! rjws)
		return NULL;

#if 0
	if (debug_radij & DB_RJ_DUMPTREES)
	  rj_dumptrees();			/* XXXXXXXXX */
#endif
        if(*pos > rnh_count) {
                kfree(rjws);
                return NULL;
        }

	spin_lock_bh(&eroute_lock);
        memset(rjws, 0, sizeof(struct rj_walkstate));

        if(rj_initwalk(rjws, rnh, NULL, NULL)) {
		spin_unlock_bh(&eroute_lock);
		kfree(rjws);
                return NULL;
        }
        rj_walktreeonce_top(rjws);
        rjws->walkonce_control = WALK_DODUPEKEY;
	spin_unlock_bh(&eroute_lock);

	return rjws;
}

static void   proc_eroute_stop(struct seq_file *m, void *v)
{
        if(v) {
                struct rj_walkstate *rjws = (struct rj_walkstate *)v;
                rj_finiwalk(rjws);
                kfree (v);
        }
}

static void * proc_eroute_next(struct seq_file *m, void *v, loff_t *pos)
{
        struct rj_walkstate *rjws = (struct rj_walkstate *)v;

	spin_lock_bh(&eroute_lock);
        do {
                switch(rjws->walkonce_control) {
                case WALK_PROCNODE:
                case WALK_DONE:
                        break;

                case WALK_DOTOP:
                        rj_walktreeonce_top(rjws);
                        rjws->walkonce_control = WALK_DODUPEKEY;
                        /* FALLTHROUGH */

                case WALK_DODUPEKEY:
                        rjws->walkonce_control = rj_walktreeonce(rjws);
                        break;
                }
        }  while(rjws->walkonce_control != WALK_PROCNODE &&
                 rjws->walkonce_control != WALK_DONE);
        spin_unlock_bh(&eroute_lock);
        if(rjws->walkonce_control == WALK_DONE) return NULL;

        rjws->walkonce_control = WALK_DODUPEKEY;
	(*pos)++;
	return v;
}

static int    proc_eroute_show(struct seq_file *m, void *v)
{
        struct rj_walkstate *rjws = (struct rj_walkstate *)v;

        if (rjws->current_node
            && !(rjws->current_node->rj_flags & RJF_ROOT)) {
                ipsec_rj_walker_procprint(m, rjws->current_node);
        }
        return 0;
}

static struct seq_operations proc_eroute_op = {
        .start =        proc_eroute_start,
        .next =         proc_eroute_next,
        .stop =         proc_eroute_stop,
        .show =         proc_eroute_show
};

static int
proc_eroute_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &proc_eroute_op);
}

struct ipsec_proc_list ipsec_proc_eroute = {
        .name   = "eroute",
        .parent = &proc_net_ipsec_dir,
        .dir    = &proc_eroute_dir,
};
struct ipsec_proc_list ipsec_proc_eroute_all = {
        .name   = "all",
        .parent = &proc_eroute_dir,
        .dir    = NULL,
        .seq_fsop = {
                .open           = proc_eroute_open,
                .read           = seq_read,
                .llseek         = seq_lseek,
                .release        = seq_release,
        },
};


struct spi_walk_state {
        unsigned int spi_total;                 /* total number of items in spi list */
        unsigned int spi_hash_num;              /* hash bucket sequenced through to */
        unsigned int spi_offset;                /* current place in list */
        struct ipsec_sa *spi_current;  /* has been locked with ipsec_sa_get */
};

static void * proc_spi_start(struct seq_file *m, loff_t *pos)
{
	int i;
        struct spi_walk_state *sws = kmalloc(sizeof(struct spi_walk_state), GFP_KERNEL);
	struct ipsec_sa *sa_p;

        if(sws == NULL) return NULL;
        memset(sws, 0, sizeof(struct spi_walk_state));

        /* count number of items */
	spin_lock_bh(&tdb_lock);
	for (i = 0; i < SADB_HASHMOD; i++) {
		for (sa_p = ipsec_sadb_hash[i];
		     sa_p;
		     sa_p = sa_p->ips_hnext) {
                        sws->spi_total++;
                }
        };

        if(*pos >= sws->spi_total) {
                spin_unlock_bh(&tdb_lock);
                kfree(sws);
                return NULL;
        }

        //printk("total: %u %d\n", sws->spi_total, *pos);

        /* now find the place in the system where we need to be */
        sws->spi_hash_num = 0;
        sws->spi_offset = 0;
        sws->spi_current = NULL;

        /* look for first stop, linear walk through hash chain */
	for (i = 0; i < SADB_HASHMOD && (sws->spi_offset <= *pos); i++) {
                sws->spi_hash_num   = i;
		for (sa_p = ipsec_sadb_hash[i];
		     sa_p && (sws->spi_offset <= *pos);
		     sa_p = sa_p->ips_hnext) {
                        if(sws->spi_offset == *pos) {
                                sws->spi_current = ipsec_sa_get(sa_p, IPSEC_REFPROC);
                        }
                        sws->spi_offset++;
                }
        }
	spin_unlock_bh(&tdb_lock);
        if(sws->spi_current == NULL) {
                /* did not found valid item */
                kfree(sws);
                return NULL;
        }
        //printk("spi_start: %u %u %u %p\n", sws->spi_total, sws->spi_hash_num,
        //       sws->spi_offset, sws->spi_current);

	return sws;
}

static void   proc_spi_stop(struct seq_file *m, void *v)
{
        if(v) {
                struct spi_walk_state *sws = (struct spi_walk_state *)v;
                if(sws->spi_current) ipsec_sa_put(sws->spi_current, IPSEC_REFPROC);
                sws->spi_current = NULL;
                kfree(sws);
        }
}

static void * proc_spi_next(struct seq_file *m, void *v, loff_t *pos)
{
        int i;
	struct ipsec_sa *sa_p;
        struct spi_walk_state *sws = (struct spi_walk_state *)v;


        //printk("spi_next 1 %u %u %u %p\n", sws->spi_total, sws->spi_hash_num,
        //       sws->spi_offset, sws->spi_current);

        /* free current item, if any */
        if(sws->spi_current) ipsec_sa_put(sws->spi_current, IPSEC_REFPROC);
        sws->spi_current = NULL;

	spin_lock_bh(&tdb_lock);
        if(sws->spi_offset > *pos) {
                /* reset search? */
                sws->spi_offset = 0;
                sws->spi_hash_num = 0;
        }

        /* find the next item in the list */
	for (i = sws->spi_hash_num; i < SADB_HASHMOD && (sws->spi_offset <= *pos); i++) {
                sws->spi_hash_num   = i;
		for (sa_p = sws->spi_current;
		     sa_p && (sws->spi_offset <= *pos);
		     sa_p = sa_p->ips_hnext) {
                        if(sws->spi_offset == *pos) {
                                sws->spi_current = ipsec_sa_get(sa_p, IPSEC_REFPROC);
                        } else {
                                sws->spi_offset++;
                        }
                }
        }
        spin_unlock_bh(&tdb_lock);

        if(sws->spi_current == NULL) {
                return NULL;
        }

        //printk("spi_next 2 %u %u %u %p\n", sws->spi_total, sws->spi_hash_num,
        //       sws->spi_offset, sws->spi_current);
	(*pos)++;
	return v;
}

/*
 * This function takes a buffer (with length), a lifetime name and type,
 * and formats a string to represent the current values of the lifetime.
 *
 * It returns the number of bytes that the format took (or would take,
 * if the buffer were large enough: snprintf semantics).
 * This is used in /proc routines and in debug output.
 */
static void
ipsec_lifetime_format(struct seq_file *m,
		      char *lifename,
		      enum ipsec_life_type timebaselife,
		      struct ipsec_lifetime64 *lifetime)
{
	__u64 count;

	if(timebaselife == ipsec_life_timebased) {
		count = ipsec_jiffieshz_elapsed(jiffies/HZ, lifetime->ipl_count);
	} else {
		count = lifetime->ipl_count;
	}

	if(lifetime->ipl_count > 1 ||
	   lifetime->ipl_soft      ||
	   lifetime->ipl_hard) {
		seq_printf(m, "%s(%Lu,%Lu,%Lu)",
			       lifename,
			       count,
			       lifetime->ipl_soft,
			       lifetime->ipl_hard);
	}
}

static int proc_spi_show(struct seq_file *m, void *v)
{
        struct spi_walk_state *sws = (struct spi_walk_state *)v;
	char sa[SATOT_BUF];
	char buf_s[SUBNETTOA_BUF];
	char buf_d[SUBNETTOA_BUF];
	size_t sa_len;
	struct ipsec_sa *sa_p = sws->spi_current;

        //printk("spi_show 1 %u %u %u %p\n", sws->spi_total, sws->spi_hash_num,
        //       sws->spi_offset, sws->spi_current);

	sa_len = satot(&sa_p->ips_said, 'x', sa, sizeof(sa));
        seq_printf(m, "%s ", sa_len ? sa : " (error)");
        seq_printf(m, "%s%s%s",
                   IPS_XFORM_NAME(sa_p));
        seq_printf(m, ": dir=%s",
		       (sa_p->ips_flags & EMT_INBOUND) ?
		       "in " : "out");

	if(sa_p->ips_addr_s) {
		sin_addrtot(sa_p->ips_addr_s, 0, buf_s, sizeof(buf_s));
		seq_printf(m, " src=%s", buf_s);
	}

	if((sa_p->ips_said.proto == IPPROTO_IPIP)
	   && (sa_p->ips_flags & (SADB_X_SAFLAGS_INFLOW
			   |SADB_X_SAFLAGS_POLICYONLY))) {
		if (sa_p->ips_flow_s.u.v4.sin_family == AF_INET) {
		subnettoa(sa_p->ips_flow_s.u.v4.sin_addr,
			  sa_p->ips_mask_s.u.v4.sin_addr,
			  0,
			  buf_s,
			  sizeof(buf_s));

		subnettoa(sa_p->ips_flow_d.u.v4.sin_addr,
			  sa_p->ips_mask_d.u.v4.sin_addr,
			  0,
			  buf_d,
			  sizeof(buf_d));
		} else {
		subnet6toa(&sa_p->ips_flow_s.u.v6.sin6_addr,
			  &sa_p->ips_mask_s.u.v6.sin6_addr,
			  0,
			  buf_s,
			  sizeof(buf_s));

		subnet6toa(&sa_p->ips_flow_d.u.v6.sin6_addr,
			  &sa_p->ips_mask_d.u.v6.sin6_addr,
			  0,
			  buf_d,
			  sizeof(buf_d));
		}

		seq_printf(m, " policy=%s->%s", buf_s, buf_d);
	}

	if(sa_p->ips_iv_bits) {
		int j;
		seq_printf(m, " iv_bits=%dbits iv=0x",
                           sa_p->ips_iv_bits);

#ifdef CONFIG_KLIPS_OCF
		if (!sa_p->ips_iv) {
			/* ocf doesn't set the IV, fake it for the UML tests */
			seq_printf(m, "0cf0");
			for (j = 0; j < (sa_p->ips_iv_bits / 8) - 2; j++) {
				seq_printf(m, "%02x",
                                           (int) ((((long)sa_p) >> j) & 0xff));
			}
		} else
#endif
		for(j = 0; j < sa_p->ips_iv_bits / 8; j++) {
			seq_printf(m, "%02x",
                                   (__u32)((__u8*)(sa_p->ips_iv))[j]);
		}
	}

	if(sa_p->ips_encalg || sa_p->ips_authalg) {
		if(sa_p->ips_replaywin) {
			seq_printf(m, " ooowin=%d",
				       sa_p->ips_replaywin);
		}
		if(sa_p->ips_errs.ips_replaywin_errs) {
			seq_printf(m, " ooo_errs=%d",
				       sa_p->ips_errs.ips_replaywin_errs);
		}
		if(sa_p->ips_replaywin_lastseq) {
		       seq_printf(m, " seq=%d",
				      sa_p->ips_replaywin_lastseq);
		}
		if(sa_p->ips_replaywin_bitmap) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
			seq_printf(m, " bit=0x%Lx",
				       sa_p->ips_replaywin_bitmap);
#else
			seq_printf(m, " bit=0x%x%08x",
				       (__u32)(sa_p->ips_replaywin_bitmap >> 32),
				       (__u32)sa_p->ips_replaywin_bitmap);
#endif
		}
		if(sa_p->ips_replaywin_maxdiff) {
			seq_printf(m, " max_seq_diff=%d",
				       sa_p->ips_replaywin_maxdiff);
		}
	}
	if(sa_p->ips_flags & ~EMT_INBOUND) {
		seq_printf(m, " flags=0x%x",
			       sa_p->ips_flags & ~EMT_INBOUND);
		seq_printf(m, "<");
		/* flag printing goes here */
		seq_printf(m, ">");
	}
	if(sa_p->ips_auth_bits) {
		seq_printf(m, " alen=%d",
			       sa_p->ips_auth_bits);
	}
	if(sa_p->ips_key_bits_a) {
		seq_printf(m, " aklen=%d",
			       sa_p->ips_key_bits_a);
	}
	if(sa_p->ips_errs.ips_auth_errs) {
		seq_printf(m, " auth_errs=%d",
			       sa_p->ips_errs.ips_auth_errs);
	}
	if(sa_p->ips_key_bits_e) {
		seq_printf(m, " eklen=%d",
			       sa_p->ips_key_bits_e);
	}
	if(sa_p->ips_errs.ips_encsize_errs) {
		seq_printf(m, " encr_size_errs=%d",
			       sa_p->ips_errs.ips_encsize_errs);
	}
	if(sa_p->ips_errs.ips_encpad_errs) {
		seq_printf(m, " encr_pad_errs=%d",
			       sa_p->ips_errs.ips_encpad_errs);
	}

	seq_printf(m, " life(c,s,h)=");

        ipsec_lifetime_format(m, "alloc",
                              ipsec_life_countbased,
                              &sa_p->ips_life.ipl_allocations);

        ipsec_lifetime_format(m, "bytes",
                              ipsec_life_countbased,
                              &sa_p->ips_life.ipl_bytes);

        ipsec_lifetime_format(m, "addtime",
                              ipsec_life_timebased,
                              &sa_p->ips_life.ipl_addtime);

        ipsec_lifetime_format(m, "usetime",
                              ipsec_life_timebased,
                              &sa_p->ips_life.ipl_usetime);

        ipsec_lifetime_format(m, "packets",
                              ipsec_life_countbased,
                              &sa_p->ips_life.ipl_packets);

	if(sa_p->ips_life.ipl_usetime.ipl_last) { /* XXX-MCR should be last? */
		seq_printf(m, " idle=%Ld",
			       ipsec_jiffieshz_elapsed(jiffies/HZ, sa_p->ips_life.ipl_usetime.ipl_last));
	}

#ifdef CONFIG_KLIPS_IPCOMP
	if(sa_p->ips_said.proto == IPPROTO_COMP &&
	   (sa_p->ips_comp_ratio_dbytes ||
	    sa_p->ips_comp_ratio_cbytes)) {
		seq_printf(m, " ratio=%Ld:%Ld",
			       sa_p->ips_comp_ratio_dbytes,
			       sa_p->ips_comp_ratio_cbytes);
	}
#endif /* CONFIG_KLIPS_IPCOMP */

#ifdef NAT_TRAVERSAL
	{
		char *natttype_name;

		switch(sa_p->ips_natt_type)
		{
		case 0:
			natttype_name="none";
			break;
		case ESPINUDP_WITH_NON_IKE:
			natttype_name="nonike";
			break;
		case ESPINUDP_WITH_NON_ESP:
			natttype_name="nonesp";
			break;
		default:
			natttype_name = "unknown";
			break;
		}

		seq_printf(m, " natencap=%s",
			       natttype_name);

		seq_printf(m, " natsport=%d",
			       sa_p->ips_natt_sport);

		seq_printf(m, " natdport=%d",
			       sa_p->ips_natt_dport);
	}
#else
	seq_printf(m, " natencap=na");
#endif /* NAT_TRAVERSAL */

	/* we decrement by one, because this SA has been referenced in order to dump this info */
	seq_printf(m, " refcount=%d",
		       atomic_read(&sa_p->ips_refcount)-1);

	seq_printf(m, " ref=%d",
		       sa_p->ips_ref);
	seq_printf(m, " refhim=%d",
		       sa_p->ips_refhim);

	if(sa_p->ips_out) {
		seq_printf(m, " outif=%s:%d",
				      sa_p->ips_out->name,
				      sa_p->ips_transport_direct);
	}
	if(debug_xform) {
		seq_printf(m, " reftable=%lu refentry=%lu",
		       (unsigned long)IPsecSAref2table(sa_p->ips_ref),
		       (unsigned long)IPsecSAref2entry(sa_p->ips_ref));
	}

	seq_printf(m, "\n");
        return 0;
}

static struct seq_operations proc_spi_op = {
        .start =        proc_spi_start,
        .next =         proc_spi_next,
        .stop =         proc_spi_stop,
        .show =         proc_spi_show
};

static int
proc_spi_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &proc_spi_op);
}

struct ipsec_proc_list ipsec_proc_spi = {
        .name   = "spi",
        .parent = &proc_net_ipsec_dir,
        .dir    = &proc_spi_dir,
};
struct ipsec_proc_list ipsec_proc_spi_all = {
        .name   = "all",
        .parent = &proc_spi_dir,
        .dir    = NULL,
        .seq_fsop = {
                .open           = proc_spi_open,
                .read           = seq_read,
                .llseek         = seq_lseek,
                .release        = seq_release,
        },
};

static int proc_spigrp_show(struct seq_file *m, void *v)
{
        struct spi_walk_state *sws = (struct spi_walk_state *)v;
	char sa[SATOT_BUF];
	size_t sa_len;
	struct ipsec_sa *sa_p = sws->spi_current;

        while(sa_p != NULL) {
                sa_len = satot(&sa_p->ips_said,
                               'x', sa, sizeof(sa));

                seq_printf(m, "%s ", sa_len ? sa : " (error)");

                sa_p = sa_p->ips_next;
        }
        seq_printf(m, "\n");

        return 0;
}

/* reuses all the spi walk mechanism, same walk, different data */
static struct seq_operations proc_spigrp_op = {
        .start =        proc_spi_start,
        .next =         proc_spi_next,
        .stop =         proc_spi_stop,
        .show =         proc_spigrp_show
};

static int
proc_spigrp_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &proc_spigrp_op);
}

struct ipsec_proc_list ipsec_proc_spigrp = {
        .name   = "spigrp",
        .parent = &proc_net_ipsec_dir,
        .dir    = &proc_spigrp_dir,
};
struct ipsec_proc_list ipsec_proc_spigrp_all = {
        .name   = "all",
        .parent = &proc_spigrp_dir,
        .dir    = NULL,
        .seq_fsop = {
                .open           = proc_spigrp_open,
                .read           = seq_read,
                .llseek         = seq_lseek,
                .release        = seq_release,
        },
};


static void * proc_tncfg_start(struct seq_file *m, loff_t *pos)
{
        unsigned int *ifnump = kmalloc(sizeof(unsigned int), GFP_KERNEL);
	if (! ifnump)
		return NULL;
	*ifnump = *pos;
	return ifnump;
}

static void   proc_tncfg_stop(struct seq_file *m, void *v)
{
        if(v) kfree (v);
}

static void * proc_tncfg_next(struct seq_file *m, void *v, loff_t *pos)
{
        unsigned int *ifnump = (unsigned int *) v;

	*pos = ++(*ifnump);
        if(*ifnump >= (IPSEC_NUM_IFMAX-1)) return NULL;

        /* else, return the increment */
	return ifnump;
}

static int    proc_tncfg_show(struct seq_file *m, void *v)
{
	char name[9];
        unsigned int *ifnump = (unsigned int *) v;
	struct net_device *dev, *privdev;
        struct ipsecpriv *priv;

        ipsec_snprintf(name, (ssize_t) sizeof(name), IPSEC_DEV_FORMAT, *ifnump);
        dev = __ipsec_dev_get(name);
        if(dev) {
                priv = netdev_to_ipsecpriv(dev);
                seq_printf(m, "%s",dev->name);
                if(priv) {
                        privdev = (struct net_device *)(priv->dev);
                        seq_printf(m, " -> %s",
                                   privdev ? privdev->name : "NULL");
                        seq_printf(m, " mtu=%d(%d) -> %d",
                                   dev->mtu,
                                   priv->mtu,
                                   privdev ? privdev->mtu : 0);
                } else {
                        KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
                                    "klips_debug:ipsec_tncfg_get_info: device '%s' has no private data space!\n",
                                    dev->name);
                }
		seq_printf(m, "\n");
        }
        return 0;
}

static struct seq_operations proc_tncfg_op = {
        .start =        proc_tncfg_start,
        .next =         proc_tncfg_next,
        .stop =         proc_tncfg_stop,
        .show =         proc_tncfg_show
};

static int proc_tncfg_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &proc_tncfg_op);
}

struct ipsec_proc_list ipsec_proc_tncfg = {
        .name   = "tncfg",
        .parent = &proc_net_ipsec_dir,
        .seq_fsop = {
                .open           = proc_tncfg_open,
                .read           = seq_read,
                .llseek         = seq_lseek,
                .release        = seq_release,
        },
};

static int proc_version_show(struct seq_file *m, void *v)
{
	seq_printf(m, "Openswan version: %s\n", ipsec_version_code());
	return 0;
}

static int proc_version_open(struct inode *inode, struct file *file)
{
        return single_open(file, proc_version_show, NULL);
}

struct ipsec_proc_list ipsec_proc_version = {
        .name   = "version",
        .parent = &proc_net_ipsec_dir,
        .seq_fsop = {
                .open           = proc_version_open,
                .read           = seq_read,
                .llseek         = seq_lseek,
                .release        = single_release,
        },
};


static int proc_saref_info_show(struct seq_file *m, void *v)
{

#ifdef IP_IPSEC_REFINFO
        seq_printf(m, "refinfo patch applied\n");
#endif

#ifdef IP_IPSEC_BINDREF
        seq_printf(m, "bindref patch applied\n");
#endif

#ifdef CONFIG_INET_IPSEC_SAREF
        seq_printf(m, "saref enabled\n");
#else
        seq_printf(m, "saref disabled\n");
#endif
        return 0;
}
static int proc_saref_info_open(struct inode *inode, struct file *file)
{
        return single_open(file, proc_saref_info_show, NULL);
}

struct ipsec_proc_list ipsec_proc_saref_info = {
        .name   = "saref",
        .parent = &proc_net_ipsec_dir,
        .seq_fsop = {
                .open           = proc_saref_info_open,
                .read           = seq_read,
                .llseek         = seq_lseek,
                .release        = single_release,
        },
};


#ifdef CONFIG_KLIPS_OCF
unsigned int ocf_available = 1;
#else
unsigned int ocf_available = 0;
#endif
module_param(ocf_available,int,0644);

static int proc_ocf_show(struct seq_file *m, void *v)
{
        seq_printf(m, "%d\n", ocf_available);
	return 0;
}

static int proc_ocf_open(struct inode *inode, struct file *file)
{
        return single_open(file, proc_ocf_show, NULL);
}

struct ipsec_proc_list ipsec_proc_ocf = {
        .name   = "ocf",
        .parent = &proc_net_ipsec_dir,
        .seq_fsop = {
                .open           = proc_ocf_open,
                .read           = seq_read,
                .llseek         = seq_lseek,
                .release        = single_release,
        },
};


#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
unsigned int natt_available = 1;
#elif defined (HAVE_UDP_ENCAP_CONVERT)
unsigned int natt_available = 2;
#else
unsigned int natt_available = 0;
#endif
module_param(natt_available,int,0644);

static int proc_natt_show(struct seq_file *m, void *v)
{
        seq_printf(m, "%d\n", natt_available);
	return 0;
}

static int proc_natt_open(struct inode *inode, struct file *file)
{
        return single_open(file, proc_natt_show, NULL);
}

struct ipsec_proc_list ipsec_proc_natt = {
        .name   = "natt",
        .parent = &proc_net_ipsec_dir,
        .seq_fsop = {
                .open           = proc_natt_open,
                .read           = seq_read,
                .llseek         = seq_lseek,
                .release        = single_release,
        },
};

static int proc_klipsdebug_show(struct seq_file *m, void *v)
{
        seq_printf(m, "debug_tunnel=%08x.\n", debug_tunnel);
        seq_printf(m, "debug_xform=%08x.\n",  debug_xform);
        seq_printf(m, "debug_eroute=%08x.\n", debug_eroute);
        seq_printf(m, "debug_spi=%08x.\n",    debug_spi);
        seq_printf(m, "debug_radij=%08x.\n",  debug_radij);
        seq_printf(m, "debug_esp=%08x.\n",    debug_esp);
        seq_printf(m, "debug_ah=%08x.\n",     debug_ah);
        seq_printf(m, "debug_rcv=%08x.\n",    debug_rcv);
        seq_printf(m, "debug_pfkey=%08x.\n",  debug_pfkey);

	return 0;
}

static int proc_klipsdebug_open(struct inode *inode, struct file *file)
{
        return single_open(file, proc_klipsdebug_show, NULL);
}

struct ipsec_proc_list ipsec_proc_klipsdebug = {
        .name   = "klipsdebug",
        .parent = &proc_net_ipsec_dir,
        .seq_fsop = {
                .open           = proc_klipsdebug_open,
                .read           = seq_read,
                .llseek         = seq_lseek,
                .release        = single_release,
        },
};

struct ipsec_proc_list ipsec_proc_stats = {
        .name   = "stats",
        .parent = &proc_net_ipsec_dir,
        .dir    = &proc_stats_dir
};
static int proc_trap_count_show(struct seq_file *m, void *v)
{
        seq_printf(m, "%d\n", ipsec_xmit_trap_count);
	return 0;
}

static int proc_trap_count_open(struct inode *inode, struct file *file)
{
        return single_open(file, proc_trap_count_show, NULL);
}

struct ipsec_proc_list ipsec_proc_trap_count = {
        .name   = "trap_count",
        .parent = &proc_stats_dir,
        .seq_fsop = {
                .open           = proc_trap_count_open,
                .read           = seq_read,
                .llseek         = seq_lseek,
                .release        = single_release,
        },
};
static int proc_trap_sendcount_show(struct seq_file *m, void *v)
{
        seq_printf(m, "%d\n", ipsec_xmit_trap_sendcount);
	return 0;
}

static int proc_trap_sendcount_open(struct inode *inode, struct file *file)
{
        return single_open(file, proc_trap_sendcount_show, NULL);
}

struct ipsec_proc_list ipsec_proc_trap_sendcount = {
        .name   = "trap_sendcount",
        .parent = &proc_stats_dir,
        .seq_fsop = {
                .open           = proc_trap_sendcount_open,
                .read           = seq_read,
                .llseek         = seq_lseek,
                .release        = single_release,
        },
};
#endif /* CONFIG_PROC_FS */

struct ipsec_proc_list ipsec_proc_xforms = {
        .name   = "xforms",
        .parent = &proc_net_ipsec_dir,
        .dir    = NULL,
        .seq_fsop = {
                .open           = proc_alg_open,
                .read           = seq_read,
                .llseek         = seq_lseek,
                .release        = seq_release,
        },
};


static struct ipsec_proc_list *proc_items[]={
        &ipsec_proc_eroute,
        &ipsec_proc_eroute_all,
        &ipsec_proc_natt,
        &ipsec_proc_version,
        &ipsec_proc_ocf,
        &ipsec_proc_klipsdebug,
        &ipsec_proc_stats,
        &ipsec_proc_trap_count,
        &ipsec_proc_trap_sendcount,
        &ipsec_proc_tncfg,
        &ipsec_proc_saref_info,
        &ipsec_proc_spi,
        &ipsec_proc_spi_all,
        &ipsec_proc_spigrp,
        &ipsec_proc_spigrp_all,
        &ipsec_proc_xforms,
        NULL,
};

int
ipsec_proc_init()
{
	int error = 0;
#ifdef IPSEC_PROC_SUBDIRS
	struct proc_dir_entry *item;
#endif

	/*
	 * just complain because pluto won't run without /proc!
	 */
#ifndef CONFIG_PROC_FS
#error You must have PROC_FS built in to use KLIPS
#endif

	/* create /proc/net/ipsec */

	proc_net_ipsec_dir = proc_mkdir("ipsec", PROC_NET);
	if(proc_net_ipsec_dir == NULL) {
		/* no point in continuing */
		return 1;
	}

	{
		struct ipsec_proc_list **iit;
		struct ipsec_proc_list *it;

		iit=proc_items;
		while(*iit != NULL) {
                        it = *iit;
			if(it->dir) {
				/* make a dir instead */
				item = proc_mkdir(it->name, *it->parent);
				*it->dir = item;
			} else {
                                unsigned int proc_mode = strcmp(it->name,"version") == 0 ? 0444 : 0400;
                                item = proc_create_data(it->name, proc_mode,
                                                        *it->parent,
                                                        &it->seq_fsop, it);
                        }
                        if(item == NULL) {
				error |= 1;
			}
			iit++;
		}
	}

	/* now create some symlinks to provide compatibility */
        /* XXX get rid of these from user space finally */
	proc_symlink("ipsec_eroute", PROC_NET, "ipsec/eroute/all");
	proc_symlink("ipsec_spi",    PROC_NET, "ipsec/spi/all");
	proc_symlink("ipsec_spigrp", PROC_NET, "ipsec/spigrp/all");
	proc_symlink("ipsec_tncfg",  PROC_NET, "ipsec/tncfg");
	proc_symlink("ipsec_version",PROC_NET, "ipsec/version");
	proc_symlink("ipsec_klipsdebug",PROC_NET,"ipsec/klipsdebug");

	return error;
}

void
ipsec_proc_cleanup()
{
	{
		struct ipsec_proc_list **iit;
		struct ipsec_proc_list *it;

		/* find end of list */
		iit=proc_items;
		while(*iit != NULL) {
			iit++;
		}
		iit--;

		do {
                        it = *iit;
			remove_proc_entry(it->name, *it->parent);
			iit--;
		} while(iit >= proc_items);
	}


	remove_proc_entry("ipsec_klipsdebug", PROC_NET);
	remove_proc_entry("ipsec_eroute",     PROC_NET);
	remove_proc_entry("ipsec_spi",        PROC_NET);
	remove_proc_entry("ipsec_spigrp",     PROC_NET);
	remove_proc_entry("ipsec_tncfg",      PROC_NET);
	remove_proc_entry("ipsec_version",    PROC_NET);
	remove_proc_entry("ipsec",            PROC_NET);
}

/*
 *
 * Local variables:
 * c-file-style: "linux"
 * End:
 *
 */

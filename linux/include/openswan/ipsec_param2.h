/*
 * header file for Openswan kernel compat
 * Copyright (C) 2009 Michael Richardson <mcr@sandelman.ca>
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 * 
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#ifndef _IPSEC_PARAM2_H_
#define _IPSEC_PARAM2_H_

/* nicely, latest netdevice.h includes this define */
#ifndef HAVE_NETDEV_PRIV
#define netdev_priv(dev) (dev->priv)
#endif

/* 
 * Stupid kernel API differences in APIs. Not only do some
 * kernels not have ip_select_ident, but some have differing APIs,
 * and SuSE has one with one parameter, but no way of checking to
 * see what is really what.
 */

#ifdef SUSE_LINUX_2_4_19_IS_STUPID
#define KLIPS_IP_SELECT_IDENT(iph, skb) ip_select_ident(iph)
#else

/* simplest case, nothing */
#if !defined(IP_SELECT_IDENT)
#define KLIPS_IP_SELECT_IDENT(iph, skb)  do { iph->id = htons(ip_id_count++); } while(0)
#endif

/* kernels > 2.3.37-ish */
#if defined(IP_SELECT_IDENT) && !defined(IP_SELECT_IDENT_NEW)
#define KLIPS_IP_SELECT_IDENT(iph, skb) ip_select_ident(iph, skb_dst(skb))
#endif

/* kernels > 2.4.2 */
#if defined(IP_SELECT_IDENT) && defined(IP_SELECT_IDENT_NEW)
#define KLIPS_IP_SELECT_IDENT(iph, skb) ip_select_ident(iph, skb_dst(skb), NULL)
#endif

#endif /* SUSE_LINUX_2_4_19_IS_STUPID */

#if !defined(HAVE_CURRENT_UID)
#define current_uid() (current->uid)
#endif

#endif /* _OPENSWAN_PARAM2_H */


#ifndef _CONFIG_ALL_H_
/*
 * Copyright (C) 2002              Michael Richardson <mcr@freeswan.org>
 * 
 * This kernel module is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 * 
 * This kernel module is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * RCSID $Id: config-all.h,v 1.8 2004/07/05 01:04:00 mcr Exp $
 */
#define	_CONFIG_ALL_H_	/* seen it, no need to see it again */

#define CONFIG_IPSEC 1

#ifndef CONFIG_IPSEC_AH
#define CONFIG_IPSEC_AH 1
#endif

#ifndef CONFIG_IPSEC_DEBUG 
#define CONFIG_IPSEC_DEBUG 1
#endif

#ifndef CONFIG_IPSEC_ESP
#define CONFIG_IPSEC_ESP 1
#endif

#ifndef CONFIG_IPSEC_IPCOMP
#define CONFIG_IPSEC_IPCOMP 1
#endif

#ifndef CONFIG_IPSEC_IPIP
#define CONFIG_IPSEC_IPIP 1
#endif

#ifndef CONFIG_IPSEC_AUTH_HMAC_MD5
#define CONFIG_IPSEC_AUTH_HMAC_MD5 1
#endif

#ifndef CONFIG_IPSEC_AUTH_HMAC_SHA1
#define CONFIG_IPSEC_AUTH_HMAC_SHA1 1
#endif 

#ifndef CONFIG_IPSEC_DYNDEV
#define CONFIG_IPSEC_DYNDEV 1
#endif

#ifndef CONFIG_IPSEC_ENC_3DES
#define CONFIG_IPSEC_ENC_3DES 1
#endif

#ifndef CONFIG_IPSEC_NAT_TRAVERSAL
#define CONFIG_IPSEC_NAT_TRAVERSAL 1
#endif

#ifndef CONFIG_IPSEC_ENC_AES
#define CONFIG_IPSEC_ENC_AES 1
#endif

/* off by default for now */
#ifndef CONFIG_IPSEC_ENC_CRYPTOAPI
#define CONFIG_IPSEC_ENC_CRYPTOAPI 0
#endif

#define CONFIG_IPSEC_ALG_CRYPTOAPI #error
#define CONFIG_IPSEC_ALG_AES #error

#ifndef CONFIG_IPSEC_ALG_AES_MAC
#define CONFIG_IPSEC_ALG_AES_MAC 1
#endif

#ifndef CONFIG_IPSEC_REGRESS
#define CONFIG_IPSEC_REGRESS 0
#endif

/* ALGO: */
#if 0
/* goal: cleanup KLIPS code from hardcoded algos :} */
#undef CONFIG_IPSEC_AUTH_HMAC_MD5
#undef CONFIG_IPSEC_AUTH_HMAC_SHA1
#undef CONFIG_IPSEC_ENC_3DES
#endif

#ifndef CONFIG_IPSEC_ALG
#define CONFIG_IPSEC_ALG 1
#endif

#endif /* _CONFIG_ALL_H */

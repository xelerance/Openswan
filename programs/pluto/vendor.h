/* FreeS/WAN ISAKMP VendorID
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
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
 *
 * RCSID $Id: vendor.h,v 1.2 2003/12/29 22:49:54 mcr Exp $
 */

#ifndef _VENDOR_H_
#define _VENDOR_H_

enum known_vendorid {
  /* 1 - 100 : Implementation names */
  VID_OPENPGP                 =1,
  VID_KAME_RACOON             =2,
  VID_MS_NT5                  =3,
  VID_SSH_SENTINEL            =4,
  VID_SSH_SENTINEL_1_1        =5,
  VID_SSH_SENTINEL_1_2        =6,
  VID_SSH_SENTINEL_1_3        =7,
  VID_SSH_IPSEC_1_1_0         =8,
  VID_SSH_IPSEC_1_1_1         =9,
  VID_SSH_IPSEC_1_1_2         =10,
  VID_SSH_IPSEC_1_2_1         =11,
  VID_SSH_IPSEC_1_2_2         =12,
  VID_SSH_IPSEC_2_0_0         =13,
  VID_SSH_IPSEC_2_1_0         =14,
  VID_SSH_IPSEC_2_1_1         =15,
  VID_SSH_IPSEC_2_1_2         =16,
  VID_SSH_IPSEC_3_0_0         =17,
  VID_SSH_IPSEC_3_0_1         =18,
  VID_SSH_IPSEC_4_0_0         =19,
  VID_SSH_IPSEC_4_0_1         =20,
  VID_SSH_IPSEC_4_1_0         =21,
  VID_SSH_IPSEC_4_2_0         =22,
  VID_CISCO_UNITY             =23,
  VID_SSH_SENTINEL_1_4        =24,
  VID_SSH_SENTINEL_1_4_1      =25,
  VID_TIMESTEP                =26,
  VID_FSWAN_2_00_VID          =27,
  VID_FSWAN_2_00_X509_1_3_1_VID =28,
  VID_FSWAN_2_00_X509_1_3_1_LDAP_VID =29,
  VID_SAFENET		    =30,
  VID_NORTEL		    =31,

  /* 101 - 200 : NAT-Traversal */
  VID_NATT_STENBERG_01       =101,
  VID_NATT_STENBERG_02       =102,
  VID_NATT_HUTTUNEN          =103,
  VID_NATT_HUTTUNEN_ESPINUDP =104,
  VID_NATT_IETF_00           =105,
  VID_NATT_IETF_02_N         =106,
  VID_NATT_IETF_02           =107,
  VID_NATT_IETF_03           =108,
  VID_NATT_RFC               =109,
  
  /* 201 - 300 : Misc */
  VID_MISC_XAUTH             =201,
  VID_MISC_DPD               =202,
  VID_MISC_HEARTBEAT_NOTIFY  =203,
  VID_MISC_FRAGMENTATION     =204
};

void init_vendorid(void);

struct msg_digest;
void handle_vendorid (struct msg_digest *md, const char *vid, size_t len);

bool out_vendorid (u_int8_t np, pb_stream *outs, enum known_vendorid vid);

#endif /* _VENDOR_H_ */


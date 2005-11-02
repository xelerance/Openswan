/* IPsec DOI and Oakley resolution routines
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
 * RCSID $Id: ipsec_doi.h,v 1.31 2003/06/27 00:57:35 dhr Exp $
 */

extern void echo_hdr(struct msg_digest *md, bool enc, u_int8_t np);

extern void ipsecdoi_initiate(int whack_sock, struct connection *c
    , lset_t policy, unsigned long try, so_serial_t replacing);

extern void ipsecdoi_replace(struct state *st, unsigned long try);

extern void init_phase2_iv(struct state *st, const msgid_t *msgid);

extern stf_status quick_outI1(int whack_sock
    , struct state *isakmp_sa
    , struct connection *c
    , lset_t policy
    , unsigned long try
    , so_serial_t replacing);

extern state_transition_fn
    main_inI1_outR1,
    main_inR1_outI2,
    main_inI2_outR2,
    main_inR2_outI3,
    main_inI3_outR3,
    main_inR3,
    quick_inI1_outR1,
    quick_inR1_outI2,
    quick_inI2;

extern void send_delete(struct state *st);
extern void accept_delete(struct state *st, struct msg_digest *md
    , struct payload_digest *p);


extern const char *init_pluto_vendorid(void);

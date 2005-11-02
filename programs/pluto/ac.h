/* Support of X.509 attribute certificates
 * Copyright (C) 2002 Ueli Gallizzi, Ariane Seiler
 * Copyright (C) 2003 Martin Berner, Lukas Suter
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
 * RCSID $Id: ac.h,v 1.2 2003/10/31 02:37:51 mcr Exp $
 */

/* access structure for an X.509 attribute certificate */

typedef struct ac_cert ac_cert_t;

struct ac_cert {
  ac_cert_t      *next;
  time_t	 installed;
  chunk_t	 certificate;
  chunk_t	   certificateInfo;
  u_int		     version;
		/*   holder */
		/*     baseCertificateID */
  chunk_t		 holderIssuer;
  chunk_t		 holderSerial;
  chunk_t		 entityName;
                /*   v2Form */
  chunk_t	       issuerName;
                /*   signature */
  chunk_t              sigAlg;
  chunk_t	     serialNumber;
                /*   attrCertValidityPeriod */
  time_t               notBefore;
  time_t               notAfter;
		/*   attributes */
  chunk_t              group;
		/*   extensions */
  chunk_t              authKeyID;
  chunk_t              authKeySerialNumber;
  bool		       noRevAvail;
		/* signatureAlgorithm */
  chunk_t            algorithm;
  chunk_t          signature;
};

/* used for initialization */
extern const ac_cert_t empty_ac;

extern void load_acerts(void);



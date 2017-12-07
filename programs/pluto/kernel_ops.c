/* routines that interface with the kernel's IPsec mechanism
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2009-2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2010 Avesh Agarwal <avagarwa@redhat.com>
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

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "rnd.h"
#include "id.h"
#include "pluto/connections.h"        /* needs id.h */
#include "state.h"
#include "timer.h"
#include "kernel.h"
#include "kernel_forces.h"
#include "kernel_pfkey.h"
#include "kernel_noklips.h"
#include "kernel_bsdkame.h"
#include "packet.h"
#include "x509.h"
#include "log.h"
#include "pluto/server.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "keys.h"

#include <ipsec_saref.h>

const struct kernel_ops *kernel_ops;

/* keep track of kernel version */
char kversion[256];

void
init_kernel(void)
{
    struct utsname un;
#if defined(NETKEY_SUPPORT) || defined(KLIPS) || defined(KLIPS_MAST)
    struct stat buf;
#endif

    /* get kernel version */
    uname(&un);
    strncpy(kversion, un.release, sizeof(kversion));

    switch(kern_interface) {
    case AUTO_PICK:
#if defined(NETKEY_SUPPORT) || defined(KLIPS) || defined(KLIPS_MAST)
	/* If we detect NETKEY and KLIPS, we can't continue */
	if(stat("/proc/net/pfkey", &buf) == 0 &&
	   stat("/proc/net/ipsec/spi/all", &buf) == 0) {
	    /* we don't die, we just log and go to sleep */
	    openswan_log("Can not run with both NETKEY and KLIPS in the kernel");
	    openswan_log("Please check your kernel configuration, or specify a stack");
	    openswan_log("using protostack={klips,netkey,mast}");
	    exit_pluto(0);
	}
#endif
	openswan_log("Kernel interface auto-pick");
	/* FALL THROUGH */

#if defined(NETKEY_SUPPORT)
    case USE_NETKEY:
	if (stat("/proc/net/pfkey", &buf) == 0) {
	    kern_interface = USE_NETKEY;
	    openswan_log("Using Linux XFRM/NETKEY IPsec interface code on %s"
			 , kversion);
	    kernel_ops = &netkey_kernel_ops;
	    break;
	} else
	    openswan_log("No Kernel XFRM/NETKEY interface detected");
	/* FALL THROUGH */
#endif

#if defined(KLIPS)
    case USE_KLIPS:
	if (stat("/proc/net/ipsec/spi/all", &buf) == 0) {
	    kern_interface = USE_KLIPS;
	    openswan_log("Using KLIPS IPsec interface code on %s"
			 , kversion);
	    kernel_ops = &klips_kernel_ops;
	    break;
	} else
	    openswan_log("No Kernel KLIPS interface detected");
	/* FALL THROUGH */
#endif

#if defined(KLIPS_MAST)
    case USE_MASTKLIPS:
        if (stat("/proc/sys/net/ipsec/debug_mast", &buf) == 0) {
	    kern_interface = USE_MASTKLIPS;
	    openswan_log("Using KLIPSng (mast) IPsec interface code on %s"
			 , kversion);
	    kernel_ops = &mast_kernel_ops;
	    break;
	} else
	    openswan_log("No Kernel MASTKLIPS interface detected");
	/* FALL THROUGH */
#endif

#if defined(BSD_KAME)
    case USE_BSDKAME:
	kern_interface = USE_BSDKAME;
	openswan_log("Using BSD/KAME IPsec interface code on %s"
			, kversion);
	kernel_ops = &bsdkame_kernel_ops;
	break;
#endif

#if defined(WIN32) && defined(WIN32_NATIVE)
    case USE_WIN32_NATIVE:
	kern_interface = USE_WIN32_NATIVE;
	openswan_log("Using Win2K native IPsec interface code on %s"
		     , kversion);
	kernel_ops = &win2k_kernel_ops;
	break;
#endif

    case NO_KERNEL:
	kern_interface = NO_KERNEL;
	openswan_log("Using 'no_kernel' interface code on %s"
		     , kversion);
	kernel_ops = &noklips_kernel_ops;
	break;

    default:
	if(kern_interface == AUTO_PICK)
		openswan_log("kernel interface auto-pick failed - no suitable kernel stack found");
	else
		openswan_log("kernel interface '%s' not available"
		     , enum_name(&kern_interface_names, kern_interface));
	exit_pluto(5);
    }

    if (kernel_ops->init)
    {
        kernel_ops->init();
    }

    /* register SA types that we can negotiate */
    can_do_IPcomp = FALSE;  /* until we get a response from KLIPS */
    if (kernel_ops->pfkey_register)
    {
	kernel_ops->pfkey_register();
    }

    if (!kernel_ops->policy_lifetime || kernel_ops->scan_shunts) {
        event_schedule(EVENT_SHUNT_SCAN, SHUNT_SCAN_INTERVAL, NULL);
    }
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

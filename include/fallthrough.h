/*
 * Pluto interface to crypto/pk operations
 *
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Daniel Djamaludin <ddjamaludin@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
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

#ifndef _FALLTHROUGH_H
#define _FALLTHROUGH_H
#if defined(__GNUC__) && __GNUC__ >= 7
 #define FALL_THROUGH __attribute__ ((fallthrough))
#else
 #define FALL_THROUGH ((void)0)
#endif /* __GNUC__ >= 7 */

#endif /* FALLTHROUGH */

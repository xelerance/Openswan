/*
 *  HelperTool.c
 *  Openswan
 *
 *  Created by Jose Quaresma on 9/7/09.
 *  Copyright 2009 __MyCompanyName__. All rights reserved.
 *
 */

#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <CoreServices/CoreServices.h>

#include "BetterAuthorizationSampleLib.h"

#include "Common.h"

/////////////////////////////////////////////////////////////////
#pragma mark DoConnect

static OSStatus DoConnect(
						  AuthorizationRef			  auth,
						  const void *                userData,
						  CFDictionaryRef			  request,
						  CFMutableDictionaryRef      response,
						  aslclient                   asl,
						  aslmsg                      aslMsg
)
// Implements the kSampleLowNumberedPortsCommand.  Opens three low-numbered ports 
// and adds them to the descriptor array in the response dictionary.
{	
	OSStatus					retval = noErr;
	CFStringRef					testString = CFStringCreateWithCString(NULL, 
																	   "I am passing a string as response now\n", 
																	   CFStringGetSystemEncoding());
	
	// Pre-conditions
    
	assert(auth != NULL);
    // userData may be NULL
	assert(request != NULL);
	assert(response != NULL);
    // asl may be NULL
    // aslMsg may be NULL
	
#pragma mark ipsec
	int err2;
	int ret;
	retval = system("/usr/local/sbin/ipsec --version");
	err2 = asl_log(asl, aslMsg, ASL_LEVEL_DEBUG, "Run ipsec --version. ret: %d", ret);
	
	if (retval == noErr) {
        CFDictionaryAddValue(response, CFSTR(kBASTestString), testString);
	}
	
    // Clean up.
    /*
	if (retval != noErr) {
		BASCloseDescriptorArray(descArray);
	}
	if (descArray != NULL) {
		CFRelease(descArray);
	}
	*/
	return retval;
}

/////////////////////////////////////////////////////////////////
#pragma mark ***** Tool Infrastructure

/*
 IMPORTANT
 ---------
 This array must be exactly parallel to the kCommandSet array 
 in "Common.c".
 */

static const BASCommandProc kCommandProcs[] = {
	DoConnect,
	NULL
};

int main(int argc, char **argv)
{
    // Go directly into BetterAuthorizationSampleLib code.
	
    // IMPORTANT
    // BASHelperToolMain doesn't clean up after itself, so once it returns 
    // we must quit.
    
	return BASHelperToolMain(kCommandSet, kCommandProcs);
}


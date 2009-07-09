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
						  AuthorizationRef			auth,
						  const void *                userData,
						  CFDictionaryRef				request,
						  CFMutableDictionaryRef      response,
						  aslclient                   asl,
						  aslmsg                      aslMsg
)
// Implements the kConnectCommand.
// Connects Openswan.
{	
	OSStatus					retval = noErr;
	CFMutableArrayRef			descArray = NULL;
	int         junk;
	
	// Pre-conditions
    
	assert(auth != NULL);
    // userData may be NULL
	assert(request != NULL);
	assert(response != NULL);
    // asl may be NULL
    // aslMsg may be NULL
	
	/*
	
	descArray = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
	if (descArray == NULL) {
		retval = coreFoundationUnknownErr;
	}
	
	if (retval == noErr) {
		retval = OpenAndBindDescAndAppendToArray(130, descArray, asl, aslMsg);
	}
	if (retval == noErr) {
		retval = OpenAndBindDescAndAppendToArray(131, descArray, asl, aslMsg);
	}
	if (retval == noErr) {
        if ( CFDictionaryContainsKey(request, CFSTR(kSampleLowNumberedPortsForceFailure)) ) {
            retval = BASErrnoToOSStatus( EADDRINUSE );
        } else {
            retval = OpenAndBindDescAndAppendToArray(132, descArray, asl, aslMsg);
        }
	}
	*/
	
	if (retval == noErr) {
        CFDictionaryAddValue(response, CFSTR(kBASDescriptorArrayKey), descArray);
	}
	
	errno=EADDRINUSE;
	junk = als_log(asl, aslMsg, ASL_LEVEL_ERR, "Connect Openswan\n");
	assert(junk=0);
	
    // Clean up.
    
	if (retval != noErr) {
		BASCloseDescriptorArray(descArray);
	}
	if (descArray != NULL) {
		CFRelease(descArray);
	}
	
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


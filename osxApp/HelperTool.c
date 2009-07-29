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

static OSStatus OpenAndBindDescAndAppendToArray(
												uint16_t					port,               // in host byte order
												CFMutableArrayRef			descArray,
												aslclient                   asl,
												aslmsg                      aslMsg
)
// A helper routine for DoGetLowNumberedPorts.  Opens a TCP port and 
// stashes the resulting descriptor in descArray.
{
	OSStatus                    retval;
	int							err;
	int							desc;
	CFNumberRef					descNum;
	
	// Pre-conditions
	
	assert(port != 0);
	assert(descArray != NULL);
    // asl may be NULL
    // aslMsg may be NULL
	
	descNum = NULL;
	
    retval = noErr;
	desc = socket(AF_INET, SOCK_STREAM, 0);
    if (desc < 0) {
        retval = BASErrnoToOSStatus(errno);
    }
	if (retval == noErr) {
		descNum = CFNumberCreate(NULL, kCFNumberIntType, &desc);
		if (descNum == NULL) {
			retval = coreFoundationUnknownErr;
		}
	}
	if (retval == 0) {
		struct sockaddr_in addr;
		
		memset(&addr, 0, sizeof(addr));
		addr.sin_len    = sizeof(addr);
		addr.sin_family = AF_INET;
		addr.sin_port   = htons(port);
		
        static const int kOne = 1;
		
        err = setsockopt(desc, SOL_SOCKET, SO_REUSEADDR, (void *)&kOne, sizeof(kOne));
        if (err < 0) {
            retval = BASErrnoToOSStatus(errno);
        }
		
        if (retval == noErr) {
            err = bind(desc, (struct sockaddr *) &addr, sizeof(addr));
            if (err < 0) {
                retval = BASErrnoToOSStatus(errno);
            }
        }
	}
	if (retval == noErr) {
		CFArrayAppendValue(descArray, descNum);
	}
    if (retval == noErr) {
        err = asl_log(asl, aslMsg, ASL_LEVEL_DEBUG, "Opened port %u", (unsigned int) port);
    } else {
        errno = BASOSStatusToErrno(retval);                         // so that %m can pick it up
        err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "Failed to open port %u: %m", (unsigned int) port);
    }
    assert(err == 0);
	
	// Clean up.
	
	if ( (retval != noErr) && (desc != -1) ) {
		err = close(desc);
		assert(err == 0);
	}
	if (descNum != NULL) {
		CFRelease(descNum);
	}
	
	return retval;
}


static OSStatus DoConnect(
						  AuthorizationRef			auth,
						  const void *                userData,
						  CFDictionaryRef				request,
						  CFMutableDictionaryRef      response,
						  aslclient                   asl,
						  aslmsg                      aslMsg
)
// Implements the kSampleLowNumberedPortsCommand.  Opens three low-numbered ports 
// and adds them to the descriptor array in the response dictionary.
{	
	OSStatus					retval = noErr;
	CFMutableArrayRef			descArray = NULL;
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
	ret = system("/usr/local/sbin/ipsec --version");
	err2 = asl_log(asl, aslMsg, ASL_LEVEL_DEBUG, "Run ipsec --version. ret: %d", ret);
	
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
	/*
	CFArrayAppendValue(descArray, 130);
	CFArrayAppendValue(descArray, 131);
	CFArrayAppendValue(descArray, 132);
	*/
	if (retval == noErr) {
        CFDictionaryAddValue(response, CFSTR(kBASDescriptorArrayKey), descArray);
	}
	
	CFDictionaryAddValue(response, CFSTR(kBASTestString), testString);
	
	
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


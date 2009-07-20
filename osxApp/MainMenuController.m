//
//  MainMenuController.m
//  Openswan
//
//  Created by Jose Quaresma on 11/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "MainMenuController.h"
#import "AdvMenuController.h"
#import "PreferenceController.h"
#import "ConnectionsDB.h"
#import <AppKit/NSCell.h>

@implementation MainMenuController

@synthesize db, connTime, connDuration, timer, connDurationPrint;

- (IBAction)showAdvMenu: (id)sender
{
	//Is advMenuController nil?
	if(!advMenuController){
		advMenuController = [[AdvMenuController alloc] init];
	}
	NSLog(@"Showing %@", advMenuController);
	[[advMenuController selConn] selectItemAtIndex:[selConn indexOfSelectedItem]];
	[advMenuController showWindow: self];
}

- (IBAction)connDisc: (id) sender
{
	if([sender state] == NSOnState){
		[connView setHidden:YES];
		[discView setHidden:NO];
	}
	else{
		[connView setHidden:NO];
		[discView setHidden:YES];
	}
}

- (void)awakeFromNib
{
	[NSApp setDelegate: self];
	
	[GrowlApplicationBridge setGrowlDelegate:self];
	
	[self loadDataFromDisk];
	
	[connView setHidden:NO];
	[discView setHidden:YES];
	[self setConnDurationPrint:[NSString stringWithString:@"0:0:0"]];
}

- (void) applicationWillTerminate: (NSNotification *)note
{
	[self saveDataToDisk];
}

- (IBAction)showPreferencePanel: (id)sender
{
	//Is preferenceController nil?
	if(!preferenceController){
		preferenceController = [[PreferenceController alloc] init];
	}
	NSLog(@"Showing %@", preferenceController);
	[preferenceController showWindow: self];
}

#pragma mark archiving

- (NSString *) pathForDataFile
{
	NSFileManager *fileManager = [NSFileManager defaultManager];
    
	NSString *folder = @"~/Library/Application Support/Openswan/";
	folder = [folder stringByExpandingTildeInPath];
	
	if ([fileManager fileExistsAtPath: folder] == NO)
	{
		[fileManager createDirectoryAtPath: folder attributes: nil];
	}
    
	NSString *fileName = @"Openswan.data";
	return [folder stringByAppendingPathComponent:fileName];
}

- (void) saveDataToDisk
{
	NSLog(@"Saving data to disk");
	NSString* path = [self pathForDataFile];
	
	NSMutableDictionary* rootObject;
	rootObject = [NSMutableDictionary dictionary];
    
	[rootObject setValue:[self db] forKey:@"db"];
	[NSKeyedArchiver archiveRootObject:rootObject toFile:path];
}

- (void) loadDataFromDisk
{
	NSLog(@"Loading data from disk");
	NSString* path        = [self pathForDataFile];
	NSDictionary* rootObject;
    
	rootObject = [NSKeyedUnarchiver unarchiveObjectWithFile:path];
	[self setDb:[rootObject valueForKey:@"db"]];
	
	//If there is no previously saved data
	if(db==NULL)
	{
		[self setDb:[ConnectionsDB sharedInstance]];	
	}	
}

- (IBAction)saveData: (id)sender
{
	[self saveDataToDisk];
}
- (IBAction)loadData: (id)sender
{
	[self loadDataFromDisk];
}

//Helper Tool

static OSStatus DoConnect(
Boolean						forceFailure, 
int							fdArray[]
)
// This code shows how to do a typical BetterAuthorizationSample privileged operation 
// in straight C.  In this case, it does the low-numbered ports operation, which 
// returns three file descriptors that are bound to low-numbered TCP ports.
{
    OSStatus        err;
    Boolean         success;
    CFBundleRef     bundle;
    CFStringRef     bundleID;
    CFIndex         keyCount;
    CFStringRef     keys[2];
    CFTypeRef       values[2];
    CFDictionaryRef request;
    CFDictionaryRef response;
    BASFailCode     failCode;
    
    // Pre-conditions
    
    assert(fdArray != NULL);
    assert(fdArray[0] == -1);
    assert(fdArray[1] == -1);
    assert(fdArray[2] == -1);
    
    // Get our bundle information.
    
    bundle = CFBundleGetMainBundle();
    assert(bundle != NULL);
    
    bundleID = CFBundleGetIdentifier(bundle);
    assert(bundleID != NULL);
    
    // Create the request.  The request always contains the kBASCommandKey that 
    // describes the command to do.  It also, optionally, contains the 
	// kSampleLowNumberedPortsForceFailure key that tells the tool to always return 
	// an error.  The purpose of this is to test our error handling path (do we leak 
	// descriptors, for example). 
    
    keyCount = 0;
    keys[keyCount]   = CFSTR(kBASCommandKey);
    values[keyCount] = CFSTR(kConnectCommand);
    keyCount += 1;
    
    if (forceFailure) {
        keys[keyCount]   = CFSTR(kSampleLowNumberedPortsForceFailure);
        values[keyCount] = kCFBooleanTrue;
        keyCount += 1;
    }
    
    request = CFDictionaryCreate(
								 NULL, 
								 (const void **) keys, 
								 (const void **) values, 
								 keyCount, 
								 &kCFTypeDictionaryKeyCallBacks, 
								 &kCFTypeDictionaryValueCallBacks
								 );
    assert(request != NULL);
    
    response = NULL;
    
    // Execute it.
	
	err = BASExecuteRequestInHelperTool(
										gAuth, 
										kCommandSet, 
										bundleID, 
										request, 
										&response
										);
	
    // If it failed, try to recover.
	
    if ( (err != noErr) && (err != userCanceledErr) ) {
        int alertResult;
        
        failCode = BASDiagnoseFailure(gAuth, bundleID);
        
        // At this point we tell the user that something has gone wrong and that we need 
        // to authorize in order to fix it.  Ideally we'd use failCode to describe the type of 
        // error to the user.
		
        alertResult = NSRunAlertPanel(@"Needs Install", @"BAS needs to install", @"Install", @"Cancel", NULL);
        
        if ( alertResult == NSAlertDefaultReturn ) {
            // Try to fix things.
            
            err = BASFixFailure(gAuth, (CFStringRef) bundleID, CFSTR("InstallTool"), CFSTR("HelperTool"), failCode);
			
            // If the fix went OK, retry the request.
            
            if (err == noErr) {
                err = BASExecuteRequestInHelperTool(
													gAuth, 
													kCommandSet, 
													bundleID, 
													request, 
													&response
													);
            }
        } else {
            err = userCanceledErr;
        }
    }
	
    // If all of the above went OK, it means that the IPC to the helper tool worked.  We 
    // now have to check the response dictionary to see if the command's execution within 
    // the helper tool was successful.
    
    if (err == noErr) {
        err = BASGetErrorFromResponse(response);
    }
    
    // Extract the descriptors from the response and copy them out to our caller.
    
    if (err == noErr) {
        CFArrayRef      descArray;
        CFIndex         arrayIndex;
        CFIndex         arrayCount;
        CFNumberRef     thisNum;
        
        descArray = (CFArrayRef) CFDictionaryGetValue(response, CFSTR(kBASDescriptorArrayKey));
        assert( descArray != NULL );
        assert( CFGetTypeID(descArray) == CFArrayGetTypeID() );
		
        arrayCount = CFArrayGetCount(descArray);
        assert(arrayCount == kNumberOfLowNumberedPorts);
        
        for (arrayIndex = 0; arrayIndex < kNumberOfLowNumberedPorts; arrayIndex++) {
            thisNum = CFArrayGetValueAtIndex(descArray, arrayIndex);
            assert(thisNum != NULL);
            assert( CFGetTypeID(thisNum) == CFNumberGetTypeID() );
            
            success = CFNumberGetValue(thisNum, kCFNumberIntType, &fdArray[arrayIndex]);
            assert(success);
        }
    }
    
    if (response != NULL) {
        CFRelease(response);
    }
    
    assert( (err == noErr) == (fdArray[0] >= 0) );
    assert( (err == noErr) == (fdArray[1] >= 0) );
    assert( (err == noErr) == (fdArray[2] >= 0) );
    
    return err;
}

- (IBAction)connect: (id)sender
{	
	[self saveConnToFile];
	if([self timer] == nil) {
		[self setConnTime:[NSDate date]];
		
		NSTimer *tmpTimer = [NSTimer scheduledTimerWithTimeInterval:1
															 target:self 
														   selector:@selector(updateConnDuration:)
														   userInfo:nil 
															repeats:YES];
		[self setTimer:tmpTimer];
	}
	else {
		[[self timer] invalidate];
		//[[self timer] release];
		[self setTimer:nil];
		[self setConnDuration:0];
		[self setConnDurationPrint:[NSString stringWithString:@"0:0:0"]];
	}
	if([sender state] == NSOnState){
		[connView setHidden:YES];
		[discView setHidden:NO];
		
		///////////////
		OSStatus    err;
		int         junk;
		int         descriptors[kNumberOfLowNumberedPorts] = { -1, -1, -1 };
		uint16_t    ports[kNumberOfLowNumberedPorts];
		int         portIndex;
		
		// Call the C code to do the real work.
		
		err = DoConnect( NO, descriptors );
		
		// Log our results.
		
		if (err == noErr) {
			// Get the port numbers for each descriptor.
			
			for (portIndex = 0; portIndex < kNumberOfLowNumberedPorts; portIndex++) {
				int                 sockErr;
				struct sockaddr_in  boundAddr;
				socklen_t           boundAddrLen;
				
				memset(&boundAddr, 0, sizeof(boundAddr));
				boundAddrLen = sizeof(boundAddr);
				
				sockErr = getsockname(descriptors[portIndex], (struct sockaddr *) &boundAddr, &boundAddrLen);
				assert(sockErr == 0);
				assert(boundAddrLen == sizeof(boundAddr));
				ports[portIndex] = ntohs(boundAddr.sin_port);
			}
			
			// Log it.
			
			NSLog(@"ports[0] = %u, port[1] = %u, port[2] = %u\n", 
				  (unsigned int) ports[0], 
				  (unsigned int) ports[1], 
				  (unsigned int) ports[2]);
			
			// Close the descriptors.
			
			for (portIndex = 0; portIndex < kNumberOfLowNumberedPorts; portIndex++) {
				junk = close(descriptors[portIndex]);
				assert(junk == 0);
			}
		} else {
			NSLog(@"Failed with error %ld.\n", (long) err);
		}
			
		//////////////
		
		[GrowlApplicationBridge
		 notifyWithTitle:@"Connected" 
		 description:@"Connection was established" 
		 notificationName:@"Openswan Growl Notification" 
		 iconData:nil 
		 priority:0 
		 isSticky:NO 
		 clickContext:nil];
	}
	else{
		[connView setHidden:NO];
		[discView setHidden:YES];
		
		[GrowlApplicationBridge
		 notifyWithTitle:@"Disconnected" 
		 description:@"Connection was closed" 
		 notificationName:@"Openswan Growl Notification" 
		 iconData:nil 
		 priority:0 
		 isSticky:NO 
		 clickContext:nil];
	}
}

- (void)updateConnDuration: (NSTimer*)aTimer
{
	NSDate* now = [NSDate date];
	[self setConnDuration:[now timeIntervalSinceDate: connTime]];
	int hours = (NSInteger)connDuration / 30;
	[self setConnDuration:(NSInteger)connDuration % 30];
	int mins = (NSInteger)connDuration / 10;
	[self setConnDuration:(NSInteger)connDuration % 10];
	int secs = (NSInteger)connDuration;
	[self setConnDurationPrint:[NSString stringWithFormat:@"%d:%d:%d", hours, mins, secs]];
}

//Growl
- (NSDictionary*) registrationDictionaryForGrowl
{
	NSArray *notifications;
	notifications = [NSArray arrayWithObject:@"Openswan Growl Notification"];
	
	NSDictionary *dict;
	dict = [NSDictionary dictionaryWithObjectsAndKeys:
			notifications, GROWL_NOTIFICATIONS_ALL,
			notifications, GROWL_NOTIFICATIONS_DEFAULT, nil];
	
	return dict;
}

int main(int argc, char *argv[])
{
    OSStatus    junk;
    
    // Create the AuthorizationRef that we'll use through this application.  We ignore 
    // any error from this.  A failure from AuthorizationCreate is very unusual, and if it 
    // happens there's no way to recover; Authorization Services just won't work.
	
    junk = AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &gAuth);
    assert(junk == noErr);
    assert( (junk == noErr) == (gAuth != NULL) );
	
	// For each of our commands, check to see if a right specification exists and, if not,
    // create it.
    //
    // The last parameter is the name of a ".strings" file that contains the localised prompts 
    // for any custom rights that we use.
    
	BASSetDefaultRules(
					   gAuth, 
					   kCommandSet, 
					   CFBundleGetIdentifier(CFBundleGetMainBundle()), 
					   CFSTR("AuthorizationPrompts")
					   );
    
    // And now, the miracle that is Cocoa...
    
    return NSApplicationMain(argc,  (const char **) argv);
}

//writing to file

- (void) saveConnToFile {
	NSFileManager *fileManager = [NSFileManager defaultManager];
	//NSString *path = @"~/Desktop/test";
	NSString *string = @"testing ";
	NSError *error;
	NSString *origFileName = [[[[ConnectionsDB sharedInstance] connDB] objectAtIndex:[selConn indexOfSelectedItem]] connName];
	NSString *fileName = [origFileName stringByAppendingFormat:@".conn"];
	
	NSString *origPath = @"~/Library/Application Support/Openswan";
	NSString *filePath = [origPath stringByAppendingPathComponent:fileName];
	NSString *path = [filePath stringByStandardizingPath];
	
	if ([fileManager fileExistsAtPath: path] == NO)
	{
		[fileManager createFileAtPath:path contents:nil attributes: nil];
	}
	
	BOOL ok = [string writeToFile:path atomically:YES
						 encoding:NSUnicodeStringEncoding error:&error];
	if (!ok) {
		// an error occurred
		NSLog(@"Error writing file at %@\n%@",
              path, [error localizedFailureReason]);
	}
}


@end

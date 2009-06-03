//
//  Controller.m
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "Controller.h"

@implementation Controller
@synthesize connections;
@synthesize Type, Auto, phase2, leftSendCert, rightSendCert, dpdAction, plutoDebug, authBy, endUserOpts;

- (id) init
{
    /* first initialize the base class */
    self = [super init];
	
    NSArray* values = [NSArray arrayWithObjects: [[Connection alloc] initWithName:@"Default"],[[Connection alloc] initWithName:@"Connection1"], 
					   @"Rename Connection...",@"Delete Connection...", nil];
    
    connections = [[NSMutableArray alloc] init];
				   [connections addObjectsFromArray:values];
	
	Type = [NSArray arrayWithObjects: @"Tunnel", @"Transport", @"Pass Through",@"Drop", @"Reject", nil];
	Auto = [NSArray arrayWithObjects: @"Start", @"Add", @"Ignore", @"Manual", @"Route", nil];
	phase2 = [NSArray arrayWithObjects: @"ESP", @"AH", nil];
	leftSendCert = [NSArray arrayWithObjects: @"Always", @"If asked",@"Never", nil];
	rightSendCert = [NSArray arrayWithObjects: @"Always", @"If asked",@"Never", nil];
	dpdAction = [NSArray arrayWithObjects: @"Hold",@"Clear", nil];
	plutoDebug = [NSArray arrayWithObjects: @"None",@"All", @"...", nil];
	authBy = [NSArray arrayWithObjects: @"Certificate", @"RSA", nil];
	endUserOpts = [NSArray arrayWithObjects: @"Raw RSA", @"X.509", @"PSK", nil];
	
	window = [[NSWindow alloc] retain];
	forceEncaps = [[NSButton alloc] retain];
	
	return self;
}

- (IBAction)advancedOpt: (id) sender
{

	NSRect rect = [window frame];
	NSLog(@"my height %f, my orig %f", rect.size.height, rect.origin.y);
	if([sender state] == YES)
	{
		rect.size.height = 679;
		rect.origin.x = 0;
		rect.origin.y = 101;
	}
	else
	{
		rect.size.height = 409;
		rect.origin.x = 0;
		rect.origin.y = 369;
	}
	[window setFrame:rect display:YES];
}

- (IBAction)natTraversal: (id) sender
{
	if([sender state] == YES)
	{
		[forceEncaps setEnabled:YES];
	}
	else
	{
		[forceEncaps setEnabled:NO];
	}
}

- (IBAction)authByAction: (id) sender
{
	NSLog(@"slected item in authBy: %@", [sender titleOfSelectedItem]);
}

@end

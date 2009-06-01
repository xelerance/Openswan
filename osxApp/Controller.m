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
@synthesize Type, Auto, phase2, leftSendCert, rightSendCert, dpdAction, plutoDebug;

- (id) init
{
    /* first initialize the base class */
    self = [super init];
	
    NSArray* values = [NSArray arrayWithObjects: [[Connection alloc] initWithName:@"Default"],[[Connection alloc] initWithName:@"Connection1"], nil];
    
    connections = [[NSMutableArray alloc] init];
				   [connections addObjectsFromArray:values];
	
	Type = [NSArray arrayWithObjects: @"Tunnel", @"Transport", @"Pass Through",@"Drop", @"Reject", nil];
	Auto = [NSArray arrayWithObjects: @"Start", @"Add", @"Ignore", @"Manual", @"Route", nil];
	phase2 = [NSArray arrayWithObjects: @"ESP", @"AH", nil];
	
	leftSendCert = [NSArray arrayWithObjects: @"Always", @"If asked",@"Never", nil];
	rightSendCert = [NSArray arrayWithObjects: @"Always", @"If asked",@"Never", nil];
	dpdAction = [NSArray arrayWithObjects: @"Hold",@"Clear", nil];
	plutoDebug = [NSArray arrayWithObjects: @"None",@"All", @"...", nil];
	
	window = [[NSWindow alloc] retain];
	
	return self;
}

- (IBAction)advancedOpt: (id) sender
{

	NSRect rect = [window frame];
	NSLog(@"my height %f, my orig %f", rect.size.height, rect.origin.y);
	if([sender state] == YES)
	{
		rect.size.height = 744;
	}
	else
	{
		rect.size.height = 616;
		rect.origin.x = 0;
		rect.origin.y = 162;
	}
	[window setFrame:rect display:YES];
}

@end

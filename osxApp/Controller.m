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
@synthesize popupType, popupAuto;

- (id) init
{
    /* first initialize the base class */
    self = [super init];
	
    NSArray* values = [NSArray arrayWithObjects: [[Connection alloc] initWithName:@"Default"],[[Connection alloc] initWithName:@"Connection1"], nil];
    
    connections = [[NSMutableArray alloc] init];
				   [connections addObjectsFromArray:values];
	
	popupType = [NSArray arrayWithObjects: @"Tunnel", @"Transport", @"Pass Through", nil];
	popupAuto = [NSArray arrayWithObjects: @"Start", @"Add", @"Ignore", @"Manual", @"Route", nil];

	return self;
}

@end

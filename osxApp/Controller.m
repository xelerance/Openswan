//
//  Controller.m
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "Controller.h"

@implementation Controller
@synthesize current, connections;

- (id) init
{
    /* first initialize the base class */
    self = [super init];
	
	connections = [NSMutableDictionary dictionary];
	
	[connections setObject:[[Connection alloc] init] forKey:@"default"];
	[connections setObject:[[Connection alloc] init] forKey:@"test1"];
	
	[[connections objectForKey:@"test1"] setSelectedLeftIP:@"192.111.111.111"];
	
	current = [connections objectForKey:@"test1"];
	
	[connections retain];
	return self;
}

- (IBAction)setDefault: (id)sender
{
	NSLog(@"controller: setting selectedLeftIP to default");
	current = [connections objectForKey:@"default"];
	[[connections objectForKey:@"test1"] setSelectedLeftIP:@"999.999.999.999"];
}

@end

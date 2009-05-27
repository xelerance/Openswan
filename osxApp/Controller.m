//
//  Controller.m
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "Controller.h"

@implementation Controller
//@synthesize current;
@synthesize connections;

- (id) init
{
    /* first initialize the base class */
    self = [super init];
	
	//NSArray * keys   = [NSArray arrayWithObjects: @"default", @"test1", nil];
    NSArray* values = [NSArray arrayWithObjects: [[Connection alloc] initWithName:@"default"],[[Connection alloc] initWithName:@"test1"], nil];
    
    connections = [[NSMutableArray alloc] init];
				   [connections addObjectsFromArray:values];
	
	//connections = [NSMutableDictionary dictionary];
	
	//[connections setObject:[[Connection alloc] init] forKey:@"default"];
	//[connections setObject:[[Connection alloc] init] forKey:@"test1"];
	
	//[[connections objectForKey:@"test1"] setSelectedLeftIP:@"192.111.111.111"];
	
	//current = [connections objectForKey:@"test1"];
	
	//[connections retain];
	return self;
}
/*
- (IBAction)setDefault: (id)sender
{
	NSLog(@"controller: setting selectedLeftIP to default");
	current = [connections objectForKey:@"default"];
	[[connections objectForKey:@"test1"] setSelectedLeftIP:@"999.999.999.999"];
}
*/
- (void)setConnections: (NSMutableArray*)a
{
	if(a==connections)
		return;
	[a retain];
	[connections release];
	connections = a;
}

@end

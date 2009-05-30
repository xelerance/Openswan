//
//  Connection.m
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "Connection.h"


@implementation Connection
@synthesize selectedLeftIP, selectedRightIP, selectedKeySetupMode;
@synthesize selectedKey, selectedType, selectedAuto;
@synthesize selectedLeftRSAsig , selectedRightRSAsig;
@synthesize connName;

- (id) initWithName:(NSString*)name
{
    /* first initialize the base class */
    self = [super init]; 
    /* then initialize the instance variables */
	
	connName = [NSString stringWithString:name];
	
	//initialize selectedLedtIP
	selectedLeftIP = [[NSMutableString alloc] init];
	
	NSString* ss = [NSString stringWithFormat: @"192.128.%@", name];
	
	[self setValue:ss forKey:@"selectedLeftIP"];
	
	NSMutableString *s = [self valueForKey:@"selectedLeftIP"];
	NSLog(@"Set value for selectedLeftIP = %@", s);
	
    /* finally return the object */
    return self;
}

- (NSString*)description
{
	return connName;
}

@end


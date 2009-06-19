//
//  Connection.m
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "Connection.h"


@implementation Connection
@synthesize selLocalHost, selRemoteHost, selAuthBy, selAuto, selLocalRSASigKey, selRemoteRSASigKey, test;
@synthesize connName;
@synthesize Type, Auto, phase2, sendCert, dpdAction, plutoDebug, authBy, endUserOpts, mode;

- (id) init
{
    /* first initialize the base class */
    self = [super init];
	
	Type = [NSArray arrayWithObjects: @"Tunnel", @"Transport", @"Pass Through",@"Drop", @"Reject", nil];
	Auto = [NSArray arrayWithObjects: @"Start", @"Add", @"Ignore", @"Route", nil];
	phase2 = [NSArray arrayWithObjects: @"ESP", @"AH", nil];
	sendCert = [NSArray arrayWithObjects: @"Always", @"If asked",@"Never", nil];
	dpdAction = [NSArray arrayWithObjects: @"Hold",@"Clear", nil];
	plutoDebug = [NSArray arrayWithObjects: @"None",@"All", @"...", nil];
	authBy = [NSArray arrayWithObjects: @"RSA Sig Key", @"Secret", nil];
	endUserOpts = [NSArray arrayWithObjects: @"Raw RSA", @"X.509", @"PSK", nil];
	mode = [NSArray arrayWithObjects: @"Main",@"Aggressive",@"IKEv2", nil];
	
	return self;
}

- (id) initWithName:(NSString*)name
{
    /* first initialize the base class */
    self = [super init]; 
    /* then initialize the instance variables */
	
	connName = [NSString stringWithString:name];
	
	//initialize selectedLedtIP
	selLocalHost = [[NSMutableString alloc] init];
	
	NSString* ss = [NSString stringWithFormat: @"192.128.%@", name];
	
	[self setValue:ss forKey:@"selLocalHost"];
	
	NSMutableString *s = [self valueForKey:@"selLocalHost"];
	NSLog(@"Set value for selLocalHost = %@", s);
	
	selAuto = [[NSPopUpButton alloc] init];
	selAuthBy = [[NSPopUpButton alloc] init];
	
	test = [[NSMutableString alloc] init];
	
	NSMutableString* tmp = [NSString stringWithFormat: @"Add"];
	
	[self setValue:tmp forKey:@"test"];
	
    /* finally return the object */
    return self;
}

- (NSString*)description
{
	return connName;
}

@end


//
//  Connection.m
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "Connection.h"


@implementation Connection
@synthesize connName;
@synthesize selLocalHost, selRemoteHost, selAuthBy, selAuto, selLocalRSASigKey, selRemoteRSASigKey;


- (id)init
{
	//first initialize the base class
    self = [super init]; 
    //then initialize the instance variables
	
	connName = [NSString stringWithString:@"New Connection"];
	
	//initialize selectedLedtIP
	selLocalHost = [[NSMutableString alloc] init];
	selRemoteHost = [[NSMutableString alloc] init];

	selAuto = [[NSMutableString alloc] init];
	
	NSMutableString* tmp = [NSString stringWithFormat:@"Add"];
	
	[self setValue:tmp forKey:@"selAuto"];
	
	selAuthBy= [[NSMutableString alloc] init];
	
	NSMutableString* tmp2 = [NSString stringWithFormat:@"RSA Sig Key"];
	
	[selAuthBy setString:tmp2];
	
    // finally return the object
    return self;
}

- (NSString*)description
{
	return connName;
}

- (void)encodeWithCoder:(NSCoder*)coder
{
	[coder encodeObject:[self connName] forKey:@"connName"];
	[coder encodeObject:[self selLocalHost] forKey:@"selLocalHost"];
	[coder encodeObject:[self selRemoteHost] forKey:@"selRemoteHost"];
	[coder encodeObject:[self selAuthBy] forKey:@"selAuthBy"];
	[coder encodeObject:[self selAuto] forKey:@"selAuto"];
	[coder encodeObject:[self selLocalRSASigKey] forKey:@"selLocalRSASigKey"];
	[coder encodeObject:[self selRemoteRSASigKey] forKey:@"selRemoteRSASigKey"];
}

- (id)initWithCoder:(NSCoder*)coder
{
	[super init];
	[self setConnName:[coder decodeObjectForKey:@"connName"]];
	[self setSelLocalHost:[coder decodeObjectForKey:@"selLocalHost"]];
	[self setSelRemoteHost:[coder decodeObjectForKey:@"selRemoteHost"]];
	[self setSelAuthBy:[coder decodeObjectForKey:@"selAuthBy"]];
	[self setSelAuto:[coder decodeObjectForKey:@"selAuto"]];
	[self setSelLocalRSASigKey:[coder decodeObjectForKey:@"selLocalRSASigKey"]];
	[self setSelRemoteRSASigKey:[coder decodeObjectForKey:@"selRemoteRSASigKey"]];
	return self;
}


@end


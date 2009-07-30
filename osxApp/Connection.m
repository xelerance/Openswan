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
@synthesize selAuto,
			selType,
			selMode,
			selLocalHost,
			selLocalID,
			selLocalSubnets,
			selLocalProtocolPort,
			selRemoteHost,
			selRemoteID,
			selRemoteSubnets,
			selRemoteProtocolPort;

@synthesize selAuthBy, selLocalRSASigKey, selRemoteRSASigKey, selPSK;


- (id)init
{
	//first initialize the base class
    self = [super init]; 
    //then initialize the instance variables
	
	connName = [NSString stringWithString:@"New Connection"];
	
	//Connection Options
	selAuto = [NSString stringWithString:@"Start"];
	selType = [NSString stringWithString:@"Tunnel"];
	selMode = [NSString stringWithString:@"IKEv2"];

	//Auth Options
	selAuthBy= [NSString stringWithString:@"RSA Sig Key"];
	
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
	
	//Connection Options
	[coder encodeObject:[self selAuto] forKey:@"selAuto"];
	[coder encodeObject:[self selType] forKey:@"selType"];
	[coder encodeObject:[self selMode] forKey:@"selMode"];
	[coder encodeObject:[self selLocalHost] forKey:@"selLocalHost"];
	[coder encodeObject:[self selLocalID] forKey:@"selLocalID"];
	[coder encodeObject:[self selLocalSubnets] forKey:@"selLocalSubnets"];
	[coder encodeObject:[self selLocalProtocolPort] forKey:@"selLocalProtocolPort"];
	[coder encodeObject:[self selRemoteHost] forKey:@"selRemoteHost"];
	[coder encodeObject:[self selRemoteID] forKey:@"selRemoteID"];
	[coder encodeObject:[self selRemoteSubnets] forKey:@"selRemoteSubnets"];
	[coder encodeObject:[self selRemoteProtocolPort] forKey:@"selRemoteProtocolPort"];
	
	[coder encodeObject:[self selAuthBy] forKey:@"selAuthBy"];
	[coder encodeObject:[self selLocalRSASigKey] forKey:@"selLocalRSASigKey"];
	[coder encodeObject:[self selRemoteRSASigKey] forKey:@"selRemoteRSASigKey"];
	[coder encodeObject:[self selPSK] forKey:@"selPSK"];
}

- (id)initWithCoder:(NSCoder*)coder
{
	[super init];
	[self setConnName:[coder decodeObjectForKey:@"connName"]];
	
	//Connection Options
	[self setSelAuto:[coder decodeObjectForKey:@"selAuto"]];
	[self setSelType:[coder decodeObjectForKey:@"selType"]];
	[self setSelMode:[coder decodeObjectForKey:@"selMode"]];
	[self setSelLocalHost:[coder decodeObjectForKey:@"selLocalHost"]];
	[self setSelLocalID:[coder decodeObjectForKey:@"selLocalID"]];
	[self setSelLocalSubnets:[coder decodeObjectForKey:@"selLocalSubnets"]];
	[self setSelLocalProtocolPort:[coder decodeObjectForKey:@"selLocalProtocolPort"]];
	[self setSelRemoteHost:[coder decodeObjectForKey:@"selRemoteHost"]];
	[self setSelRemoteID:[coder decodeObjectForKey:@"selRemoteID"]];
	[self setSelRemoteSubnets:[coder decodeObjectForKey:@"selRemoteSubnets"]];
	[self setSelRemoteProtocolPort:[coder decodeObjectForKey:@"selRemoteProtocolPort"]];
	
	[self setSelAuthBy:[coder decodeObjectForKey:@"selAuthBy"]];
	[self setSelLocalRSASigKey:[coder decodeObjectForKey:@"selLocalRSASigKey"]];
	[self setSelRemoteRSASigKey:[coder decodeObjectForKey:@"selRemoteRSASigKey"]];
	[self setSelPSK:[coder decodeObjectForKey:@"selPSK"]];
	return self;
}


@end


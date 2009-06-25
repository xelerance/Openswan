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

- (id) initWithName:(NSString*)name
{
    /* first initialize the base class */
    self = [super init]; 
    /* then initialize the instance variables */
	
	connName = [NSString stringWithString:name];
	
	//initialize selectedLedtIP
	selLocalHost = [[NSMutableString alloc] init];
	selRemoteHost = [[NSMutableString alloc] init];
	
	NSString* ss = [NSString stringWithFormat: @"192.128.%@", name];
	
	[self setValue:ss forKey:@"selLocalHost"];
	
	NSMutableString *s = [self valueForKey:@"selLocalHost"];
	NSLog(@"Set value for selLocalHost = %@", s);
	
	//selAuthBy = [[NSPopUpButton alloc] init];
	
	selAuto = [[NSMutableString alloc] init];
	
	NSMutableString* tmp = [NSString stringWithFormat:@"Add"];
	
	[self setValue:tmp forKey:@"selAuto"];
	
	selAuthBy= [[NSMutableString alloc] init];
	
	NSMutableString* tmp2 = [NSString stringWithFormat:@"RSA Sig Key"];
	
	[selAuthBy setString:tmp2];
	
	//[self setValue:tmp2 forKey:@"selAuthBy"];
	
    /* finally return the object */
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
	NSLog(@"the saved value is %@", [self selLocalHost]);
	[coder encodeObject:[self selAuthBy] forKey:@"selAuthBy"];
	[coder encodeObject:[self selAuto] forKey:@"selAuto"];
	//[coder encodeObject:selLocalRSASigKey forKey:@"selLocalRSASigKey"];
	//[coder encodeObject:selRemoteRSASigKey forKey:@"selRemoteRSASigKey"];
}

- (id)initWithCoder:(NSCoder*)coder
{
	[super init];
	[self setConnName:[coder decodeObjectForKey:@"connName"]];
	[self setSelLocalHost:[coder decodeObjectForKey:@"selLocalHost"]];
	NSLog(@"the loaded value is %@", [coder decodeObjectForKey:@"selLocalHost"]);
	[self setSelRemoteHost:[coder decodeObjectForKey:@"selRemoteHost"]];
	[self setSelAuthBy:[coder decodeObjectForKey:@"selAuthBy"]];
	[self setSelAuto:[coder decodeObjectForKey:@"selAuto"]];
	//selLocalRSASigKey = [coder decodeObjectForKey:@"selLocalRSASigKey"];
	//selRemoteRSASigKey = [coder decodeObjectForKey:@"selRemoteRSASigKey"];
	return self;
}


@end


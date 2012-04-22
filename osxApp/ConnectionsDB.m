//
//  ConnectionsDB.m
//  Libreswan
//
//  Created by Jose Quaresma on 19/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "ConnectionsDB.h"
#import "Connection.h"

@implementation ConnectionsDB
@synthesize connDB;

static ConnectionsDB *sharedConnDB = nil;

+ (ConnectionsDB*)sharedInstance
{
    @synchronized(self) {
        if (sharedConnDB == nil) {
            [[self alloc] init];
        }
    }
    return sharedConnDB;
}

+ (id)allocWithZone:(NSZone *)zone
{
    @synchronized(self) {
        if (sharedConnDB == nil) {
            return [super allocWithZone:zone];
        }
    }
    return sharedConnDB;
}

- (id)init
{
    Class myClass = [self class];
    @synchronized(myClass) {
        if (sharedConnDB == nil) {
            if (self = [super init]) {
                sharedConnDB = self;
                // custom initialization here
				NSArray* values = [NSArray arrayWithObjects: [[Connection alloc] init], nil];
				NSMutableArray* tmpArray = [[NSMutableArray alloc] init];
				
				[tmpArray retain];
				[tmpArray addObjectsFromArray:values];
				[sharedConnDB setConnDB:tmpArray];
            }
        }
    }
    return sharedConnDB;
}

- (id)copyWithZone:(NSZone *)zone { return self; }

- (id)retain { return self; }

- (unsigned)retainCount { return UINT_MAX; }

- (void)release {}

- (id)autorelease { return self; }


- (void)encodeWithCoder:(NSCoder*)coder
{		
	
	[coder encodeObject:[sharedConnDB connDB] forKey:@"connDB"];
}


- (id)initWithCoder:(NSCoder*)coder
{
	[super init];
	[sharedConnDB setConnDB:[coder decodeObjectForKey:@"connDB"]];
	return self;
}


@end

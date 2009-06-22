//
//  ConnectionsDB.m
//  Openswan
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
				NSArray* values = [NSArray arrayWithObjects: [[Connection alloc] initWithName:@"Connection1"],
								   [[Connection alloc] initWithName:@"Connection2"], nil];

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

/*
- (void)encodeWithCoder:(NSCoder*)coder
{		
	[coder encodeObject:connDB forKey:@"connDB"];
}


- (id)initWithCoder:(NSCoder*)coder
{
	[super init];
	connDB = [coder decodeObjectForKey:@"connDB"];
	return self;
}
*/

//Saving and loading data
- (NSString *) pathForDataFile
{
	NSFileManager *fileManager = [NSFileManager defaultManager];
    
	NSString *folder = @"~/Library/Application Support/Openswan/";
	folder = [folder stringByExpandingTildeInPath];
	
	if ([fileManager fileExistsAtPath: folder] == NO)
	{
		[fileManager createDirectoryAtPath: folder attributes: nil];
	}
    
	NSString *fileName = @"Openswan.data";
	return [folder stringByAppendingPathComponent: fileName];
}

- (void) saveDataToDisk
{
	NSString * path = [self pathForDataFile];
	
	NSMutableDictionary * rootObject;
	rootObject = [NSMutableDictionary dictionary];
    
	[rootObject setValue:[self connDB] forKey:@"connDB"];
	[NSKeyedArchiver archiveRootObject:rootObject toFile:path];
}

- (void) loadDataFromDisk
{
	NSString     * path        = [self pathForDataFile];
	NSDictionary * rootObject;
    
	rootObject = [NSKeyedUnarchiver unarchiveObjectWithFile:path];
	[self setConnDB:[rootObject valueForKey:@"connDB"]];
}

@end

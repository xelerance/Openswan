//
//  ConnectionsDB.h
//  Libreswan
//
//  Created by Jose Quaresma on 19/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface ConnectionsDB : NSObject <NSCoding> {
	NSMutableArray* connDB;
}

@property (readwrite, retain) NSMutableArray* connDB;

+ (ConnectionsDB*)sharedInstance;

@end

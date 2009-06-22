//
//  ConnectionsDB.h
//  Openswan
//
//  Created by Jose Quaresma on 19/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface ConnectionsDB : NSObject /*<NSCoding>*/ {
	NSMutableArray* connDB;
}

@property (readwrite, copy) NSMutableArray* connDB;

+ (ConnectionsDB*)sharedInstance;

- (NSString *) pathForDataFile;
- (void) saveDataToDisk;
- (void) loadDataFromDisk;

@end

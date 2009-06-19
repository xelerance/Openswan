//
//  Connection.h
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface Connection : NSObject {

	NSString* connName;
	
	NSMutableString* selLocalHost;
	NSMutableString* selRemoteHost;
	NSMutableString* selAuthBy;
	NSMutableString* selAuto;
	NSMutableString* selLocalRSASigKey;
	NSMutableString* selRemoteRSASigKey;
}

@property (readwrite, copy) NSString *connName;
@property (readwrite, copy) NSMutableString *selLocalHost, *selRemoteHost, *selLocalRSASigKey, *selRemoteRSASigKey, *selAuto;
@property (readwrite, copy) NSMutableString *selAuthBy;

- (id) initWithName:(NSString*)name;
@end

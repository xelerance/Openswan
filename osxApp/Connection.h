//
//  Connection.h
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface Connection : NSObject <NSCoding> {

	NSMutableString* connName;
	
	NSMutableString* selLocalHost;
	NSMutableString* selRemoteHost;
	NSMutableString* selAuthBy;
	NSMutableString* selAuto;
	NSMutableString* selLocalRSASigKey;
	NSMutableString* selRemoteRSASigKey;
	NSMutableString* selPSK;
}

@property (readwrite, retain) NSMutableString *connName;
@property (readwrite, retain) NSMutableString *selLocalHost, *selRemoteHost, *selLocalRSASigKey, *selRemoteRSASigKey, *selAuto;
@property (readwrite, retain) NSMutableString *selAuthBy, *selPSK;

@end

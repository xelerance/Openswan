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
	
	//Connection Options
	NSMutableString* selAuto;
	NSMutableString* selType;
	NSMutableString* selMode;
	
	NSMutableString* selLocalHost;
	NSMutableString* selLocalID;
	NSMutableString* selLocalSubnets;
	NSMutableString* selLocalProtocolPort;
	
	NSMutableString* selRemoteHost;
	NSMutableString* selRemoteID;
	NSMutableString* selRemoteSubnets;
	NSMutableString* selRemoteProtocolPort;
	
	//Auth Options
	
	//Global Options
	
	NSMutableString* selAuthBy;
	NSMutableString* selLocalRSASigKey;
	NSMutableString* selRemoteRSASigKey;
	NSMutableString* selPSK;
}

@property (readwrite, retain) NSMutableString *connName;
@property (readwrite, retain) NSMutableString	*selAuto,
												*selType,
												*selMode,
												*selLocalHost,
												*selLocalID,
												*selLocalSubnets,
												*selLocalProtocolPort,
												*selRemoteHost,
												*selRemoteID,
												*selRemoteSubnets,
												*selRemoteProtocolPort;

@property (readwrite, retain) NSMutableString *selLocalRSASigKey, *selRemoteRSASigKey;
@property (readwrite, retain) NSMutableString *selAuthBy, *selPSK;


@end

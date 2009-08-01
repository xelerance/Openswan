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
	NSMutableString* selAuthBy;
	NSMutableString* selPSK;
	NSMutableString* selPKCS;
	NSMutableString* selSendCert;
	NSMutableString* selLocalRSASigKey;
	NSMutableString* selRemoteRSASigKey;
	
	//Global Options
	NSButton* selNatTEnable;
	NSMutableString* selVirtualPrivate;
	NSMutableString* selForceKeepAlive;
	NSMutableString* selKeepAlive;
	NSButton* selForceEncaps;
	
	NSMutableString* selCrlCheckIntvl;
	NSButton* selStrictCrlEnable;
	
	NSButton* selOppEncEnable;
	NSMutableString* selMyID;
	
	NSMutableString* selPlutoDebug;
	NSButton* selUniqueIDs;
}

@property (readwrite, retain) NSMutableString *connName;
//Connection Options
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
//Auth Options
@property (readwrite, retain) NSMutableString	*selAuthBy,
												*selPSK,
												*selPKCS,
												*selSendCert,
												*selLocalRSASigKey,
												*selRemoteRSASigKey;
//Global Options
@property (readwrite, retain) NSMutableString *selVirtualPrivate,
*selForceKeepAlive,
*selKeepAlive,
*selCrlCheckIntvl,
*selMyID,
*selPlutoDebug;

@property (readwrite, retain) NSButton *selForceEncaps,
*selNatTEnable,
*selStrictCrlEnable,
*selOppEncEnable,
*selUniqueIDs;

@end

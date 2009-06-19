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
	IBOutlet NSPopUpButton* selAuthBy;
	IBOutlet NSPopUpButton* selAuto;
	
	NSMutableString* selLocalRSASigKey;
	NSMutableString* selRemoteRSASigKey;
	
	NSArray* Type;
	NSArray* Auto;
	NSArray* phase2;
	NSArray* sendCert; 
	NSArray* dpdAction;
	NSArray* plutoDebug;
	NSArray* authBy;
	NSArray* endUserOpts;
	NSArray* mode;
	
	NSMutableString* test;
}

@property (readwrite, copy) NSMutableString *selLocalHost, *selRemoteHost, *selLocalRSASigKey, *selRemoteRSASigKey, *test;
@property (readwrite, copy) NSArray *Type, *Auto, *phase2, *sendCert, *dpdAction;
@property (readwrite, copy) NSArray *plutoDebug, *authBy, *endUserOpts, *mode;
@property (readwrite, copy) NSString *connName;
@property (readwrite, assign) NSPopUpButton *selAuthBy, *selAuto;

- (id) initWithName:(NSString*)name;
@end

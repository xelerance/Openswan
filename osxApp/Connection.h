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
	
	NSArray* Type;
	NSArray* Auto;
	NSArray* phase2;
	NSArray* sendCert; 
	NSArray* dpdAction;
	NSArray* plutoDebug;
	NSArray* authBy;
	NSArray* endUserOpts;
	NSArray* mode;

}

@property (readwrite, copy) NSMutableString *selLocalHost, *selRemoteHost, *selAuthBy, *selAuto;
@property (readwrite, copy) NSArray *Type, *Auto, *phase2, *sendCert, *dpdAction;
@property (readwrite, copy) NSArray *plutoDebug, *authBy, *endUserOpts, *mode;
@property (readwrite, copy) NSString *connName;

- (id) initWithName:(NSString*)name;
@end

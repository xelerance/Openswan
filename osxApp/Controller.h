//
//  Controller.h
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "Connection.h"

@interface Controller : NSObject {
	NSMutableArray* connections;
	NSArray* Type;
	NSArray* Auto;
	NSArray* phase2;
	NSArray* leftSendCert; 
	NSArray* rightSendCert; 
	NSArray* dpdAction;
	NSArray* plutoDebug;
	NSArray* authBy;
	NSArray* endUserOpts;
	
	IBOutlet NSWindow* window;
	IBOutlet NSButton* forceEncaps;
}

@property (readwrite, copy) NSMutableArray* connections;
@property (readwrite, copy) NSArray *Type, *Auto, *phase2, *leftSendCert, *rightSendCert, *dpdAction, *plutoDebug, *authBy, *endUserOpts;

- (id)init;

- (IBAction)advancedOpt: (id) sender;
- (IBAction)natTraversal: (id) sender;
- (IBAction)authByAction: (id) sender;

@end

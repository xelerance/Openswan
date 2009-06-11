//
//  Controller.h
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "Connection.h"
@class PreferenceController;

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
	NSArray* mode;
	
	IBOutlet NSWindow* window;
	IBOutlet NSButton* forceEncaps;
	IBOutlet NSPopUpButton* authByButton;
	IBOutlet NSPopUpButton* userOpts;
	IBOutlet NSTextField* rawRSAText;
	IBOutlet NSView* PSKView;
	IBOutlet NSView* X509View;
	IBOutlet NSView* rawRSAView;
	IBOutlet NSView* natView;
	IBOutlet NSView* oeView;
	
	PreferenceController *preferenceController;
}

@property (readwrite, copy) NSMutableArray* connections;
@property (readwrite, copy) NSArray *Type, *Auto, *phase2, *leftSendCert, *rightSendCert, *dpdAction, *plutoDebug, *authBy, *endUserOpts, *mode;

- (id)init;

- (IBAction)advancedOpt: (id) sender;
- (IBAction)authByAction: (id) sender;
- (IBAction)selectedEndUserOpt: (id)sender;
- (IBAction)natTraversal: (id) sender;
- (IBAction)oe: (id) sender;

- (IBAction)showPreferencePanel: (id)sender;

@end

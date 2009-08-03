//
//  AdvMenuController.h
//  Openswan
//
//  Created by Jose Quaresma on 11/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "Connection.h"
#import "ConnectionsDB.h"

@class PreferenceController;

@interface AdvMenuController : NSWindowController {
	NSMutableArray* connections;
	
	IBOutlet NSTextField* rawRSAText;
	IBOutlet NSView* PSKView;
	IBOutlet NSView* X509View;
	IBOutlet NSView* rawRSAView;
	IBOutlet NSView* natView;
	IBOutlet NSView* oeView;
	IBOutlet NSView* dpdView;
	
	IBOutlet NSPopUpButton* selConn;
	
	IBOutlet NSWindow *changeNameSheet;
	
	NSMutableString* prevConnName;
}

@property (readwrite, retain) NSMutableArray* connections;
@property (readwrite, retain) NSPopUpButton* selConn;
@property (readwrite, copy) NSMutableString* prevConnName;

- (IBAction)advancedOpt: (id) sender;
- (IBAction)selectedEndUserOpt: (id)sender;
- (IBAction)save: (id)sender;

- (IBAction)showChangeNameSheet:(id)sender;
- (IBAction)AppliedChangeNameSheet:(id)sender;
- (IBAction)CanceledChangeNameSheet:(id)sender;

@end

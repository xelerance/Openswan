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
	ConnectionsDB* db;
	
	IBOutlet NSTextField* rawRSAText;
	IBOutlet NSView* PSKView;
	IBOutlet NSView* X509View;
	IBOutlet NSView* rawRSAView;
	IBOutlet NSView* natView;
	IBOutlet NSView* oeView;
	
	IBOutlet NSPopUpButton* selConn;
}

@property (readwrite, copy) NSMutableArray* connections;
@property (readwrite, assign) NSPopUpButton* selConn;
@property (readwrite, assign) ConnectionsDB* db;

- (IBAction)advancedOpt: (id) sender;
- (IBAction)selectedEndUserOpt: (id)sender;
- (IBAction)natTraversal: (id) sender;
- (IBAction)oe: (id) sender;
- (IBAction)save: (id)sender;

- (NSString *) pathForDataFile;
- (void) saveDataToDisk;
- (void) loadDataFromDisk;

- (IBAction)saveData: (id)sender;
- (IBAction)loadData: (id)sender;

@end

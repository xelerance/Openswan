//
//  MainMenuController.h
//  Openswan
//
//  Created by Jose Quaresma on 11/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <Growl-WithInstaller/Growl.h>
#import "ConnectionsDB.h"

@class AdvMenuController;
@class PreferenceController;

@interface MainMenuController : NSWindowController <GrowlApplicationBridgeDelegate> {
	AdvMenuController* advMenuController;
	PreferenceController *preferenceController;
	
	ConnectionsDB* db;
	
	IBOutlet NSView* discView;
	IBOutlet NSView* connView;
	IBOutlet NSPopUpButton* selConn;
	
	NSDate* connTime;
	NSTimer* timer;
	NSTimeInterval connDuration;
	NSMutableString* connDurationPrint;
}

@property (readwrite, retain) ConnectionsDB* db;
@property (readwrite, retain) NSDate* connTime;
@property (readwrite, retain) NSMutableString* connDurationPrint;
@property (readwrite) NSTimeInterval connDuration;
@property (nonatomic, assign) NSTimer* timer;


- (IBAction)showAdvMenu: (id)sender;
- (IBAction)connDisc: (id) sender;
- (IBAction)showPreferencePanel: (id)sender;

- (NSString *) pathForDataFile;
- (void) saveDataToDisk;
- (void) loadDataFromDisk;

- (IBAction)saveData: (id)sender;
- (IBAction)loadData: (id)sender;

- (void)updateConnDuration: (NSTimer*)aTimer;
- (IBAction)connect: (id)sender;

//Growl
- (NSDictionary*) registrationDictionaryForGrowl;

@end

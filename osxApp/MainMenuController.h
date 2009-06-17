//
//  MainMenuController.h
//  Openswan
//
//  Created by Jose Quaresma on 11/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
@class AdvMenuController;
@class PreferenceController;

@interface MainMenuController : NSWindowController {
	AdvMenuController* advMenuController;
	PreferenceController *preferenceController;
	
	IBOutlet NSView* discView;
	IBOutlet NSView* connView;
	IBOutlet NSPopUpButton* selConn;
}

- (IBAction)showAdvMenu: (id)sender;
- (IBAction)connDisc: (id) sender;
- (IBAction)showPreferencePanel: (id)sender;

@end

//
//  MainMenuController.h
//  Openswan
//
//  Created by Jose Quaresma on 11/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
@class AdvMenuController;

@interface MainMenuController : NSWindowController {
	AdvMenuController* advMenuController;
	
	IBOutlet NSView* discView;
	IBOutlet NSView* connView;
}

- (IBAction)showAdvMenu: (id)sender;
- (IBAction)connDisc: (id) sender;

@end

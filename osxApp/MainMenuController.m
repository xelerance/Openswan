//
//  MainMenuController.m
//  Openswan
//
//  Created by Jose Quaresma on 11/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "MainMenuController.h"
#import "AdvMenuController.h"
#import "PreferenceController.h"
#import <AppKit/NSCell.h>

@implementation MainMenuController

- (IBAction)showAdvMenu: (id)sender
{
	//Is preferenceController nil?
	if(!advMenuController){
		advMenuController = [[AdvMenuController alloc] init];
	}
	NSLog(@"Showing %@", advMenuController);
	//NSNumber* index = [NSNumber numberWithInt: [selConn indexOfSelectedItem]];
	[[advMenuController selConn] selectItemAtIndex:[selConn indexOfSelectedItem]];
	[advMenuController showWindow: self];
}

- (IBAction)connDisc: (id) sender
{
	if([sender state] == NSOnState){
		[connView setHidden:YES];
		[discView setHidden:NO];
	}
	else{
		[connView setHidden:NO];
		[discView setHidden:YES];
	}
}

- (void)awakeFromNib
{
	[connView setHidden:NO];
	[discView setHidden:YES];
}

- (IBAction)showPreferencePanel: (id)sender
{
	//Is preferenceController nil?
	if(!preferenceController){
		preferenceController = [[PreferenceController alloc] init];
	}
	NSLog(@"Showing %@", preferenceController);
	[preferenceController showWindow: self];
}

@end

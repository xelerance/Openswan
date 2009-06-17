//
//  AdvMenuController.m
//  Openswan
//
//  Created by Jose Quaresma on 11/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "AdvMenuController.h"
#import "PreferenceController.h"

@implementation AdvMenuController
@synthesize connections, selConn;

- (id)init
{
	if(![super initWithWindowNibName:@"AdvancedMenu"])
		return nil;
	
	NSArray* values = [NSArray arrayWithObjects: [[Connection alloc] initWithName:@"Default"],[[Connection alloc] initWithName:@"Connection1"], 
					   @"Rename Connection...",@"Delete Connection...", nil];
    
    connections = [[NSMutableArray alloc] init];
	[connections addObjectsFromArray:values];
	
	authByButton = [[NSPopUpButton alloc] init];
	rawRSAText = [[NSTextField alloc] init];
	
	PSKView = [[NSView alloc] init];
	X509View = [[NSView alloc] init];
	rawRSAView = [[NSView alloc] init];
	
	natView = [[NSView alloc] init];
	oeView = [[NSView alloc] init];
	
	return self;
}

- (void)windowDidLoad
{
	NSLog(@"Advanced Menu Nib file is loaded");
}

- (IBAction)advancedOpt: (id) sender
{
	
	NSRect rect = [[super window] frame];
	NSLog(@"my height %f, my orig %f", rect.size.height, rect.origin.y);
	if([sender state] == YES)
	{
		rect.size.height = 679;
		rect.origin.x = 0;
		rect.origin.y = 101;
	}
	else
	{
		rect.size.height = 409;
		rect.origin.x = 0;
		rect.origin.y = 369;
	}
	[[super window] setFrame:rect display:YES];
}

- (IBAction)natTraversal: (id) sender
{
	if([sender state] == YES)
	{
		NSArray* subViews = [natView subviews];
		int i = [subViews count];
		while ( i-- ) {
			[[subViews objectAtIndex:i] setEnabled:YES];
		}
	}
	else
	{
		NSArray* subViews = [natView subviews];
		int i = [subViews count];
		while ( i-- ) {
			[[subViews objectAtIndex:i] setEnabled:NO];
		}
	}
}

- (IBAction)oe: (id) sender
{
	if([sender state] == YES)
	{
		NSArray* subViews = [oeView subviews];
		int i = [subViews count];
		while ( i-- ) {
			[[subViews objectAtIndex:i] setEnabled:YES];
		}
	}
	else
	{
		NSArray* subViews = [oeView subviews];
		int i = [subViews count];
		while ( i-- ) {
			[[subViews objectAtIndex:i] setEnabled:NO];
		}
	}
}

- (IBAction)authByAction: (id) sender
{
	NSLog(@"selected item in authBy: %@", [sender titleOfSelectedItem]);
}

- (IBAction)selectedEndUserOpt: (id)sender
{
	NSString* selected = [NSString stringWithString:[sender titleOfSelectedItem]];
	
	if([selected isEqualToString:@"Raw RSA"]){
		NSLog(@"user selected option Raw RSA");
		[authByButton selectItemWithTitle:@"RSA Sig Key"];
		[authByButton setEnabled:NO];
		
		[rawRSAView setHidden:NO];
		[X509View setHidden:YES];
		[PSKView setHidden:YES];
	}
	else{
		if([selected isEqualToString:@"X.509"]){
			NSLog(@"user selected option X.509");
			[authByButton selectItemWithTitle:@"RSA Sig Key"];
			[authByButton setEnabled:NO];
			
			[X509View setHidden:NO];
			[rawRSAView setHidden:YES];
			[PSKView setHidden:YES];
		}
		else{//PSK
			NSLog(@"user selected option PSK");
			[authByButton selectItemWithTitle:@"Secret"];
			[authByButton setEnabled:NO];
			
			[PSKView setHidden:NO];
			[X509View setHidden:YES];
			[rawRSAView setHidden:YES];
		}
	}
}

- (void)awakeFromNib
{
	[X509View setHidden:YES];
	[PSKView setHidden:YES];
}

- (IBAction)save: (id)sender
{
	Connection* selectedConn = [connections objectAtIndex:[selConn indexOfSelectedItem]];
	NSLog(@"saving connection: %@", [selectedConn connName]);
	NSLog(@"local host: %@",[selectedConn selLocalHost]);
	NSLog(@"remote host: %@",[selectedConn selRemoteHost]);
	NSLog(@"Auto: %d", [[selectedConn selAuto] indexOfSelectedItem]);
}
@end

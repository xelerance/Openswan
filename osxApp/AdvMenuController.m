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
@synthesize connections, selConn, prevConnName;

- (id)init
{
	if(![super initWithWindowNibName:@"AdvancedMenu"])
		return nil;
	
	connections = [[ConnectionsDB sharedInstance] connDB];
	
	rawRSAText = [[NSTextField alloc] init];
	
	PSKView = [[NSView alloc] init];
	X509View = [[NSView alloc] init];
	rawRSAView = [[NSView alloc] init];
	
	natView = [[NSView alloc] init];
	oeView = [[NSView alloc] init];
	dpdView = [[NSView alloc] init];
	
	prevConnName = [[NSMutableString alloc] init];
		
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
		rect.size.height = rect.size.height + 230;
		rect.origin.y = rect.origin.y - 230;
	}
	else
	{
		rect.size.height = rect.size.height - 230;
		rect.origin.y = rect.origin.y + 230;
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

- (IBAction)dpd: (id) sender
{
	if([sender state] == YES)
	{
		NSArray* subViews = [dpdView subviews];
		int i = [subViews count];
		while ( i-- ) {
			[[subViews objectAtIndex:i] setEnabled:YES];
		}
	}
	else
	{
		NSArray* subViews = [dpdView subviews];
		int i = [subViews count];
		while ( i-- ) {
			[[subViews objectAtIndex:i] setEnabled:NO];
		}
	}
}

- (IBAction)selectedEndUserOpt: (id)sender
{
	NSString* selected = [NSString stringWithString:[sender titleOfSelectedItem]];
	Connection* selectedConn = [connections objectAtIndex:[selConn indexOfSelectedItem]];
	
	if([selected isEqualToString:@"Raw RSA"]){
		NSLog(@"user selected option Raw RSA");
		[selectedConn setSelAuthBy:@"RSA Sig Key"];
		
		[rawRSAView setHidden:NO];
		[X509View setHidden:YES];
		[PSKView setHidden:YES];
	}
	else{
		if([selected isEqualToString:@"X.509"]){
			NSLog(@"user selected option X.509");
			[selectedConn setSelAuthBy:@"RSA Sig Key"];
			
			[X509View setHidden:NO];
			[rawRSAView setHidden:YES];
			[PSKView setHidden:YES];
		}
		else{//PSK
			NSLog(@"user selected option PSK");
			[selectedConn setSelAuthBy:@"Secret"];
			
			[PSKView setHidden:NO];
			[X509View setHidden:YES];
			[rawRSAView setHidden:YES];
		}
	}
}

- (void)awakeFromNib
{
	connections = [[ConnectionsDB sharedInstance] connDB];
	[X509View setHidden:YES];
	[PSKView setHidden:YES];
}

- (IBAction)save: (id)sender
{
	Connection* selectedConn = [connections objectAtIndex:[selConn indexOfSelectedItem]];
	NSLog(@"saving connection: %@", [selectedConn connName]);
	NSLog(@"local host: %@",[selectedConn selLocalHost]);
	NSLog(@"remote host: %@",[selectedConn selRemoteHost]);
	NSLog(@"Auto: %@", [selectedConn selAuto]);
	NSLog(@"Auto: %@", [selectedConn selAuthBy]);
}

- (IBAction)showChangeNameSheet:(id)sender{

	Connection* selectedConn = [connections objectAtIndex:[selConn indexOfSelectedItem]];

	[self setPrevConnName:[selectedConn connName]];
	
	[NSApp beginSheet:changeNameSheet
		   modalForWindow:[self window]
		modalDelegate:nil
	   didEndSelector:NULL
		  contextInfo:NULL];
}

- (IBAction)AppliedChangeNameSheet:(id)sender{
	[NSApp endSheet:changeNameSheet];
	[changeNameSheet orderOut:sender];
}

- (IBAction)CanceledChangeNameSheet:(id)sender{
	[NSApp endSheet:changeNameSheet];
	
	Connection* selectedConn = [connections objectAtIndex:[selConn indexOfSelectedItem]];
	[selectedConn setConnName:[self prevConnName]];
	
	[changeNameSheet orderOut:sender];
}


@end

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
@synthesize selConn, prevConnName, selItemIndex;

- (id)init
{
	if(![super initWithWindowNibName:@"AdvancedMenu"])
		return nil;
	
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

- (IBAction)selectedEndUserOpt: (id)sender
{
	NSString* selected = [NSString stringWithString:[sender titleOfSelectedItem]];
	Connection* selectedConn = [[self connections] objectAtIndex:[selConn indexOfSelectedItem]];
	
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
	[[self selConn] selectItemAtIndex:selItemIndex];
	[X509View setHidden:YES];
	[PSKView setHidden:YES];
}

- (IBAction)showChangeNameSheet:(id)sender{

	Connection* selectedConn = [[self connections] objectAtIndex:[selConn indexOfSelectedItem]];

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
	
	Connection* selectedConn = [[self connections] objectAtIndex:[selConn indexOfSelectedItem]];
	[selectedConn setConnName:[self prevConnName]];
	
	[changeNameSheet orderOut:sender];
}

- (NSMutableArray*)connections{
	return [[ConnectionsDB sharedInstance] connDB];
}


@end

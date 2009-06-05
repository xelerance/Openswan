//
//  Controller.m
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "Controller.h"

@implementation Controller
@synthesize connections;
@synthesize Type, Auto, phase2, leftSendCert, rightSendCert, dpdAction, plutoDebug, authBy, endUserOpts, mode;

- (id) init
{
    /* first initialize the base class */
    self = [super init];
	
    NSArray* values = [NSArray arrayWithObjects: [[Connection alloc] initWithName:@"Default"],[[Connection alloc] initWithName:@"Connection1"], 
					   @"Rename Connection...",@"Delete Connection...", nil];
    
    connections = [[NSMutableArray alloc] init];
				   [connections addObjectsFromArray:values];
	
	Type = [NSArray arrayWithObjects: @"Tunnel", @"Transport", @"Pass Through",@"Drop", @"Reject", nil];
	Auto = [NSArray arrayWithObjects: @"Start", @"Add", @"Ignore", @"Manual", @"Route", nil];
	phase2 = [NSArray arrayWithObjects: @"ESP", @"AH", nil];
	leftSendCert = [NSArray arrayWithObjects: @"Always", @"If asked",@"Never", nil];
	rightSendCert = [NSArray arrayWithObjects: @"Always", @"If asked",@"Never", nil];
	dpdAction = [NSArray arrayWithObjects: @"Hold",@"Clear", nil];
	plutoDebug = [NSArray arrayWithObjects: @"None",@"All", @"...", nil];
	authBy = [NSArray arrayWithObjects: @"RSA Sig Key", @"Secret", nil];
	endUserOpts = [NSArray arrayWithObjects: @"Raw RSA", @"X.509", @"PSK", nil];
	mode = [NSArray arrayWithObjects: @"Main",@"Aggressive",@"IKEv2", nil];
	
	window = [[NSWindow alloc] retain];
	forceEncaps = [[NSButton alloc] init];
	authByButton = [[NSPopUpButton alloc] init];
	userOpts = [[NSPopUpButton alloc] init];
	rawRSAText = [[NSTextField alloc] init];
	
	PSKView = [[NSView alloc] init];
	X509View = [[NSView alloc] init];
	rawRSAView = [[NSView alloc] init];
	
	return self;
}

- (IBAction)advancedOpt: (id) sender
{

	NSRect rect = [window frame];
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
	[window setFrame:rect display:YES];
}

- (IBAction)natTraversal: (id) sender
{
	if([sender state] == YES)
	{
		[forceEncaps setEnabled:YES];
	}
	else
	{
		[forceEncaps setEnabled:NO];
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

@end

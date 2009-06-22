//
//  AdvMenuController.m
//  Openswan
//
//  Created by Jose Quaresma on 11/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "AdvMenuController.h"
#import "PreferenceController.h"
#import "ConnectionsDB.h" 

@implementation AdvMenuController
@synthesize connections, selConn, db;

- (id)init
{
	if(![super initWithWindowNibName:@"AdvancedMenu"])
		return nil;
	
	db = [ConnectionsDB sharedInstance];
	
    connections = [[NSMutableArray alloc] init];
	connections = [db connDB];
	
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
	
	//[NSApp setDelegate: self];    
	//[self loadDataFromDisk];
	//connections = [db connDB];
}

/*
- (void) applicationWillTerminate: (NSNotification *)note
{
	[self saveDataToDisk];
}
*/
- (IBAction)save: (id)sender
{
	Connection* selectedConn = [connections objectAtIndex:[selConn indexOfSelectedItem]];
	NSLog(@"saving connection: %@", [selectedConn connName]);
	NSLog(@"local host: %@",[selectedConn selLocalHost]);
	NSLog(@"remote host: %@",[selectedConn selRemoteHost]);
	NSLog(@"Auto: %@", [selectedConn selAuto]);
	NSLog(@"Auto: %@", [selectedConn selAuthBy]);
}

//Saving and loading data
- (NSString *) pathForDataFile
{
	NSFileManager *fileManager = [NSFileManager defaultManager];
    
	NSString *folder = @"~/Library/Application Support/Openswan/";
	folder = [folder stringByExpandingTildeInPath];
	
	if ([fileManager fileExistsAtPath: folder] == NO)
	{
		[fileManager createDirectoryAtPath: folder attributes: nil];
	}
    
	NSString *fileName = @"Openswan.data";
	return [folder stringByAppendingPathComponent: fileName];
}

- (void) saveDataToDisk
{
	NSString * path = [self pathForDataFile];
	
	NSMutableDictionary * rootObject;
	rootObject = [NSMutableDictionary dictionary];
    
	[rootObject setValue:[self db] forKey:@"db"];
	[NSKeyedArchiver archiveRootObject:rootObject toFile:path];
}

- (void) loadDataFromDisk
{
	NSString     * path        = [self pathForDataFile];
	NSDictionary * rootObject;
    
	rootObject = [NSKeyedUnarchiver unarchiveObjectWithFile:path];    
	[self setDb:[rootObject valueForKey:@"db"]];
	[self setConnections:[db connDB]];
}

- (IBAction)saveData: (id)sender
{
	[self saveDataToDisk];
}
- (IBAction)loadData: (id)sender
{
	[self loadDataFromDisk];
}

@end

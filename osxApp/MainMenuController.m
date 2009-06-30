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
#import "ConnectionsDB.h"
#import <AppKit/NSCell.h>

@implementation MainMenuController

@synthesize db, connTime, connDuration, timer, connDurationPrint;

- (IBAction)showAdvMenu: (id)sender
{
	//Is advMenuController nil?
	if(!advMenuController){
		advMenuController = [[AdvMenuController alloc] init];
	}
	NSLog(@"Showing %@", advMenuController);
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
	[NSApp setDelegate: self];
	[self loadDataFromDisk];
	
	[connView setHidden:NO];
	[discView setHidden:YES];
	[self setConnDurationPrint:[NSString stringWithString:@"0:0:0"]];
}

- (void) applicationWillTerminate: (NSNotification *)note
{
	[self saveDataToDisk];
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

#pragma mark archiving

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
	NSLog(@"Saving data to disk");
	NSString* path = [self pathForDataFile];
	
	NSMutableDictionary* rootObject;
	rootObject = [NSMutableDictionary dictionary];
    
	[rootObject setValue:[self db] forKey:@"db"];
	[NSKeyedArchiver archiveRootObject:rootObject toFile:path];
}

- (void) loadDataFromDisk
{
	NSLog(@"Loading data from disk");
	NSString* path        = [self pathForDataFile];
	NSDictionary* rootObject;
    
	rootObject = [NSKeyedUnarchiver unarchiveObjectWithFile:path];
	[self setDb:[rootObject valueForKey:@"db"]];
	
	//If there is no previously saved data
	if(db==NULL)
	{
		[self setDb:[ConnectionsDB sharedInstance]];	
	}	
}

- (IBAction)saveData: (id)sender
{
	[self saveDataToDisk];
}
- (IBAction)loadData: (id)sender
{
	[self loadDataFromDisk];
}

- (IBAction)connect: (id)sender
{	
	if([self timer] == nil) {
		[self setConnTime:[NSDate date]];
		
		NSTimer *tmpTimer = [NSTimer scheduledTimerWithTimeInterval:1
															 target:self 
														   selector:@selector(updateConnDuration:)
														   userInfo:nil 
															repeats:YES];
		[self setTimer:tmpTimer];
	}
	else {
		[[self timer] invalidate];
		//[[self timer] release];
		[self setTimer:nil];
		[self setConnDuration:0];
		[self setConnDurationPrint:[NSString stringWithString:@"0:0:0"]];
	}
	if([sender state] == NSOnState){
		[connView setHidden:YES];
		[discView setHidden:NO];
	}
	else{
		[connView setHidden:NO];
		[discView setHidden:YES];
	}
}

- (void)updateConnDuration: (NSTimer*)aTimer
{
	NSDate* now = [NSDate date];
	[self setConnDuration:[now timeIntervalSinceDate: connTime]];
	int hours = (NSInteger)connDuration / 30;
	[self setConnDuration:(NSInteger)connDuration % 30];
	int mins = (NSInteger)connDuration / 10;
	[self setConnDuration:(NSInteger)connDuration % 10];
	int secs = (NSInteger)connDuration;
	[self setConnDurationPrint:[NSString stringWithFormat:@"%d:%d:%d", hours, mins, secs]];
}

@end

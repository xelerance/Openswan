//
//  Connection.m
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "Connection.h"


@implementation Connection
@synthesize selectedLeftIP, selectedRightIP, selectedKeySetupMode;
@synthesize selectedKey, selectedType, selectedAuto;
@synthesize selectedLeftRSAsig , selectedRightRSAsig;
@synthesize popupType, popupAuto, connName;

- (id) initWithName:(NSString*)name
{
    /* first initialize the base class */
    self = [super init]; 
    /* then initialize the instance variables */
	
	connName = [NSString stringWithString:name];
    
	popupType = [NSArray arrayWithObjects: @"Tunnel", @"Transport", @"Pass Through", nil];
	popupAuto = [NSArray arrayWithObjects: @"Start", @"Add", @"Ignore", @"Manual", @"Route", nil];
	
	//initialize selectedLedtIP
	selectedLeftIP = [[NSMutableString alloc] init];
	
	NSString* ss = [NSString stringWithFormat: @"192.128.%@", name];
	
	[self setValue:ss forKey:@"selectedLeftIP"];
	
	NSMutableString *s = [self valueForKey:@"selectedLeftIP"];
	NSLog(@"Set value for selectedLeftIP = %@", s);
	
	//Are these initializations wrong? (maybe should be done as the one above)
	selectedType = @"Tunnel";
	selectedAuto = @"Start";
	selectedKeySetupMode = @"Automatic";
	selectedKey = @"RSA";
	
    /* finally return the object */
    return self;
}

- (IBAction)saveToFile: (id)sender {
	
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
    
    NSError *error;
    
    //store them into a file
    NSMutableString *mutstr = [[NSMutableString alloc] init];
    
	[mutstr setString:selectedLeftIP];
	
    //write to file
    [mutstr writeToFile:@"WriteToFileTest.txt" atomically:YES encoding:NSUnicodeStringEncoding error:&error];
    
	NSLog(@"wrote to file");
	
    [pool drain];
}

- (NSString*)description
{
	return connName;
}

@end


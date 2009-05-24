//
//  Model.m
//  Openswan
//
//  Created by Jose Quaresma on 20/4/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "Model.h"

@implementation Model
@synthesize selectedLeftIP, selectedRightIP, selectedKeySetupMode;
@synthesize selectedKey, selectedType, selectedAuto;
@synthesize selectedLeftRSAsig , selectedRightRSAsig;
@synthesize popupType, popupAuto;

- (id) init
{
    /* first initialize the base class */
    self = [super init]; 
    /* then initialize the instance variables */
    
	popupType = [NSArray arrayWithObjects: @"Tunnel", @"Transport", @"Pass Through", nil];
	popupAuto = [NSArray arrayWithObjects: @"Start", @"Add", @"Ignore", @"Manual", @"Route", nil];
	
	//initialize selectedLedtIP
	selectedLeftIP = [[NSMutableString alloc] init];
	
	[self setValue:@"192.168.0.0" forKey:@"selectedLeftIP"];
	
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

- (IBAction)setDefault: (id)sender
{
	NSLog(@"setting selectedLeftIP to default");
	[self setSelectedLeftIP:@"192.168.0.0"]; 
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


@end

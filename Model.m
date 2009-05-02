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
	
	selectedType = @"Tunnel";
	selectedAuto = @"Start";
	selectedKeySetupMode = @"Automatic";
	selectedKey = @"RSA";
	
    /* finally return the object */
    return self;
}

/*
- (void) saveToFile:(NSString*) name{
	
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
    
    NSError *error;
    
    //store them into a file
    NSString *mutstr = [[NSMutableString alloc] init];
    
	mutstr = selectedLeftIP;
	//[mutstr appendFormat:@"\n"];
	
	
    //write to file
    [mutstr writeToFile:@"CARAI.txt" atomically:YES encoding:NSUnicodeStringEncoding error:&error];
    
    [pool drain];

}
*/

@end

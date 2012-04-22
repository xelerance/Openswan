//
//  PreferenceController.m
//  Libreswan
//
//  Created by Jose Quaresma on 11/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "PreferenceController.h"


@implementation PreferenceController

- (id)init
{
	if(![super initWithWindowNibName:@"Preferences"])
		return nil;
	
	return self;
}

- (void)windowDidLoad
{
	NSLog(@"Nib file is loaded");
}

@end

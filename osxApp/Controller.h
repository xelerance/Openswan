//
//  Controller.h
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "Connection.h"

@interface Controller : NSObject {
	Connection* current;
	NSMutableDictionary* connections;
}

@property (readwrite, copy) Connection* current;
@property (readwrite, copy) NSMutableDictionary* connections;

- (id)init;
- (IBAction)setDefault: (id)sender;

@end

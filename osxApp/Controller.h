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
	NSMutableArray* connections;
	//Type pop-up
	NSArray* popupType;
	//Auto pop-up
	NSArray* popupAuto;
}

@property (readwrite, copy) NSMutableArray* connections;
@property (readwrite, copy) NSArray *popupType, *popupAuto;

- (id)init;

@end

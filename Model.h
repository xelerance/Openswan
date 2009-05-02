//
//  Model.h
//  Openswan
//
//  Created by Jose Quaresma on 20/4/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface Model : NSObject {
		
	NSString* selectedLeftIP;
	NSString* selectedRightIP;
	NSString* selectedKeySetupMode;
	NSString* selectedKey;
	NSString* selectedType;
	NSString* selectedAuto;
	NSString* selectedLeftRSAsig;
	NSString* selectedRightRSAsig;
	//Type pop-up
	NSArray* popupType;
	//Auto pop-up
	NSArray* popupAuto;
}

@property (readwrite, copy) NSString *selectedLeftIP, *selectedRightIP, *selectedKeySetupMode;
@property (readwrite, copy) NSString *selectedKey, *selectedType, *selectedAuto;
@property (readwrite, copy) NSString *selectedLeftRSAsig , *selectedRightRSAsig;
@property (readwrite, copy) NSArray *popupType, *popupAuto;

- (id) init;
/*
- (void) saveToFile:(NSString*) name;
*/
@end

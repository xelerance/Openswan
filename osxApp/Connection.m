//
//  Connection.m
//  Openswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "Connection.h"


@implementation Connection
@synthesize connName;
//Connection Options
@synthesize 
selAuto,
selType,
selMode,
selLocalHost,
selLocalID,
selLocalSubnets,
selLocalProtocolPort,
selRemoteHost,
selRemoteID,
selRemoteSubnets,
selRemoteProtocolPort;
//Auth Options
@synthesize 
selAuthBy,
selPSK,
selPKCS,
selSendCert,
selLocalRSASigKey,
selRemoteRSASigKey;
//Global Options
@synthesize
selVirtualPrivate,
selForceKeepAlive,
selKeepAlive,
selCrlCheckIntvl,
selMyID,
selPlutoDebug,
selForceEncaps,
selNatTEnable,
selStrictCrlEnable,
selOppEncEnable,
selUniqueIDs;

//Advanced Options
@synthesize
selDPDDelay,
selDPDTimeout,
selDPDAction,
selDPDEnable,
selIKE1Enc,
selIKE1Hash,
selIKE2Enc,
selIKE2Hash,
selIKEv2,
selIKELifetime,
selPhase2,
selPhase2Alg,
selSALifetime,
selRekeyMargin,
selRekeyFuzz,
selKeyingTries,
selCompressEnable,
selPfsEnable,
selRekeyEnable;

- (id)init
{
	//first initialize the base class
    self = [super init]; 
    //then initialize the instance variables
	
	connName = [NSString stringWithString:@"New Connection"];
	
	//Connection Options
	selAuto = [NSString stringWithString:@"Start"];
	selType = [NSString stringWithString:@"Tunnel"];
	selMode = [NSString stringWithString:@"IKEv2"];

	//Auth Options
	selAuthBy= [NSString stringWithString:@"RSA Sig Key"];
	selSendCert = [NSString stringWithString:@"Always"];
	
	//Global Options
	selPlutoDebug = [NSString stringWithString:@"None"];
	
	//Advanced Options
	selDPDAction = [NSString stringWithString:@"Hold"];
	
	selIKE1Enc = [NSString stringWithString:@"AES"];
	selIKE1Hash = [NSString stringWithString:@"SHA1"];
	selIKE2Enc = [NSString stringWithString:@"3DES"];
	selIKE2Hash = [NSString stringWithString:@"MD5"];
	selIKEv2 = [NSString stringWithString:@"Propose"];
	selPhase2 = [NSString stringWithString:@"ESP"];
	
    // finally return the object
    return self;
}

- (NSString*)description
{
	return connName;
}

- (void)encodeWithCoder:(NSCoder*)coder
{
	[coder encodeObject:[self connName] forKey:@"connName"];
	
	//Connection Options
	[coder encodeObject:[self selAuto] forKey:@"selAuto"];
	[coder encodeObject:[self selType] forKey:@"selType"];
	[coder encodeObject:[self selMode] forKey:@"selMode"];
	[coder encodeObject:[self selLocalHost] forKey:@"selLocalHost"];
	[coder encodeObject:[self selLocalID] forKey:@"selLocalID"];
	[coder encodeObject:[self selLocalSubnets] forKey:@"selLocalSubnets"];
	[coder encodeObject:[self selLocalProtocolPort] forKey:@"selLocalProtocolPort"];
	[coder encodeObject:[self selRemoteHost] forKey:@"selRemoteHost"];
	[coder encodeObject:[self selRemoteID] forKey:@"selRemoteID"];
	[coder encodeObject:[self selRemoteSubnets] forKey:@"selRemoteSubnets"];
	[coder encodeObject:[self selRemoteProtocolPort] forKey:@"selRemoteProtocolPort"];
	
	//AuthOptions
	[coder encodeObject:[self selAuthBy] forKey:@"selAuthBy"];
	[coder encodeObject:[self selPSK] forKey:@"selPSK"];
	[coder encodeObject:[self selPKCS] forKey:@"selPKCS"];
	[coder encodeObject:[self selSendCert] forKey:@"selSendCert"];
	[coder encodeObject:[self selLocalRSASigKey] forKey:@"selLocalRSASigKey"];
	[coder encodeObject:[self selRemoteRSASigKey] forKey:@"selRemoteRSASigKey"];
	
	//Global Options
	[coder encodeObject:[self selVirtualPrivate] forKey:@"selVirtualPrivate"];
	[coder encodeObject:[self selForceKeepAlive] forKey:@"selForceKeepAlive"];
	[coder encodeObject:[self selKeepAlive] forKey:@"selKeepAlive"];
	[coder encodeObject:[self selCrlCheckIntvl] forKey:@"selCrlCheckIntvl"];
	[coder encodeObject:[self selMyID] forKey:@"selMyID"];
	[coder encodeObject:[self selPlutoDebug] forKey:@"selPlutoDebug"];
	[coder encodeObject:[self selForceEncaps] forKey:@"selForceEncaps"];
	[coder encodeObject:[self selNatTEnable] forKey:@"selNatTEnable"];
	[coder encodeObject:[self selStrictCrlEnable] forKey:@"selStrictCrlEnable"];
	[coder encodeObject:[self selOppEncEnable] forKey:@"selOppEncEnable"];
	[coder encodeObject:[self selUniqueIDs] forKey:@"selUniqueIDs"];
	
	//Advanced Options
	[coder encodeObject:[self selDPDDelay] forKey:@"selDPDDelay"];
	[coder encodeObject:[self selDPDTimeout] forKey:@"selDPDTimeout"];
	[coder encodeObject:[self selDPDAction] forKey:@"selDPDAction"];
	[coder encodeObject:[self selDPDEnable] forKey:@"selDPDEnable"];
	
	[coder encodeObject:[self selIKE1Enc] forKey:@"selIKE1Enc"];
	[coder encodeObject:[self selIKE1Hash] forKey:@"selIKE1Hash"];
	[coder encodeObject:[self selIKE2Enc] forKey:@"selIKE2Enc"];
	[coder encodeObject:[self selIKE2Hash] forKey:@"selIKE2Hash"];
	[coder encodeObject:[self selIKEv2] forKey:@"selIKEv2"];
	[coder encodeObject:[self selIKELifetime] forKey:@"selIKELifetime"];
	[coder encodeObject:[self selPhase2] forKey:@"selPhase2"];
	[coder encodeObject:[self selPhase2Alg] forKey:@"selPhase2Alg"];
	[coder encodeObject:[self selSALifetime] forKey:@"selSALifetime"];
	[coder encodeObject:[self selRekeyMargin] forKey:@"selRekeyMargin"];
	[coder encodeObject:[self selRekeyFuzz] forKey:@"selRekeyFuzz"];
	[coder encodeObject:[self selKeyingTries] forKey:@"selKeyingTries"];
	[coder encodeObject:[self selCompressEnable] forKey:@"selCompressEnable"];
	[coder encodeObject:[self selPfsEnable] forKey:@"selPfsEnable"];
	[coder encodeObject:[self selRekeyEnable] forKey:@"selRekeyEnable"];
}

- (id)initWithCoder:(NSCoder*)coder
{
	[super init];
	[self setConnName:[coder decodeObjectForKey:@"connName"]];
	
	//Connection Options
	[self setSelAuto:[coder decodeObjectForKey:@"selAuto"]];
	[self setSelType:[coder decodeObjectForKey:@"selType"]];
	[self setSelMode:[coder decodeObjectForKey:@"selMode"]];
	[self setSelLocalHost:[coder decodeObjectForKey:@"selLocalHost"]];
	[self setSelLocalID:[coder decodeObjectForKey:@"selLocalID"]];
	[self setSelLocalSubnets:[coder decodeObjectForKey:@"selLocalSubnets"]];
	[self setSelLocalProtocolPort:[coder decodeObjectForKey:@"selLocalProtocolPort"]];
	[self setSelRemoteHost:[coder decodeObjectForKey:@"selRemoteHost"]];
	[self setSelRemoteID:[coder decodeObjectForKey:@"selRemoteID"]];
	[self setSelRemoteSubnets:[coder decodeObjectForKey:@"selRemoteSubnets"]];
	[self setSelRemoteProtocolPort:[coder decodeObjectForKey:@"selRemoteProtocolPort"]];
	
	//Auth Options
	[self setSelAuthBy:[coder decodeObjectForKey:@"selAuthBy"]];
	[self setSelPSK:[coder decodeObjectForKey:@"selPSK"]];
	[self setSelPKCS:[coder decodeObjectForKey:@"selPKCS"]];
	[self setSelSendCert:[coder decodeObjectForKey:@"selSendCert"]];
	[self setSelLocalRSASigKey:[coder decodeObjectForKey:@"selLocalRSASigKey"]];
	[self setSelRemoteRSASigKey:[coder decodeObjectForKey:@"selRemoteRSASigKey"]];
	
	//Global Options
	[self setSelVirtualPrivate:[coder decodeObjectForKey:@"selVirtualPrivate"]];
	[self setSelForceKeepAlive:[coder decodeObjectForKey:@"selForceKeepAlive"]];
	[self setSelKeepAlive:[coder decodeObjectForKey:@"selKeepAlive"]];
	[self setSelCrlCheckIntvl:[coder decodeObjectForKey:@"selCrlCheckIntvl"]];
	[self setSelMyID:[coder decodeObjectForKey:@"selMyID"]];
	[self setSelPlutoDebug:[coder decodeObjectForKey:@"selPlutoDebug"]];
	[self setSelForceEncaps:[coder decodeObjectForKey:@"selForceEncaps"]];
	[self setSelNatTEnable:[coder decodeObjectForKey:@"selNatTEnable"]];
	[self setSelStrictCrlEnable:[coder decodeObjectForKey:@"selStrictCrlEnable"]];
	[self setSelOppEncEnable:[coder decodeObjectForKey:@"selOppEncEnable"]];
	[self setSelUniqueIDs:[coder decodeObjectForKey:@"selUniqueIDs"]];
	
	//Advanced Options
	[self setSelDPDDelay:[coder decodeObjectForKey:@"selDPDDelay"]];
	[self setSelDPDTimeout:[coder decodeObjectForKey:@"selDPDTimeout"]];
	[self setSelDPDAction:[coder decodeObjectForKey:@"selDPDAction"]];
	[self setSelDPDEnable:[coder decodeObjectForKey:@"selDPDEnable"]];
	
	[self setSelIKE1Enc:[coder decodeObjectForKey:@"selIKE1Enc"]];
	[self setSelIKE1Hash:[coder decodeObjectForKey:@"selIKE1Hash"]];
	[self setSelIKE2Enc:[coder decodeObjectForKey:@"selIKE2Enc"]];
	[self setSelIKE2Hash:[coder decodeObjectForKey:@"selIKE2Hash"]];
	[self setSelIKEv2:[coder decodeObjectForKey:@"selIKEv2"]];
	[self setSelIKELifetime:[coder decodeObjectForKey:@"selIKELifetime"]];
	[self setSelPhase2:[coder decodeObjectForKey:@"selPhase2"]];
	[self setSelPhase2Alg:[coder decodeObjectForKey:@"selPhase2Alg"]];
	[self setSelSALifetime:[coder decodeObjectForKey:@"selSALifetime"]];
	[self setSelRekeyMargin:[coder decodeObjectForKey:@"selRekeyMargin"]];
	[self setSelRekeyFuzz:[coder decodeObjectForKey:@"selRekeyFuzz"]];
	[self setSelKeyingTries:[coder decodeObjectForKey:@"selKeyingTries"]];
	[self setSelCompressEnable:[coder decodeObjectForKey:@"selCompressEnable"]];
	[self setSelPfsEnable:[coder decodeObjectForKey:@"selPfsEnable"]];
	[self setSelRekeyEnable:[coder decodeObjectForKey:@"selRekeyEnable"]];
	
	return self;
}


@end


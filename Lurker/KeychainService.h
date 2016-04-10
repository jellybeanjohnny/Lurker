//
//  KeychainService.h
//  Lurker
//
//  Created by Matt Amerige on 4/10/16.
//  Copyright © 2016 Wubbyland. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface KeychainService : NSObject

- (void)saveToken:(NSString *)token;
- (NSString *)loadToken;

@end

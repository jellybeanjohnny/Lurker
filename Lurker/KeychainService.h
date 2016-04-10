//
//  KeychainService.h
//  Lurker
//
//  Created by Matt Amerige on 4/10/16.
//  Copyright © 2016 Wubbyland. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum
{
  OAUTH_TOKEN,
  REFRESH_TOKEN
} TokenType;

@interface KeychainService : NSObject

/**
 @abstract Saves the specified token with corresponding token type to the keychain.
 @param token A string representation of the token to be stored.
 @param tokenType Either a token or refresh token, specifed by the enum.
 @discussion If there is already an entry for the tokentype in the keychain the item will be updated,
 otherwise a new entry is created.
 */
- (void)saveToken:(NSString *)token withType:(TokenType)tokenType;

/**
 Loads the token from the keychain that matches the specified tokentype.
 @param tokenType Either a token or refresh token, specified by the enum TokenType.
 @return if No matching item is found, returns nil, otherwise a token-string is returned.
 */
- (NSString *)loadTokenForType:(TokenType)tokenType;

@end

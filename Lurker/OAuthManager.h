//
//  OauthManager.h
//  Lurker
//
//  Created by Matt Amerige on 3/7/16.
//  Copyright © 2016 Wubbyland. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum UserContextType_
{
  UserlessContext,
  ValidUserContext
} UserContextType;

@protocol OAuthManagerDelegate <NSObject>
@optional
/**
 @abstract OAuthManager can alert its delegate when the token request process is completed,
 and it successfully completed or not
 @discussion After the request is completed you can access the token via the KeychainServices class.
 */
- (void)authTokenRequestDidComplete:(BOOL)succeeded;

@end

/**
 This class provides an interface for dealing with all things OAuth required by the Reddit Api to access user data.
 It includes generating authorization tokens and refresh tokens.
 */
@interface OAuthManager : NSObject

/**
 Shared singleton instance of the OAuthManager
 */
+ (OAuthManager *)sharedManager;

/**
 @abstract Starts the OAuth process for a user context.
 */
- (void)startForUserContext;

/**
 @abstract Starts the OAuth Process for a userless context.
 */
- (void)startForUserlessContext;

/**
 @abstract Parses the response reddit for a URL which includes the code to receive an access token
 */
- (BOOL)parseAuthorizationResponseForURL:(NSURL *)url;

/**
 Refreshes the token depending on the current user context. 
 */
- (void)refreshToken;

/**
 The URL to allow/deny access for this user
 */
@property (nonatomic, readonly) NSURL *authorizationURL;

@property (nonatomic, readonly) UserContextType userContextType;

@property (nonatomic, weak) id<OAuthManagerDelegate> delegate;



@end

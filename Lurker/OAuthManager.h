//
//  OauthManager.h
//  Lurker
//
//  Created by Matt Amerige on 3/7/16.
//  Copyright © 2016 Wubbyland. All rights reserved.
//

#import <Foundation/Foundation.h>

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
 @abstract Sends POST request for OAuth with a userless context
 @discussion This will be used when the user first opens the app before logging in
 */
- (void)postRequestForApplicationOnlyOAuth;

/**
 @abstract Parses the response reddit for a URL which includes the code to receive an access token
 */
- (BOOL)parseAuthorizationResponseForURL:(NSURL *)url;

/**
 Sends a POST request for another token and refresh token
 */
- (void)refreshToken;

/**
 The URL to allow/deny access for this user
 */
@property (nonatomic, readonly) NSURL *authorizationURL;

@property (nonatomic, weak) id<OAuthManagerDelegate> delegate;



@end

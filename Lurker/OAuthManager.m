//
//  OAuthManager.m
//  Lurker
//
//  Created by Matt Amerige on 3/7/16.
//  Copyright © 2016 Wubbyland. All rights reserved.
//
// https://github.com/reddit/reddit/wiki/OAuth2

#import "OAuthManager.h"
#import "KeychainService.h"
#import "Constants.h"
#import "PlistManager.h"


static const NSString *REDIRECT_URI = @"myappscheme://response";

@interface OAuthManager ()
{
  NSURL *_authorizationURL;
  NSString *_state;
  NSError *_oAuthResponseError;
  
  UserContextType _userContextType;
  
  
  __weak id <OAuthManagerDelegate> _delegate;
  
  
}

@end

@implementation OAuthManager
@synthesize authorizationURL = _authorizationURL;
@synthesize userContextType = _userContextType;

+ (OAuthManager *)sharedManager
{
  static OAuthManager *sharedInstance = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedInstance = [[OAuthManager alloc] init];
  });
  return sharedInstance;
}

- (instancetype)init
{
  if (!(self = [super init])) {
    return nil;
  }
  _oAuthResponseError = nil;
  _authorizationURL = nil;
  
  _state = [[NSUUID UUID] UUIDString];
  _userContextType = UserlessContext;

  return self;
}

#pragma mark - User Authorization

/**
 Generates the URL to send the user to log in to reddit. 
 The URL includes the appropriate scope, duration, redirect uri, and client id
 for this application
 */
NSURL * _generateAuthURLForState(NSString *state)
{
  
  /*
   Scopes: mysubreddits, identity, read, save, vote, history
   */
  
  NSString *scopes = @"mysubreddits+identity+read+save+vote+history";
  NSString *clientId = plistObjectForKey(kRedditClientIdKey);
  NSString *URLString = [NSString stringWithFormat:
      @"https://www.reddit.com/api/v1/authorize.compact?client_id=%@&response_type=code&state=%@&redirect_uri=%@&duration=permanent&scope=%@",
                         clientId, state, REDIRECT_URI, scopes];
  return [NSURL URLWithString:URLString];
}


/**
 @abstract Parses the response reddit for a URL which includes the code to receive an access token
 */
- (BOOL)parseAuthorizationResponseForURL:(NSURL *)url
{
  if ([url.scheme isEqualToString:@"myappscheme"]) {
    NSArray *queryParams = [[url query] componentsSeparatedByString:@"&"];
    NSArray *codeParam = [queryParams filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"SELF BEGINSWITH %@", @"code="]];
    NSString *codeQuery = [codeParam objectAtIndex:0];
    NSString *code = [codeQuery stringByReplacingOccurrencesOfString:@"code=" withString:@""];
    [self _requestAuthTokenForCode:code];
    return YES;
  }
  
  return NO;
}

/**
 @abstract Using the code received from the response url, makes a POST request for an access token
 */
- (void)_requestAuthTokenForCode:(NSString *)code
{
  [self _postRequestForTokenWithBodyString:[NSString stringWithFormat:@"grant_type=authorization_code&code=%@&redirect_uri=%@",
                                            code, REDIRECT_URI] block:nil];
}

/**
 Sends a post request for a refresh token.
 */
- (void)refreshToken
{
  [self refreshTokenWithBlock:nil];
}

- (void)refreshTokenWithBlock:(void(^)(BOOL succeeded))completionHandler
{
  if (_userContextType == ValidUserContext ) {
    KeychainService *keychainService = [[KeychainService alloc] init];
    NSString *token = [keychainService loadTokenForType:REFRESH_TOKEN];
    [self _postRequestForTokenWithBodyString:[NSString stringWithFormat:@"grant_type=refresh_token&refresh_token=%@",
                                              token] block:^(BOOL succeeded) {
      
      if (completionHandler) {
        if (succeeded) completionHandler(YES);
        else completionHandler(NO);
      }
    }];
  }
  else {
    [self startForUserlessContextWithBlock:^(BOOL succeeded) {
      if (completionHandler) {
        if (succeeded) completionHandler(YES);
        else completionHandler(NO);
      }
    }];
  }
}


/**
 @abstract Sends a POST request for an access token for the specified bodyString
 @param bodyString A string to be encoded as the HTTP Body for the POST request. Should either be for a normal access token or a refresh token
 */
- (void)_postRequestForTokenWithBodyString:(NSString *)bodyString block:(void(^)(BOOL succeeded))completionHandler
{
  NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:[NSURL URLWithString:@"https://www.reddit.com/api/v1/access_token"]];
  NSString *loginString = [NSString stringWithFormat:@"%@:%@", plistObjectForKey(kRedditClientIdKey), @""];
  NSData *authData = [loginString dataUsingEncoding:NSASCIIStringEncoding];
  NSString *authValue = [NSString stringWithFormat:@"Basic %@",
                         [authData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed]];
  [request setValue:authValue forHTTPHeaderField:@"Authorization"];
  request.HTTPMethod = @"POST";
  request.HTTPBody = [bodyString dataUsingEncoding:NSUTF8StringEncoding];
  request.timeoutInterval = 5;
  NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request
   completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
     if (!error) {
       [self _parseAuthTokenResponse:data succeeded:^(BOOL succeeded) {
         if (completionHandler) {
           if (succeeded) completionHandler(YES);
           else completionHandler(NO);
         }
       }];
     }
     else {
       // handle error
       if (completionHandler) completionHandler(NO);
       NSLog(@"Error completing POST request for OAuth Token: %@", error);
     }
   }];
  [task resume];
}

/**
 @abstract Parses the response from the access token POST request
 */
- (void)_parseAuthTokenResponse:(NSData *)response succeeded:(void(^)(BOOL succeeded))completionBlock
{
  NSError *jsonError;
  NSDictionary *jsonResponse = [NSJSONSerialization JSONObjectWithData:response
                                                               options:kNilOptions
                                                                 error:&jsonError];
  
  NSLog(@"Here's the JSON Response for the Auth Token request:\n%@", jsonResponse);
  
  if ([jsonResponse objectForKey:@"error"]) {
    NSLog(@"There's been error loading JSON!");
    NSString *errorString = [jsonResponse objectForKey:@"error"];
    _oAuthResponseError = [NSError errorWithDomain:@"OAuthResponseError" code:[errorString integerValue] userInfo:nil];
    [self _alertDelegateForOAuthCompletion:NO];
    if (completionBlock) completionBlock(NO);
  }
  else {
    _oAuthResponseError = nil;
    KeychainService *keychainService = [[KeychainService alloc] init];
    
    // Store the token on the keychain
    NSString *accessToken = [jsonResponse objectForKey:@"access_token"];
    if (accessToken) [keychainService saveToken:accessToken withType:OAUTH_TOKEN];
    
    // Store the refresh token on the keychain
    NSString *refreshToken = [jsonResponse objectForKey:@"refresh_token"];
    if (refreshToken) [keychainService saveToken:refreshToken withType:REFRESH_TOKEN];

    [self _alertDelegateForOAuthCompletion:YES];
    if (completionBlock) completionBlock(YES);
  }
}

#pragma mark - Application Only OAuth

/**
 @abstract Sends POST request for OAuth with a userless context
 */
- (void)_postRequestForApplicationOnlyOAuthWithBlock:(void(^)(BOOL completed))completionHandler
{
  NSString *appOnlyBodyString = [NSString stringWithFormat:@"grant_type=https://oauth.reddit.com/grants/installed_client&device_id=%@", _state];
  [self _postRequestForTokenWithBodyString:appOnlyBodyString block:^(BOOL succeeded) {
    if (completionHandler) {
      if (succeeded) completionHandler(YES);
      else completionHandler(NO);
    }
  }];
}



#pragma mark - Delegate Methods

/**
 @abstract Alerts the delegate that the token request is completed, and if it succeeded or not
 */
- (void)_alertDelegateForOAuthCompletion:(BOOL)didSucceed
{
  if (_delegate && [_delegate respondsToSelector:@selector(authTokenRequestDidComplete:)]) {
    [_delegate authTokenRequestDidComplete:didSucceed];
  }
}

#pragma mark - Starting OAuth for Userless and Valid User contexts

- (void)startForUserContext
{
  _userContextType = ValidUserContext;
  _authorizationURL = _generateAuthURLForState(_state);
  
}

- (void)startForUserlessContext
{
  [self startForUserlessContextWithBlock:nil];
}

- (void)startForUserlessContextWithBlock:(void(^)(BOOL succeeded))completionhandler
{
  _userContextType = UserlessContext;
  [self _postRequestForApplicationOnlyOAuthWithBlock:^(BOOL completed) {
    if (completionhandler) {
      if (completed) completionhandler(YES);
      else completionhandler(NO);
    }
  }];
}


@end









//
//  RedditAPIService.m
//  Lurker
//
//  Created by Matt Amerige on 4/17/16.
//  Copyright © 2016 Wubbyland. All rights reserved.
//

#import "RedditAPIService.h"
#import "OAuthManager.h"
#import "KeychainService.h"

@interface RedditAPIService() <OAuthManagerDelegate>
{
  
}

@end

@implementation RedditAPIService

- (instancetype)init
{
  if (!(self = [super init])) {
    return nil;
  }
  
  [OAuthManager sharedManager].delegate = self;
    
  return self;
}


/*
 Logic I'm going for:

 Get the oauth token from the keychain
 If there isnt a token in the keychain, generate one through the OAuthManager
 Make the post request for the front page data
 return the data through the completionBlock


 */
- (void)frontPageWithBlock:(void(^)(NSDictionary *results))completionBlock
{
  // Retrieve the token
  KeychainService *keychainService = [[KeychainService alloc] init];
  NSString *token = [keychainService loadTokenForType:OAUTH_TOKEN];
  
  // What if token is nil?
  if (!token) {
    // dispatch_sync
    [[OAuthManager sharedManager] refreshToken];
  }
  
  NSURL *url = [NSURL URLWithString:@"https://oauth.reddit.com"];
  NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
  NSString *authValue = [NSString stringWithFormat:@"bearer %@", token];
  [request setValue:authValue forHTTPHeaderField:@"Authorization"];
  
  NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request
      completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
      if (!error) {
       NSLog(@"response: %@", response);
       NSError *jsonError;
       NSDictionary *jsonResponse = [NSJSONSerialization JSONObjectWithData:data
                                                                    options:kNilOptions
                                                                      error:&jsonError];
       
       NSLog(@"Front Page JSON:\n%@", jsonResponse);
        completionBlock(jsonResponse);
      }
      else {
       // handle error
        completionBlock(nil);
       NSLog(@"Error completing POST request for OAuth Token: %@", error);
      }
      }];
  [task resume];
}


@end

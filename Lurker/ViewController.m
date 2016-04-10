//
//  ViewController.m
//  Lurker
//
//  Created by Matt Amerige on 3/6/16.
//  Copyright © 2016 Wubbyland. All rights reserved.
//

#import "ViewController.h"
#import "OAuthManager.h"
#import <SafariServices/SafariServices.h>
#import "KeychainService.h"

@interface ViewController () <OAuthManagerDelegate>
{
  
}
@end

@implementation ViewController

- (void)viewDidLoad
{
  [super viewDidLoad];
  
  [OAuthManager sharedManager].delegate = self;
}

- (IBAction)_safariViewController:(id)sender
{
  NSURL *url = [OAuthManager sharedManager].authorizationURL;
  [OAuthManager sharedManager].delegate = self;
  SFSafariViewController *safariVC = [[SFSafariViewController alloc] initWithURL:url];
  [self showViewController:safariVC sender:nil];
  
}

- (void)authTokenRequestDidComplete:(BOOL)succeeded
{
  if (succeeded) {
    // Retrieve the token
    KeychainService *keychainService = [[KeychainService alloc] init];
    NSString *token = [keychainService loadTokenForType:OAUTH_TOKEN];
    
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
       }
       else {
         // handle error
         NSLog(@"Error completing POST request for OAuth Token: %@", error);
       }
     }];
    [task resume];


  }
}


@end

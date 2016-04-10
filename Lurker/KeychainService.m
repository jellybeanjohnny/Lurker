//
//  KeychainService.m
//  Lurker
//
//  Created by Matt Amerige on 4/10/16.
//  Copyright © 2016 Wubbyland. All rights reserved.
//

#import "KeychainService.h"
#import <Security/Security.h>

@interface KeychainService()
{
  
}
@end

@implementation KeychainService


- (void)saveToken:(NSString *)token withType:(TokenType)tokenType
{
  NSMutableDictionary *keychainItem = [NSMutableDictionary dictionary];
  keychainItem[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  keychainItem[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleWhenUnlocked;
  keychainItem[(__bridge id)kSecAttrLabel] = [NSString stringWithFormat:@"%d", tokenType];
  
  if (SecItemCopyMatching((__bridge CFDictionaryRef)keychainItem, NULL) == noErr) {
    NSMutableDictionary *attributesToUpdate = [NSMutableDictionary dictionary];
    attributesToUpdate[(__bridge id)kSecValueData] = [token dataUsingEncoding:NSUTF8StringEncoding];
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)keychainItem, (__bridge CFDictionaryRef)attributesToUpdate);
    NSLog(@"Item Update Status Code: %d", (int)status);
  }
  else {
    keychainItem[(__bridge id)kSecValueData] = [token dataUsingEncoding:NSUTF8StringEncoding];
    
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)keychainItem, NULL);
    NSLog(@"Item Add Status Code: %d", (int)status);
  }
}


- (NSString *)loadTokenForType:(TokenType)tokenType
{
  NSMutableDictionary *keychainItem = [NSMutableDictionary dictionary];
  keychainItem[(__bridge id)kSecClass]  = (__bridge id)kSecClassGenericPassword;
  keychainItem[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleWhenUnlocked;
  keychainItem[(__bridge id)kSecAttrLabel] = [NSString stringWithFormat:@"%d", tokenType];
  
  keychainItem[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
  keychainItem[(__bridge id)kSecReturnAttributes] = (__bridge id)kCFBooleanTrue;
  
  CFDictionaryRef result = nil;
  
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)keychainItem, (CFTypeRef *)&result);
  NSLog(@"Load Status: %d", (int)status);
  
  if (status == noErr) {
    NSDictionary *resultDictionary = (__bridge_transfer NSDictionary *)result;
    NSData *tokenData = resultDictionary[(__bridge id)kSecValueData];
    NSString *token = [[NSString alloc] initWithData:tokenData encoding:NSUTF8StringEncoding];
    return token;
  }
  else {
    NSLog(@"No item matching specified tokentype.");
    return nil;
  }
}

@end

































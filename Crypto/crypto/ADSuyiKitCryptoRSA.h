//
//  ADSuyiKitCryptoRSA.h
//  ADSuyiKit
//
//  Created by 陈坤 on 2020/3/19.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ADSuyiKitCryptoRSA : NSObject

// return base64 encoded string
+ (NSString *)encryptString:(NSString *)str publicKey:(NSString *)pubKey keychainTag:(NSString *)keychainTag;
// return raw data
+ (nullable NSData *)encryptData:(NSData *)data publicKey:(NSString *)pubKey keychainTag:(NSString *)keychainTag;
// return base64 encoded string
+ (NSString *)encryptString:(NSString *)str privateKey:(NSString *)privKey keychainTag:(NSString *)keychainTag;
// return raw data
+ (nullable NSData *)encryptData:(NSData *)data privateKey:(NSString *)privKey keychainTag:(NSString *)keychainTag;

// decrypt base64 encoded string, convert result to string(not base64 encoded)
+ (NSString *)decryptString:(NSString *)str publicKey:(NSString *)pubKey keychainTag:(NSString *)keychainTag;
+ (nullable NSData *)decryptData:(NSData *)data publicKey:(NSString *)pubKey keychainTag:(NSString *)keychainTag;
+ (NSString *)decryptString:(NSString *)str privateKey:(NSString *)privKey keychainTag:(NSString *)keychainTag;
+ (nullable NSData *)decryptData:(NSData *)data privateKey:(NSString *)privKey keychainTag:(NSString *)keychainTag;

@end

NS_ASSUME_NONNULL_END

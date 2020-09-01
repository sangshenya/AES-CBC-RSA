//
//  ADSuyiKitCryptoAES.m
//  ADSuyiKit
//
//  Created by 陈坤 on 2020/3/19.
//

#import "ADSuyiKitCryptoAES.h"
#import <CommonCrypto/CommonCryptor.h>
#import "NSData+ADSuyiKit.h"

NSString const *kAdsyInitVector = @"ABCDEFGJIJKLMNOP";
size_t const kAdsyKeySize = kCCKeySizeAES128;

/**
 AES加密，ECB模式
 */
NSData * adsy_ecbcipherOperation(NSData *contentData, NSData *keyData, CCOperation operation) {
    NSUInteger dataLength = contentData.length;
    
    void const *initVectorBytes = [kAdsyInitVector dataUsingEncoding:NSUTF8StringEncoding].bytes;
    void const *contentBytes = contentData.bytes;
    void const *keyBytes = keyData.bytes;
    
    size_t operationSize = dataLength + kCCBlockSizeAES128;
    void *operationBytes = malloc(operationSize);
    if (operationBytes == NULL) {
        return nil;
    }
    size_t actualOutSize = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyBytes,
                                          kAdsyKeySize,
                                          initVectorBytes,
                                          contentBytes,
                                          dataLength,
                                          operationBytes,
                                          operationSize,
                                          &actualOutSize);
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:operationBytes length:actualOutSize];
    }
    free(operationBytes);
    operationBytes = NULL;
    return nil;
}

/**
AES ECB模式加密
*/
NSString * KADSYAESECBEncryptString(NSString *content, NSString *key) {
    NSCParameterAssert(content);
    NSCParameterAssert(key);
    
    NSData *contentData = [content dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encrptedData = KADSYAESECBEncryptData(contentData, keyData);
    return [encrptedData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
}

/**
AES ECB模式解密
*/
NSString * KADSYAESECBDecryptString(NSString *content, NSString *key) {
    NSCParameterAssert(content);
    NSCParameterAssert(key);
    
    NSData *contentData = [[NSData alloc] initWithBase64EncodedString:content options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *decryptedData = KADSYAESECBDecryptData(contentData, keyData);
    //    NSString *str = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}

/**
 AES ECB模式加密
 */
NSData * KADSYAESECBEncryptData(NSData *contentData, NSData *keyData) {
    NSCParameterAssert(contentData);
    NSCParameterAssert(keyData);
    
    NSString *hint = [NSString stringWithFormat:@"The key size of AES-%lu should be %lu bytes!", kAdsyKeySize * 8, kAdsyKeySize];
    NSCAssert(keyData.length == kAdsyKeySize, hint);
    return adsy_ecbcipherOperation(contentData, keyData, kCCEncrypt);
}
/**
AES ECB模式解密
*/
NSData * KADSYAESECBDecryptData(NSData *contentData, NSData *keyData) {
    NSCParameterAssert(contentData);
    NSCParameterAssert(keyData);
    
    NSString *hint = [NSString stringWithFormat:@"The key size of AES-%lu should be %lu bytes!", kAdsyKeySize * 8, kAdsyKeySize];
    NSCAssert(keyData.length == kAdsyKeySize, hint);
    return adsy_ecbcipherOperation(contentData, keyData, kCCDecrypt);
}


#pragma mark - AES CBC 加密
NSString * KADSYAESCBCEncryptData(NSString *content, NSString *key, NSString *iv){
    NSCParameterAssert(content);
    NSCParameterAssert(key);
    
    NSData *contentData = [content dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *encryptedData = nil;
    if (key.length == 16) {
        encryptedData = [contentData AESCBC128EncryptWithKey:key gIv:iv];
    } else {
        encryptedData = [contentData AESCBC256EncryptWithKey:key gIv:iv];
    }
    
    NSData *base64Data = [encryptedData base64EncodedDataWithOptions:0];
    return [[NSString alloc]initWithData:base64Data encoding:NSUTF8StringEncoding];
}

#pragma mark - AES CBC 解密
NSString * KADSYAESCBCDecryptData(NSString *content, NSString *key, NSString *iv){
    NSCParameterAssert(content);
    NSCParameterAssert(key);
    
    // base64解密
    NSData *decodeBase64Data = [[NSData alloc]initWithBase64EncodedString:content options:NSDataBase64DecodingIgnoreUnknownCharacters];
        
    NSData *decryData = nil;
    if ( key.length == 16 ) {
        decryData = [decodeBase64Data AESCBC128DecryptWithKey:key gIv:iv];
    } else {
        decryData = [decodeBase64Data AESCBC256DecryptWithKey:key gIv:iv];
    }
    
    NSString *str = [[NSString alloc]initWithData:decryData encoding:NSUTF8StringEncoding];
    
    return str;
}

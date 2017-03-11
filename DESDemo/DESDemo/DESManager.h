//
//  DESManager.h
//  DESDemo
//
//  Created by huhaifeng on 2017/3/10.
//  Copyright © 2017年 huhaifeng. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>

@interface DESManager : NSObject
+ (NSString *)encryptUseDES:(NSString *)plainText key:(NSString *)key;
+ (NSString *)decryptUseDES:(NSString*)cipherText key:(NSString*)key;
@end

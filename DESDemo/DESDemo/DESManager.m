//
//  DESManager.m
//  DESDemo
//
//  Created by huhaifeng on 2017/3/10.
//  Copyright © 2017年 huhaifeng. All rights reserved.
//

#import "DESManager.h"
#import "GTBase64.h"
@implementation DESManager

+ (long long)random8Numbers
{
    return [self randomNumber:10000000 to:100000000];
}

// 取一个随机整数，范围在[from,to），包括from，不包括to
+ (long long)randomNumber:(long long)from to:(long long)to
{
    return (long long)(from + arc4random() % (to - from + 1));
}
/*
 *字符串加密
 *plainText : 加密明文
 *key       : 密钥 64位
 */
+ (NSString *)encryptUseDES:(NSString *)plainText key:(NSString *)key
{
    NSMutableString *ciphertext = [NSMutableString new];
    
    NSData * encryptData =[plainText dataUsingEncoding:NSUTF8StringEncoding];
    const char *encryptBytes = (const char *)[encryptData bytes];
    size_t encryptDataLength = [encryptData length];

    NSData * keyData =[key dataUsingEncoding:NSUTF8StringEncoding];
    const char *keyBytes = (const char *)[keyData bytes];
    //size_t keyDataLength = [keyData length];
    
    NSString * iv =[NSString stringWithFormat:@"%lld",[self random8Numbers]];
    NSData * ivData =[iv dataUsingEncoding:NSUTF8StringEncoding];
    const char *ivBytes = (const char *)[ivData bytes];
    
    unsigned char buffer[1024 *15];
    memset(buffer, 0, sizeof(char));

    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding,
                                          keyBytes, kCCKeySizeDES,
                                          ivBytes,
                                          encryptBytes, encryptDataLength,
                                          buffer, 1024 *15,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess)
    {
        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
        NSString * one =[self convertDataToHexStr:[iv dataUsingEncoding:NSUTF8StringEncoding]];
        NSString * two = [self convertDataToHexStr:data];
        [ciphertext appendString:one];
        [ciphertext appendString:two];
        [ciphertext uppercaseString];//转大写
        
    }
    return [ciphertext copy];
}

const char* merge(const char *s1,const char *s2)
{
    char *result = malloc(strlen(s1)+strlen(s2)+1);//+1 for the zero-terminator
    //in real code you would check for errors in malloc here
    if (result == NULL) exit (1);
    
    strcpy(result, s1);
    strcat(result, s2);
    
    return result;
}

//解密
+ (NSString *)decryptUseDES:(NSString*)cipherText key:(NSString*)key
{
    NSString * ivHex;
    NSString * cipherString =[cipherText copy];
    [cipherString lowercaseString];
    NSString * sub =[self convertDataToHexStr:[@"12345678" dataUsingEncoding:NSUTF8StringEncoding]];
    if ([cipherString length]>=[sub length])
    {
        cipherText =[cipherString substringFromIndex:[sub length]];
        ivHex =[cipherString substringToIndex:[sub length]];
    }
    NSData* cipherData = [self convertHexStrToData:cipherText];
    const char *cipherBytes = (const char *)[cipherData bytes];
    size_t ciphertDataLength = [cipherData length];
    
    NSData * keyData =[key dataUsingEncoding:NSUTF8StringEncoding];
    const char *keyBytes = (const char *)[keyData bytes];
//    size_t keyDataLength = [keyData length];

    NSData * ivData =[self convertHexStrToData:ivHex];
    const char *ivBytes = (const char *)[ivData bytes];
    
    unsigned char buffer[1024 * 15];
    memset(buffer, 0, sizeof(char));
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding,
                                          keyBytes,
                                          kCCKeySizeDES,
                                          ivBytes,
                                          cipherBytes,
                                          ciphertDataLength,
                                          buffer,
                                          1024 * 15,
                                          &numBytesDecrypted);
    NSString* plainText = nil;
    if (cryptStatus == kCCSuccess)
    {
        NSData* data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesDecrypted];
        plainText = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return plainText;
}

/**
 二进制转十六进制

 @param data 二进制数据
 @return 十六进制字符串
 */
+ (NSString *)hexStringFromData:(NSData *)data
{
    Byte *bytes = (Byte *)[data bytes];
    //下面是Byte 转换为16进制。
    NSString *hexStr=@"";
    for(int i=0;i<[data length];i++)
    {
        NSString *newHexStr = [NSString stringWithFormat:@"%x",bytes[i]&0xff];///16进制数
        
        if([newHexStr length]==1)
            
            hexStr = [NSString stringWithFormat:@"%@0%@",hexStr,newHexStr];
        
        else
            
            hexStr = [NSString stringWithFormat:@"%@%@",hexStr,newHexStr]; 
    } 
    return hexStr; 
}

//将NSString转换成十六进制的字符串则可使用如下方式:
+ (NSString *)convertDataToHexStr:(NSData *)data
{
    NSMutableString *string = [[NSMutableString alloc] initWithCapacity:[data length]];
    
    [data enumerateByteRangesUsingBlock:^(const void *bytes, NSRange byteRange, BOOL *stop) {
        unsigned char *dataBytes = (unsigned char*)bytes;
        for (NSInteger i = 0; i < byteRange.length; i++) {
            NSString *hexStr = [NSString stringWithFormat:@"%x", (dataBytes[i]) & 0xff];
            if ([hexStr length] == 2) {
                [string appendString:hexStr];
            } else {
                [string appendFormat:@"0%@", hexStr];
            }
        }
    }];
    
    return string;
}

//将十六进制的字符串转换成NSString则可使用如下方式:
+ (NSData *)convertHexStrToData:(NSString *)str
{
    if (!str || [str length] == 0)
    {
        return nil;
    }
    
    NSMutableData *hexData = [[NSMutableData alloc] initWithCapacity:8];
    NSRange range;
    if ([str length] % 2 == 0)
    {
        range = NSMakeRange(0, 2);
    } else {
        range = NSMakeRange(0, 1);
    }
    for (NSInteger i = range.location; i < [str length]; i += 2) {
        unsigned int anInt;
        NSString *hexCharStr = [str substringWithRange:range];
        NSScanner *scanner = [[NSScanner alloc] initWithString:hexCharStr];
        
        [scanner scanHexInt:&anInt];
        NSData *entity = [[NSData alloc] initWithBytes:&anInt length:1];
        [hexData appendData:entity];
        
        range.location += range.length;
        range.length = 2;
    }
    return hexData;
}
@end

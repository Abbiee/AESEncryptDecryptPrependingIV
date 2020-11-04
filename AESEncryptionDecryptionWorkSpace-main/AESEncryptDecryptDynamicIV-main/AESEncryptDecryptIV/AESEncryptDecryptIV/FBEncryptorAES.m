//
// Copyright (c) 2011 Five-technology Co.,Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

#import "FBEncryptorAES.h"
#import "NSData+Base64.h"

@implementation FBEncryptorAES

#pragma mark -
#pragma mark Initialization and deallcation


#pragma mark -
#pragma mark Praivate


#pragma mark -
#pragma mark API

+ (NSData*)encryptData:(NSData*)data key:(NSData*)key error:(NSError **)error;
{
    if (key.length != 16 && key.length != 24 && key.length != 32) {
        *error = [NSError errorWithDomain:@"keyLengthError" code:-1 userInfo:nil];
        return nil;
    }

    CCCryptorStatus ccStatus   = kCCSuccess;
    int             ivLength   = kCCBlockSizeAES128;
    size_t          cryptBytes = 0;
    NSMutableData  *dataOut     = [NSMutableData dataWithLength:ivLength + data.length + kCCBlockSizeAES128];

    int status = SecRandomCopyBytes(kSecRandomDefault, ivLength, dataOut.mutableBytes);
    NSLog(@"Data Out String Encrypt%@", dataOut);
    NSLog(@"Status ID Engrypt%d", status);
    if (status != 0) {
        *error = [NSError errorWithDomain:@"ivError" code:status userInfo:nil];
        return nil;
    }
    ccStatus = CCCrypt(kCCEncrypt,
                       kCCAlgorithmAES,
                       kCCOptionPKCS7Padding,
                       key.bytes,
                       key.length,
                       dataOut.bytes,
                       data.bytes,
                       data.length,
                       dataOut.mutableBytes + ivLength, dataOut.length,
                       &cryptBytes);

    if (ccStatus == kCCSuccess) {
        dataOut.length = cryptBytes + ivLength;
    }
    else {
        if (error) {
            *error = [NSError errorWithDomain:@"kEncryptionError" code:ccStatus userInfo:nil];
        }
        dataOut = nil;
    }

    return dataOut;
}

+ (NSData*)decryptData:(NSData*)data key:(NSData*)key error:(NSError **)error;
{
    if (key.length != 16 && key.length != 24 && key.length != 32) {
        *error = [NSError errorWithDomain:@"keyLengthError" code:-1 userInfo:nil];
        return nil;
    }

    
    CCCryptorStatus ccStatus   = kCCSuccess;
    int             ivLength   = kCCBlockSizeAES128;
    size_t          clearBytes = 0;
    NSMutableData *dataOut     = [NSMutableData dataWithLength:data.length - ivLength];
    
    NSLog(@"Data Out String Decrypt%@", dataOut);

    ccStatus = CCCrypt(kCCDecrypt,
                       kCCAlgorithmAES,
                       kCCOptionPKCS7Padding,
                       key.bytes,
                       key.length,
                       data.bytes,
                       data.bytes + ivLength,
                       data.length - ivLength,
                       dataOut.mutableBytes,
                       dataOut.length,
                       &clearBytes);

    if (ccStatus == kCCSuccess) {
        dataOut.length = clearBytes;
    }
    else {
        if (error) {
            *error = [NSError errorWithDomain:@"kEncryptionError" code:ccStatus userInfo:nil];
        }
        dataOut = nil;
    }

    return dataOut;
}


//+ (NSString*)encryptBase64String:(NSString*)string keyString:(NSString*)keyString separateLines:(BOOL)separateLines
//{
//    NSData* data = [self encryptData:[string dataUsingEncoding:NSUTF8StringEncoding]
//                                 key:[keyString dataUsingEncoding:NSUTF8StringEncoding]
//                                  iv:nil];
//    return [data base64EncodedStringWithSeparateLines:separateLines];
//}
//
//+ (NSString*)decryptBase64String:(NSString*)encryptedBase64String keyString:(NSString*)keyString
//{
//    NSData* encryptedData = [NSData dataFromBase64String:encryptedBase64String];
//    NSData* data = [self decryptData:encryptedData
//                                 key:[keyString dataUsingEncoding:NSUTF8StringEncoding]
//                                  iv:nil];
//    if (data) {
//        return [[NSString alloc] initWithData:data
//                                      encoding:NSUTF8StringEncoding];
//    } else {
//        return nil;
//    }
//}


#define FBENCRYPT_IV_HEX_LEGNTH (FBENCRYPT_BLOCK_SIZE*2)

+ (NSData*)generateIv
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        srand(time(NULL));
    });

    char cIv[FBENCRYPT_BLOCK_SIZE];
    for (int i=0; i < FBENCRYPT_BLOCK_SIZE; i++) {
        cIv[i] = rand() % 256;
    }
    return [NSData dataWithBytes:cIv length:FBENCRYPT_BLOCK_SIZE];
}

+ (NSData *)randomDataOfLength:(size_t)length {
  NSMutableData *data = [NSMutableData dataWithLength:length];

  int result = SecRandomCopyBytes(kSecRandomDefault,
                                  length,
                                  data.mutableBytes);
  NSAssert(result == 0, @"Unable to generate random bytes: %d",
           errno);

  return data;
}

+ (NSData *)random128BitAESKey {
    unsigned char buf[16];
    arc4random_buf(buf, sizeof(buf));
    return [NSData dataWithBytes:buf length:sizeof(buf)];
}

+ (NSString*)hexStringForData:(NSData*)data
{
    if (data == nil) {
        return nil;
    }

    NSMutableString* hexString = [NSMutableString string];

    const unsigned char *p = [data bytes];
    
    for (int i=0; i < [data length]; i++) {
        [hexString appendFormat:@"%02x", *p++];
    }
    return hexString;
}

NSString *letters = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

-(NSString *) randomStringWithLength: (int) len {

    NSMutableString *randomString = [NSMutableString stringWithCapacity: len];

    for (int i=0; i<len; i++) {
         [randomString appendFormat: @"%C", [letters characterAtIndex: arc4random_uniform((int)[letters length])]];
    }

    return randomString;
}

+ (NSData*)dataForHexString:(NSString*)hexString
{
    if (hexString == nil) {
        return nil;
    }
    
    const char* ch = [[hexString lowercaseString] cStringUsingEncoding:NSUTF8StringEncoding];
    NSMutableData* data = [NSMutableData data];
    while (*ch) {
        char byte = 0;
        if ('0' <= *ch && *ch <= '9') {
            byte = *ch - '0';
        } else if ('a' <= *ch && *ch <= 'f') {
            byte = *ch - 'a' + 10;
        }
        ch++;
        byte = byte << 4;
        if (*ch) {
            if ('0' <= *ch && *ch <= '9') {
                byte += *ch - '0';
            } else if ('a' <= *ch && *ch <= 'f') {
                byte += *ch - 'a' + 10;
            }
            ch++;
        }
        [data appendBytes:&byte length:1];
    }
    return data;
}

@end

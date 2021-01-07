//
//  LTEccTool.h
//  ECC
//
//  Created by wei li on 2020/12/21.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LTEccTool : NSObject
+(instancetype) shared;
/***
 * out:pubKey priKey
 * if privateKey is nil ,generate a new one 
 */
- (NSDictionary *)genKeyPair:(NSString *)privateKey;


- (NSData *)ecc_encrypt:(NSData *)dataPlainTxt pubkey:(NSString *)pubkeystring;
- (NSData *)ecc_decrypt:(NSData *)dataCipher private:(NSString *)prikey;
+ (NSData *)base64DeCode:(NSString *)strBase64;

- (NSString *)bytesToBase64:(void *)byte lenOfByte:(size_t )len;

- (void)saveKeyToKeyChain:(NSString *)secKey pubKey:(NSString *)pubKey;
- (NSString *)getSecKeyInKeychain;
- (NSString *)getPublicKeyInKeychain;

- (void)ecc_encryptFile:(NSString *)inFilePath outPath:(NSString *)outpath pubkey:(NSString *)pubkeystring;

- (void)ecc_decryptFile:(NSString *)inFilePath outPath:(NSString *)outpath secKey:(NSString *)pubkeystring;


- (NSString *)dealPath:(NSString *)path;
@end

NS_ASSUME_NONNULL_END

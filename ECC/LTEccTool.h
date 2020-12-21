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
- (NSString *) ecc_encrypt:(NSString *)strPlainTxt pubkey:(NSString *)pubkeystring;
- (NSString *)ecc_decrypt:(NSString *)strCipher private:(NSString *)prikey;


- (void)test;
@end

NS_ASSUME_NONNULL_END

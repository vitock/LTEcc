//
//  LTEccTool.m
//  ECC
//
//  Created by wei li on 2020/12/21.
//

#import "LTEccTool.h"
#import "NSData+Compression.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>
#import "secp256k1.h"
#import "secp256k1_preallocated.h"
#import "secp256k1_extrakeys.h"
#import "secp256k1_ecdh.h"
#import "base64.h"
#import "Header.h"
#import <Security/Security.h>
@interface ECCEncResult:NSObject
@property (nonatomic, strong)NSData *ephemPubkeyData;
@property (nonatomic, strong)NSData *iv;
@property (nonatomic, strong)NSData *dataEnc;
@property (nonatomic, strong)NSData *mac;



@end

@implementation ECCEncResult

- (NSString *)description{
    NSLog(@"ephemPubkeyData %@",_ephemPubkeyData);
    NSLog(@"iv:%@",_iv);
    NSLog(@"mac %@",_mac);
    NSLog(@"dataEnc %@",_dataEnc);
    
    return @"";
}


- (NSData *)toResultData{
    ECCEncResult *r = self;
    UInt16 ivLen = r.iv.length;
    UInt16 macLen = r.mac.length;
    UInt16 ephemPubLen = r.ephemPubkeyData.length;
    UInt16 Zero = 0;
    
    ivLen = CFSwapInt16HostToLittle(ivLen);
    macLen = CFSwapInt16HostToLittle(macLen);
    ephemPubLen = CFSwapInt16HostToLittle(ephemPubLen);
    
    
    
    NSMutableData *dataOut = [[NSMutableData alloc] initWithCapacity:r.ephemPubkeyData.length + r.iv.length + r.mac.length + r.dataEnc.length + 8 ];
    
    
    [dataOut appendBytes:&Zero length:2];
    
    [dataOut appendBytes:&ivLen length:2];
    [dataOut appendBytes:&macLen length:2];
    [dataOut appendBytes:&ephemPubLen length:2];
    
    [dataOut appendData:r.iv];
    [dataOut appendData:r.mac];
    [dataOut appendData:r.ephemPubkeyData];
    [dataOut appendData:r.dataEnc];
    
    return  dataOut;
}


- (void)parser:(NSData *)data{
    
    UInt16 ivLen = 0;
    UInt16 macLen = 0;
    UInt16 ephermPubLen = 0;
    [data getBytes:&ivLen  range:NSMakeRange(2, 2)];
    [data getBytes:&macLen  range:NSMakeRange(4, 2)];
    [data getBytes:&ephermPubLen  range:NSMakeRange(6, 2)];
    
    ivLen = CFSwapInt16HostToLittle(ivLen);
    macLen = CFSwapInt16HostToLittle(macLen);
    ephermPubLen = CFSwapInt16HostToLittle(ephermPubLen);
    
    size_t idx = 8;
    self.iv = [data subdataWithRange:NSMakeRange(idx, ivLen)];
    idx += ivLen;
    self.mac = [data subdataWithRange:NSMakeRange(idx, macLen)];
    idx += macLen;
    self.ephemPubkeyData = [data subdataWithRange:NSMakeRange(idx, ephermPubLen)];
    idx += ephermPubLen;
    self.dataEnc = [data subdataWithRange:NSMakeRange(idx, data.length  - idx)];
    
     
}

 
@end
 
/// 只取 0-31
int sha512(
  unsigned char *output64,
                  const unsigned char *x32,int sizeOfInput){
    
    char result[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(x32, sizeOfInput, result);
    memcpy(output64, result, CC_SHA512_DIGEST_LENGTH);
    return 1;
}

static int my_ecdh_hash_function(
  unsigned char *output,
  const unsigned char *x32,
  const unsigned char *y32,
  void *data){
    return sha512(output,x32,32);
}




@interface LTEccTool ()
@property (nonatomic, assign)secp256k1_context *ctx;
@end

@implementation LTEccTool
+(instancetype) shared{
    static LTEccTool *tool = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        tool = [LTEccTool new];
    });
    
    return tool;
}



- (instancetype)init{
    self = [super init];
    if (self ) {
        size_t blocksize = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_SIGN);
        unsigned char *p = malloc(blocksize);
        self.ctx = secp256k1_context_preallocated_create(p,SECP256K1_CONTEXT_SIGN);
        const char seed[32] = "312255ff8b9db2d1d43bffbe44664238";
        arc4random_buf(seed, 32);
        int r = secp256k1_context_randomize(self.ctx,seed);
        
    }
    
    return self;;
}

 
- (NSDictionary *)genKeyPair:(NSString *)privateKey{
    NSData *dataPrivate = nil;
    void* pPrivate = NULL;
    unsigned char _keysNew[32];
    if (privateKey) {
        dataPrivate = [self base64ToData:privateKey];
        pPrivate = (void *) dataPrivate.bytes;
        if(dataPrivate.length != 32 || !secp256k1_ec_seckey_verify(self.ctx, dataPrivate.bytes)){
            fprintf(stderr, "seckey lenth must be 32 byte\n");
            return nil;
        }
    }
    else{
        
        pPrivate = _keysNew;
        [self genSecKey:pPrivate];
    }
    
    
    
    secp256k1_pubkey pubkey;
    int r =secp256k1_ec_pubkey_create(self.ctx, &pubkey,pPrivate);
    if ( r == 0) {
        return @{@"err":@"err"};
    }
    
    char pPubOut65[65];
    size_t pubLen = 65;
    secp256k1_ec_pubkey_serialize(self.ctx, pPubOut65, &pubLen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    
    NSString *strPub = [self bytesToBase64:pPubOut65 lenOfByte:65];
    
    NSMutableDictionary *dicOut = [NSMutableDictionary new];
    if (strPub) {
        [dicOut setObject:strPub forKey:@"pubKey"];
    }
    
    NSString *strPri = [self bytesToBase64:pPrivate lenOfByte:32];
    if (strPri) {
        [dicOut setObject:strPri forKey:@"priKey"];
    }
    return dicOut;
}

- (void)genSecKey:(unsigned char *)secKey32{
    char tmp[64] ;
    const char *seed = "39583afc3b7af94b355be1a78f41780a";
    memcpy(tmp, seed, strlen(seed));
    do {
        do {
            arc4random_buf(tmp + 32, 32);
            CCHmac(kCCHmacAlgSHA256, tmp, 64, tmp + 32, 32, secKey32);
        } while (0);
    } while (!secp256k1_ec_seckey_verify(self.ctx , secKey32));
}
 
- (NSData *)base64ToData:(NSString *)strBase64{
    return [LTEccTool base64DeCode:strBase64];
}


- (NSString *)bytesToBase64:(void *)byte lenOfByte:(size_t )len {
    NSData *data = [[NSData alloc] initWithBytes:byte length:len];
    NSData *data2 = [data base64EncodedDataWithOptions:0];
    return [[NSString alloc] initWithData:data2 encoding:NSUTF8StringEncoding];
}

#pragma mark - encrypt

- (ECCEncResult *) _ecc_encrypt:(NSData *) dataPlain0 pubkey:(NSString *)pubkeystring{
    if (!pubkeystring) {
        return nil;
    }
    
    secp256k1_pubkey pubkey ;
    NSData *dataPub = [LTEccTool base64DeCode:pubkeystring];
    
    int r = secp256k1_ec_pubkey_parse(self.ctx, &pubkey, dataPub.bytes, dataPub.length);
    if (r == 0 ) {
        
        fprintf(stderr, "pubkey is not valid");
        return nil;
    }
    
    
    unsigned char randKey[32];
    [self genSecKey:randKey];
    
    secp256k1_pubkey randomPub;
    r = secp256k1_ec_pubkey_create(self.ctx, &randomPub, randKey);
    if (r == 0 ) {
        fprintf(stderr, "pubkey create fail");
        return nil;
    }
    unsigned char outHash[64];
    r = secp256k1_ecdh(self.ctx, outHash, &pubkey, randKey, my_ecdh_hash_function, NULL);
    /// 不需要了,重置randkey
    [self genSecKey:randKey];
    if (r == 0) {
        fprintf(stderr, "pubkey is not falid");
        return nil;
    }
    
    char iv[kCCBlockSizeAES128] ;
    arc4random_buf(iv , kCCBlockSizeAES128);
    NSData *dataPlain = dataPlain0; // [strPlainTxt dataUsingEncoding:NSUTF8StringEncoding];
    
    
    size_t dataOutAvailable = dataPlain.length + kCCBlockSizeAES128;
    void *dataOut  = malloc(dataOutAvailable);
    size_t outSize ;
    
    CCCrypt(kCCEncrypt,
            kCCAlgorithmAES,
            kCCOptionPKCS7Padding,      /* kCCOptionPKCS7Padding, etc. */
            outHash,
            kCCKeySizeAES256,
            iv,
            dataPlain.bytes,
            dataPlain.length,
            dataOut,
            dataOutAvailable,
            &outSize);
    
    
    NSData *dateEnc = [[NSData alloc] initWithBytes:dataOut length:outSize];
    
    ECCEncResult *result = [ECCEncResult new];
    result.dataEnc = dateEnc;
    result.iv = [[NSData alloc] initWithBytes:iv  length:kCCBlockSizeAES128];
    
    unsigned char outPub[65];
    size_t len=65;
    secp256k1_ec_pubkey_serialize(self.ctx, outPub, &len,&randomPub, SECP256K1_EC_UNCOMPRESSED);
    result.ephemPubkeyData = [[NSData alloc] initWithBytes:outPub  length:len];
    
    
    NSMutableData *dataForMac = [[NSMutableData alloc] initWithCapacity:result.dataEnc.length  + result.iv.length + result.ephemPubkeyData.length];
    [dataForMac appendData:result.iv];
    [dataForMac appendData:result.ephemPubkeyData];
    [dataForMac appendData:result.dataEnc];
    
     
    char macOut[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256,outHash+32,32,dataForMac.bytes,dataForMac.length,macOut);
    result.mac = [[NSData alloc] initWithBytes:macOut length:CC_SHA256_DIGEST_LENGTH];
    free(dataOut);
    
    
    return  result;
   
}

 
- (NSData *) ecc_encrypt:(NSData *)dataOrigin pubkey:(NSString *)pubkeystring{
    
    NSData *dataCompress = [dataOrigin gzipDeflate];
    ECCEncResult *r = [self _ecc_encrypt:dataCompress pubkey:pubkeystring];
    return [r toResultData];

}

- (NSData *)_ecc_decrypt:(NSData *)dataCipher private:(NSString *)prikey{
    ECCEncResult *r = [ECCEncResult new];
    [r parser:dataCipher];
    
    
    
    NSData *dataPrikey = [LTEccTool base64DeCode:prikey];
    const unsigned char *pPrivateKey = dataPrikey.bytes;
    if (!secp256k1_ec_seckey_verify(self.ctx, pPrivateKey)) {
        return  nil;
    }
    
    
    secp256k1_pubkey ephemPubKey ;
    int r0 = secp256k1_ec_pubkey_parse(self.ctx, &ephemPubKey, r.ephemPubkeyData.bytes, r.ephemPubkeyData.length);
    if (!r0) {
        fprintf(stderr, "no valid pubkey");
        return nil;
    }
    
    unsigned char outHash[64];
    
    r0 = secp256k1_ecdh(self.ctx, outHash, &ephemPubKey, pPrivateKey, my_ecdh_hash_function, NULL);
    if (r0 == 0) {
        fprintf(stderr, "fail to ecdh");
        return nil;
    }
    
    NSMutableData *dataForMac = [[NSMutableData alloc] initWithCapacity:r.ephemPubkeyData.length + r.iv.length + r.dataEnc.length ];
    [dataForMac appendData:r.iv];
    [dataForMac appendData:r.ephemPubkeyData];
    [dataForMac appendData:r.dataEnc];
    
    
    char macOut[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256,outHash+32,32,dataForMac.bytes,dataForMac.length,macOut);
    NSData *dataMac = [[NSData alloc] initWithBytes:macOut length:CC_SHA256_DIGEST_LENGTH];
    
    
    if(![dataMac isEqualToData:r.mac]){
        fprintf(stderr, "mac not fit\n");
        return nil;
    }
    
    
    /// 开始解密
    size_t dataOutAvailable = r.dataEnc.length + kCCBlockSizeAES128;
    void *dataOut  = malloc(dataOutAvailable);
    size_t outSize ;
    
    CCCrypt(kCCDecrypt,
            kCCAlgorithmAES,
            kCCOptionPKCS7Padding,      /* kCCOptionPKCS7Padding, etc. */
            outHash,
            kCCKeySizeAES256,
            r.iv.bytes,
            r.dataEnc.bytes,
            r.dataEnc.length,
            dataOut,
            dataOutAvailable,
            &outSize);
    
    return [[NSData alloc] initWithBytes:dataOut length:outSize];
 
}


- (NSData *)ecc_decrypt:(NSData *)dataCipher private:(NSString *)prikey{
    NSData *data = [self _ecc_decrypt:dataCipher private:prikey];
    NSData *data2 = [data gzipInflate];
    return  data2;
}


+ (NSData *)base64DeCode:(NSString *)strBase64{
    
    if ( strBase64.length > 0 ) {
        NSData *dataOrigin = [strBase64 dataUsingEncoding:NSUTF8StringEncoding];
        NSMutableData *dataFix = [dataOrigin mutableCopy];
        [dataFix appendBytes:"=====" length:3];
        unsigned int len  = strBase64.length + 10;
        unsigned char *pDes = malloc(len);
        len =  base64Decode(pDes, dataFix.bytes);
        NSData *data = [NSData dataWithBytes:pDes length:len];
        free(pDes);
        return data;
    }
    else {
        return nil;
    }
   
    
}


 


OS_CONST static NSString *seckeyforkeychain = @"y1NsDrXnvQfx1DxyebUALOAjpGuUojANwWbpO4y/x90=";
OS_CONST static NSString *pubkeyforkeychain = @"BLLLgvLL7eoER5gPJ6eFhj4T3GPzSMOlLxxlJ5leG75RcQr05uaxqwzIwl7h2cdxnGW0Kehwe/cxtcGTrc8n5TA=";


- (NSString *)getPublicKeyInKeychain{
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
            (id)kSecClassGenericPassword,(id)kSecClass,
            @"vitock.ecc.seckey.seckeys", (id)kSecAttrService,
            @"e46c6231b528cd74e81570e0409eac2a", (id)kSecAttrAccount,
            (id)kSecAttrAccessibleAfterFirstUnlock,(id)kSecAttrAccessible,
            nil];
  
    [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
    [query setObject:(id)kSecMatchLimitOne forKey:(id)kSecMatchLimit];
    
    NSString *strPri = nil;
    CFDataRef keyData = NULL;
    if (SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&keyData) == noErr) {
        NSString *strB64 = [[NSString alloc] initWithData:(__bridge NSData * _Nonnull)(keyData) encoding:NSUTF8StringEncoding];
        
        NSData *datBase64 = [self base64ToData:strB64];
        NSData *datKey = [self ecc_decrypt:datBase64 private:seckeyforkeychain];
        strPri = [self bytesToBase64:datKey.bytes lenOfByte:datKey.length];
        
        
        
    }
    if (keyData)
        CFRelease(keyData);
    return strPri;
    
}


- (NSString *)getSecKeyInKeychain{
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
            (id)kSecClassGenericPassword,(id)kSecClass,
            @"vitock.ecc.seckey.seckeys", (id)kSecAttrService,
            @"bd454dc28bdd8ffda5c775185ccc9814", (id)kSecAttrAccount,
            (id)kSecAttrAccessibleAfterFirstUnlock,(id)kSecAttrAccessible,
            nil];
  
    [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
    [query setObject:(id)kSecMatchLimitOne forKey:(id)kSecMatchLimit];
    
    NSString *strPri = nil;
    CFDataRef keyData = NULL;
    if (SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&keyData) == noErr) {
        
        NSString *strB64 = [[NSString alloc] initWithData:(__bridge NSData * _Nonnull)(keyData) encoding:NSUTF8StringEncoding];
        
        NSData *datBase64 = [self base64ToData:strB64];
        NSData *datKey = [self ecc_decrypt:datBase64 private:seckeyforkeychain];
        strPri = [self bytesToBase64:(void * )datKey.bytes lenOfByte:datKey.length];
    }
    if (keyData)
        CFRelease(keyData);
    return strPri;
    
}

- (void)saveKeyToKeyChain:(NSString *)secKey pubKey:(NSString *)pubKey{
    
    if (secKey) {
        NSData *dataSec = [self base64ToData:secKey];
        NSData *datSecEnc =[self ecc_encrypt:dataSec pubkey:pubkeyforkeychain];
        
        NSString *SaveValue = [self bytesToBase64:(void * )datSecEnc.bytes lenOfByte:datSecEnc.length];
         
        NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                (id)kSecClassGenericPassword,(id)kSecClass,
                @"vitock.ecc.seckey.seckeys", (id)kSecAttrService,
                @"bd454dc28bdd8ffda5c775185ccc9814", (id)kSecAttrAccount,
                (id)kSecAttrAccessibleAfterFirstUnlock,(id)kSecAttrAccessible,
                nil];
      
        [query setObject:SaveValue forKey:(id)kSecValueData];
        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
        status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
        
        if(status != errSecSuccess){
            MyLogFunc(@"save key to key chain fail");
        }
    }
    
    if (pubKey.length ) {
        NSData *dataPub = [self base64ToData:pubKey];
        NSData *datPubEnc =[self ecc_encrypt:dataPub pubkey:pubkeyforkeychain];
        NSString *strSecSave = [self bytesToBase64:(void * )datPubEnc.bytes lenOfByte:datPubEnc.length];
        
        NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                (id)kSecClassGenericPassword,(id)kSecClass,
                @"vitock.ecc.seckey.seckeys", (id)kSecAttrService,
                @"e46c6231b528cd74e81570e0409eac2a", (id)kSecAttrAccount,
                (id)kSecAttrAccessibleAfterFirstUnlock,(id)kSecAttrAccessible,
                nil];
      
        [query setObject:strSecSave forKey:(id)kSecValueData];
        SecItemDelete((__bridge CFDictionaryRef)query);
        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
        
        if(status != errSecSuccess){
            MyLogFunc(@"save key to key chain fail");
        }
    }
     
}
 
@end

//
//XPC_CONSTRUCTOR static void test(){
//
//    NSDictionary *dicKeyPair = [[LTEccTool shared] genKeyPair:nil];
//
//    NSString *str =  [[LTEccTool shared] getSecKeyInKeychain];
//    NSString *str2 =  [[LTEccTool shared] getPublicKeyInKeychain];
//
//    MyLogFunc(@"%@\n%@",str,str2);
//
//}


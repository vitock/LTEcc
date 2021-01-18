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
#import "SSKeychain.h"
#include <zlib.h>
#define kGzBlockSize (1<<14)

@interface ECCEncResult:NSObject
@property (nonatomic, strong)NSData *ephemPubkeyData;
@property (nonatomic, strong)NSData *iv;
@property (nonatomic, strong)NSData *dataEnc;
@property (nonatomic, strong)NSData *mac;
/// 0 内容经过gzip 1 内容没有经过gzip 需要程序提前自己处理
@property (nonatomic, assign)UInt16 type;


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
    UInt16 Zero = self.type;
    
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
    
    UInt16 type = 0;
    UInt16 ivLen = 0;
    UInt16 macLen = 0;
    UInt16 ephermPubLen = 0;
    
    [data getBytes:&type  range:NSMakeRange(0, 2)];
    [data getBytes:&ivLen  range:NSMakeRange(2, 2)];
    [data getBytes:&macLen  range:NSMakeRange(4, 2)];
    [data getBytes:&ephermPubLen  range:NSMakeRange(6, 2)];
    
    type = CFSwapInt16HostToLittle(type);
    
    ivLen = CFSwapInt16HostToLittle(ivLen);
    macLen = CFSwapInt16HostToLittle(macLen);
    ephermPubLen = CFSwapInt16HostToLittle(ephermPubLen);
    
    self.type = type;
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
            PrintErr( "seckey lenth must be 32 byte\n");
            
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
        
        PrintErr( "pubkey is not valid");
        return nil;
    }
    
    
    unsigned char randKey[32];
    [self genSecKey:randKey];
    
    secp256k1_pubkey randomPub;
    r = secp256k1_ec_pubkey_create(self.ctx, &randomPub, randKey);
    if (r == 0 ) {
        PrintErr( "pubkey create fail");
        return nil;
    }
    unsigned char outHash[64];
    r = secp256k1_ecdh(self.ctx, outHash, &pubkey, randKey, my_ecdh_hash_function, NULL);
    /// 不需要了,重置randkey
    [self genSecKey:randKey];
    if (r == 0) {
        PrintErr( "pubkey is not falid");
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

- (NSData *)_ecc_decrypt:(NSData *)dataCipher private:(NSString *)prikey type:(UInt16 *) ptype{
    ECCEncResult *r = [ECCEncResult new];
    [r parser:dataCipher];
    if(ptype){
        *ptype = r.type;
    }
    
    
    
    NSData *dataPrikey = [LTEccTool base64DeCode:prikey];
    const unsigned char *pPrivateKey = dataPrikey.bytes;
    if (!secp256k1_ec_seckey_verify(self.ctx, pPrivateKey)) {
        return  nil;
    }
    
    
    secp256k1_pubkey ephemPubKey ;
    int r0 = secp256k1_ec_pubkey_parse(self.ctx, &ephemPubKey, r.ephemPubkeyData.bytes, r.ephemPubkeyData.length);
    if (!r0) {
        PrintErr( "no valid pubkey");
        return nil;
    }
    
    unsigned char outHash[64];
    
    r0 = secp256k1_ecdh(self.ctx, outHash, &ephemPubKey, pPrivateKey, my_ecdh_hash_function, NULL);
    if (r0 == 0) {
        PrintErr( "fail to ecdh");
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
        MyLogFunc(@"\ncaculted: %@\nmacOrigin: %@",[self bytesToBase64:dataMac.bytes lenOfByte:dataMac.length],[self bytesToBase64:r.mac.bytes lenOfByte:r.mac.length]);
        
        
        PrintErr( "mac not fit\n");
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
    UInt16 type = 0;
    NSData *data = [self _ecc_decrypt:dataCipher private:prikey type:&type];
    if (type == 0) {
        NSData *data2 = [data gzipInflate];
        return  data2;
    }
    return data;
    
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
    NSString *strvalue =  [SSKeychain passwordForService:@"vitock.ecc.publickey" account:@"e46c6231b528cd74e81570e0409eac2a"];
    if (strvalue) {
        NSData *d0 = [self base64ToData:strvalue];
        NSData *data1 = [self ecc_decrypt:d0 private:seckeyforkeychain];
        
        return [[NSString alloc] initWithData:data1 encoding:NSUTF8StringEncoding];
    }
    return nil;
    
    
}


- (NSString *)getSecKeyInKeychain{
    NSString *strvalue = [SSKeychain passwordForService:@"vitock.ecc.privatekey" account:@"bd454dc28bdd8ffda5c775185ccc9814"];
    if (strvalue) {
        NSData *d0 = [self base64ToData:strvalue];
        NSData *data1 = [self ecc_decrypt:d0 private:seckeyforkeychain];
        return [[NSString alloc] initWithData:data1 encoding:NSUTF8StringEncoding];
    }
    return nil;
    
    
}

- (void)saveKeyToKeyChain:(NSString *)secKey pubKey:(NSString *)pubKey{
    NSData *dsec = [self ecc_encrypt:[secKey dataUsingEncoding:NSUTF8StringEncoding] pubkey:pubkeyforkeychain];
    NSData *dpub = [self ecc_encrypt:[pubKey dataUsingEncoding:NSUTF8StringEncoding] pubkey:pubkeyforkeychain];
    
    NSString *strSec = [self bytesToBase64:dsec.bytes lenOfByte:dsec.length];
    NSString *strPub = [self bytesToBase64:dpub.bytes lenOfByte:dpub.length];
    dsec = nil;
    dpub = nil;
    
    [SSKeychain setPassword:strSec forService:@"vitock.ecc.privatekey" account:@"bd454dc28bdd8ffda5c775185ccc9814"];
    
    [SSKeychain setPassword:strPub forService:@"vitock.ecc.publickey" account:@"e46c6231b528cd74e81570e0409eac2a"];
     
}

- (NSString *)dealOutPath:(NSString *)outpath inpath:(NSString *)inpath isEncrypt:(BOOL)enc{
    BOOL isDirectory = NO;
    BOOL isExesit = [[NSFileManager defaultManager] fileExistsAtPath:outpath isDirectory:&isDirectory];
    
    if (isExesit && isDirectory) {
        NSString *strName = [inpath lastPathComponent];
        if (enc) {
            strName = [strName stringByAppendingPathExtension:@"ec"];
        }
        else{
            if ([inpath hasSuffix:@".ec"]) {
                strName =  [strName stringByDeletingPathExtension];
            }
        }
        outpath = [outpath stringByAppendingPathComponent:strName];
        return [self dealOutPath:outpath inpath:inpath isEncrypt:enc];
    }
    else if(isExesit){
        NSString *path2 = [outpath stringByDeletingLastPathComponent];
        NSString *strFileName =  [outpath  lastPathComponent];
        NSString *str2Extentiton = [outpath pathExtension];
        NSMutableArray *arrNames = [[strFileName componentsSeparatedByString:@"."] mutableCopy];
        if (arrNames.count) {
            strFileName  = arrNames[0];
            [arrNames removeObjectAtIndex:0];
            str2Extentiton = [arrNames componentsJoinedByString:@"."];
        }
        
        int i = 2;
        while (isExesit) {
            NSString *strName2 = [NSString stringWithFormat:@"%@_%d",strFileName,i ++];
            NSString *strNewPath =  [[path2 stringByAppendingPathComponent:strName2] stringByAppendingPathExtension:str2Extentiton];
            isExesit = [[NSFileManager defaultManager] fileExistsAtPath:strNewPath isDirectory:&isDirectory];
            
            if (!isExesit) {
                return strNewPath;
            }
            
        }
        
    }
    
    return outpath;
}

- (void)ecc_decryptFile:(NSString *)inFilePath outPath:(NSString *)outpath secKey:(NSString *)seckey gzip:(BOOL) gzip{
    inFilePath =[self dealPath:inFilePath];
    
    if (!outpath) {
        if (inFilePath.length > 3 &&  [[inFilePath pathExtension] isEqualToString:@"ec"]) {
            outpath = [inFilePath stringByDeletingPathExtension];
        }
        else{
            outpath = [inFilePath stringByAppendingPathExtension:@"dec"];
        }
    }
    outpath =[self dealPath:outpath];
    
    
    outpath = [self dealOutPath:outpath inpath:inFilePath isEncrypt:NO];
    
    NSInputStream *streamIn = [[NSInputStream alloc] initWithFileAtPath:inFilePath];
    [streamIn open];
    
    const size_t BufferSize = kCCBlockSizeAES128 << 10 ;
    uint8_t *buffer = malloc(BufferSize);
    size_t readLen = 0;
    readLen = [streamIn read:buffer maxLength:8];
    
    UInt16 type = 0;
    NSData *dataIv = nil;
    NSData *dataEphermPubKey = nil;
    NSData *dataMac = nil;
    if(readLen == 8){
        
        UInt16 ivLen = 0;
        UInt16 macLen = 0;
        UInt16 ephermPubLen = 0;
        NSData *data = [[NSData alloc] initWithBytesNoCopy:buffer length:readLen deallocator:NULL];
        
        [data getBytes:&type  range:NSMakeRange(0, 2)];
        [data getBytes:&ivLen  range:NSMakeRange(2, 2)];
        [data getBytes:&macLen  range:NSMakeRange(4, 2)];
        [data getBytes:&ephermPubLen  range:NSMakeRange(6, 2)];
        type = CFSwapInt16HostToLittle(type);
        ivLen = CFSwapInt16HostToLittle(ivLen);
        macLen = CFSwapInt16HostToLittle(macLen);
        ephermPubLen = CFSwapInt16HostToLittle(ephermPubLen);
        
        NSUInteger len1 = ivLen + macLen + ephermPubLen;
        NSUInteger len2 = [streamIn read:buffer maxLength:len1];
        if (len1 != len2) {
            PrintErr( "file format is not suitable,no iv ,mac or ephermPubkey");
            return;;
        }
        
        dataIv = [[NSData alloc] initWithBytes:buffer length:ivLen];
        dataMac = [[NSData alloc] initWithBytes:buffer + ivLen length:macLen];
        dataEphermPubKey = [[NSData alloc] initWithBytes:buffer + ivLen + macLen length:ephermPubLen];
        
    }
    else{
        PrintErr("file format is not suitable");
        return;
    }
    
    
    NSString *tmpFile = nil;
    NSOutputStream *streamOut = nil;
    NSString *realOutPath = outpath;
    if (type == 0) {
        if (gzip) {
            
            tmpFile = [NSString stringWithFormat:@"%@.%x.gz",outpath,arc4random()];
            outpath = tmpFile;
        }
        else{
            if (![outpath hasSuffix:@".gz"]) {
                outpath = [outpath stringByAppendingPathExtension:@"gz"];
                realOutPath = outpath;
            }
        }
        
    }
    
    streamOut = [NSOutputStream outputStreamToFileAtPath:outpath  append:NO];
    [streamOut open];
    
    UInt8 dhHash[64];
    {
        NSData *dataPrikey = [self base64ToData:seckey];
        
        const unsigned char *pPrivateKey = dataPrikey.bytes;
        if (!secp256k1_ec_seckey_verify(self.ctx, pPrivateKey)) {
            PrintErr( "seckey is not availble");
            return ;
        }
        
        
        secp256k1_pubkey ephemPubKey ;
        int r0 = secp256k1_ec_pubkey_parse(self.ctx, &ephemPubKey, dataEphermPubKey.bytes, dataEphermPubKey.length);
        if (!r0) {
            PrintErr( "no valid pubkey");
        }
        
        
        
        int r = secp256k1_ecdh(self.ctx, dhHash, &ephemPubKey, pPrivateKey, my_ecdh_hash_function, NULL);
        /// 不需要了,重置randkey
        dataPrikey = nil;
        if (r == 0) {
            PrintErr( "pubkey is not falid");
            return ;
        }
    }
     
    
    
    CCCryptorRef cryptor;
    CCCryptorCreate(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, dhHash, kCCKeySizeAES256, dataIv.bytes, &cryptor);
    
    
    // iv empherpubkey dataenc
    CCHmacContext ctx;
    CCHmacInit(&ctx, kCCHmacAlgSHA256 , dhHash+32, 32);
    CCHmacUpdate(&ctx,dataIv.bytes,dataIv.length);
    CCHmacUpdate(&ctx,dataEphermPubKey.bytes,dataEphermPubKey.length);
    
    readLen = [streamIn read:buffer maxLength:BufferSize];
    
    size_t dataOutAvailable = BufferSize + kCCBlockSizeAES128;
    UInt8 *dataOut = malloc(dataOutAvailable);
    size_t dataOutLen = 0;
    uLong unzipSize = 0;
   
    while (readLen > 0 ) {
        CCHmacUpdate(&ctx, buffer, readLen);
        CCCryptorUpdate(cryptor, buffer, readLen, dataOut, dataOutAvailable, &dataOutLen);
        if (dataOutLen > 0 ) {
            [streamOut write:dataOut maxLength:dataOutLen];
        }
        readLen = [streamIn read:buffer maxLength:BufferSize];
    }
    
    CCCryptorFinal(cryptor, dataOut, dataOutAvailable, &dataOutLen);
    if (dataOutLen > 0) {
        [streamOut write:dataOut maxLength:dataOutLen];
    }
    [streamIn close];
    [streamOut close];
    
    CCCryptorRelease(cryptor);
    UInt8 macOut[CC_SHA256_DIGEST_LENGTH];
    CCHmacFinal(&ctx, macOut);
    if (!memcpy(macOut, dataMac.bytes, CC_SHA256_DIGEST_LENGTH)) {
        PrintErr( "mac not fit ");
        goto  END;
    }
    
   
    printf("\noutput file:%s\n",realOutPath.UTF8String);
    
END:
    free(dataOut);
    free(buffer);
    
    
    if (tmpFile && gzip) {
        NSString *strCmd = [NSString stringWithFormat:@"gzip -dc %@ > %@",tmpFile,realOutPath];
        system(strCmd.UTF8String);
        [[NSFileManager defaultManager] removeItemAtPath:tmpFile error:nil];
    }
}

- (void)gunzipFile:(NSString *)inFilePath outpath:(NSString *)outpath{
    z_stream strm;
    strm.total_out = 0;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    if (inflateInit2(&strm, (15+32)) != Z_OK) {
        return;;
    }
    
    inFilePath =[self dealPath:inFilePath];
    outpath =[self dealPath:outpath];
    
    NSInputStream *inStream = [[NSInputStream alloc] initWithFileAtPath:inFilePath];
    NSOutputStream *outStream = [NSOutputStream outputStreamToFileAtPath:outpath append:NO];
    [inStream open];
    [outStream open];
     
    // 16K chunks for expansion
    const int buffersize = (1 << 14) ;
    UInt8 buffer[buffersize];
    
    const int bufferOutSize = buffersize * 5;
    UInt8 bufferOut[bufferOutSize];
    NSInteger readLen = [inStream read:buffer maxLength:buffersize];
     
    BOOL done = NO;
    uLong unzipSize = 0;
    while (!done  && readLen > 0) {
        strm.next_in=(Bytef *)buffer;
        strm.avail_in = (uInt)readLen;
         
        strm.next_out = bufferOut;
        strm.avail_out = bufferOutSize;
         
        int status = inflate (&strm, Z_SYNC_FLUSH);
        
        uLong dataOutLen = strm.total_out -  unzipSize;
       ;
        
        if (status == Z_STREAM_END) {
            [outStream write:bufferOut maxLength:dataOutLen];
            done = YES;
            break;;
        }
        else if (status != Z_OK) {
            dataOutLen = strm.total_out -  unzipSize;
            [outStream write:bufferOut maxLength:dataOutLen];
            break;;
        }
        [outStream write:bufferOut maxLength:dataOutLen];
        readLen = [inStream read:buffer maxLength:buffersize];
        
        unzipSize = strm.total_out;
    }
    
    inflateEnd(&strm);
     
    
    [inStream close];
    [outStream close];
    
}

- (void)ecc_encryptFile:(NSString *)inFilePath outPath:(NSString *)outpath pubkey:(NSString *)pubkeystring gzip:(BOOL) gzip{
    inFilePath =[self dealPath:inFilePath];
    NSString *strOriInputPath = inFilePath;
    NSString *strziptmp = nil;
    if (gzip) {
        strziptmp = [inFilePath stringByDeletingLastPathComponent];
        strziptmp = [NSString stringWithFormat:@"%@/%x.gz",strziptmp, (1 << 10) +  arc4random()];
        NSString *strcmp= [NSString stringWithFormat:@"gzip -c %@ >  %@" ,inFilePath,strziptmp];
        system([strcmp UTF8String]);
        inFilePath = strziptmp;
        
    }
    
    
    if (!outpath) {
        outpath = [strOriInputPath stringByAppendingPathExtension:@"ec"];
    }
    
    outpath =[self dealPath:outpath];
    outpath = [self dealOutPath:outpath inpath:strOriInputPath isEncrypt:YES];
    
    NSInputStream *streamIn = [[NSInputStream alloc] initWithFileAtPath:inFilePath];
    NSOutputStream *streamOut = [NSOutputStream outputStreamToFileAtPath:outpath  append:NO];
    [streamOut open];
    [streamIn open];
     
    UInt8 dhHash[64];
    const  size_t publen=65;
    
    UInt8 outPub[publen];
    {
        secp256k1_pubkey pubkey ;
        NSData *dataPub = [LTEccTool base64DeCode:pubkeystring];
        
        int r = secp256k1_ec_pubkey_parse(self.ctx, &pubkey, dataPub.bytes, dataPub.length);
        if (r == 0 ) {
            PrintErr("pubkey is not valid");
            return ;
        }
         
        unsigned char randKey[32];
        [self genSecKey:randKey];
        
        secp256k1_pubkey randomPub;
        r = secp256k1_ec_pubkey_create(self.ctx, &randomPub, randKey);
        if (r == 0 ) {
            PrintErr("create pubkey fail");
            return ;
        }
        
        r = secp256k1_ecdh(self.ctx, dhHash, &pubkey, randKey, my_ecdh_hash_function, NULL);
        /// 不需要了,重置randkey
        [self genSecKey:randKey];
        if (r == 0) {
            PrintErr("pubkey is not falid");
            return ;
        }
        size_t len = publen;
        secp256k1_ec_pubkey_serialize(self.ctx, outPub, &len,&randomPub, SECP256K1_EC_UNCOMPRESSED);
         
    }
    
    
    int macPostion = 0;
    UInt8 macBuffer[CC_SHA256_DIGEST_LENGTH];
    memset(macBuffer, 0, CC_SHA256_DIGEST_LENGTH);
    uint8_t iv[kCCBlockSizeAES128] ;
    arc4random_buf(iv , kCCBlockSizeAES128);
    {
        UInt16 ivLen = kCCBlockSizeAES128;
        UInt16 macLen = CC_SHA256_DIGEST_LENGTH;
        UInt16 ephemPubLen = publen;
        /// 内容没有zip
        UInt16 Zero = gzip ? 0 : 1;
        
        int preLen = ivLen + macLen + ephemPubLen + 8;
        
        ivLen = CFSwapInt16HostToLittle(ivLen);
        macLen = CFSwapInt16HostToLittle(macLen);
        ephemPubLen = CFSwapInt16HostToLittle(ephemPubLen);
        NSMutableData *dataPre = [[NSMutableData alloc] initWithCapacity:preLen ];
        [dataPre appendBytes:&Zero length:2];
        [dataPre appendBytes:&ivLen length:2];
        [dataPre appendBytes:&macLen length:2];
        [dataPre appendBytes:&ephemPubLen length:2];
        
        [streamOut write:dataPre.bytes maxLength:dataPre.length];
        [streamOut write:iv maxLength:ivLen];
        [streamOut write:macBuffer maxLength:macLen];
        [streamOut write:outPub maxLength:ephemPubLen];
        
        macPostion = 8 + ivLen;
    }
    
    
    CCCryptorRef cryptor;
    CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, dhHash, kCCKeySizeAES256, iv, &cryptor);
    
    
    // iv empherpubkey dataenc
    CCHmacContext ctx;
    CCHmacInit(&ctx, kCCHmacAlgSHA256 , dhHash+32, 32);
    CCHmacUpdate(&ctx,iv,kCCBlockSizeAES128);
    CCHmacUpdate(&ctx,outPub,publen);
     
    NSInteger readDateLen = 0;
    const int buffersize = kCCBlockSizeAES128 << 10;
    const int encbuffersize = buffersize + kCCBlockSizeAES128;
    
    UInt8 *buffer = malloc(buffersize);
    UInt8 *bufferEncry = malloc(encbuffersize);
    
    readDateLen = [streamIn read:buffer maxLength:buffersize];
    size_t  encsize = 0;
    while (readDateLen > 0 ){
        CCCryptorUpdate(cryptor, buffer, readDateLen, bufferEncry, encbuffersize, &encsize);
        if (encsize > 0) {
            CCHmacUpdate(&ctx, bufferEncry, encsize);
            [streamOut write:bufferEncry maxLength:encsize];
        }
        readDateLen = [streamIn read:buffer maxLength:buffersize];
    }
    
    CCCryptorFinal(cryptor, bufferEncry, encbuffersize, &encsize);
    CCHmacUpdate(&ctx,bufferEncry,encsize);
    CCHmacFinal(&ctx, macBuffer);
    
    
    if (encsize > 0 ) {
        [streamOut write:bufferEncry maxLength:encsize];
    }
    
    
    CCCryptorRelease(cryptor);
    free(bufferEncry);
    free(buffer);
    arc4random_buf(dhHash, 32);
    memset(&ctx , 0, sizeof(ctx));
    [streamIn close];
    [streamOut close];
    
    /// write mac to file head
    FILE *fileOut = NULL;
    if (outpath.length) {
        fileOut = fopen(outpath.UTF8String, "r+b");
    }
    
    fseek(fileOut, macPostion, SEEK_SET);
    fwrite(macBuffer, CC_SHA256_DIGEST_LENGTH, 1, fileOut);
    fclose(fileOut);
    
    if (strziptmp) {
        
        long long filesize = [[[NSFileManager defaultManager] attributesOfItemAtPath:strziptmp error:nil] fileSize];
        
        NSOutputStream *removeStream = [NSOutputStream outputStreamToFileAtPath:strziptmp append:NO];
        [removeStream open];
        
        const int removeBfs = 1 << 9;
        uint8_t removebuffer[removeBfs];
        arc4random_buf(removebuffer, removeBfs);
        NSInteger l = 0;
        NSInteger r = 0;
        while (l < filesize ) {
            r = [removeStream write:removebuffer maxLength:removeBfs];
            if (r > 0 ) {
                l += r;
            }
            else{
                PrintErr("remove error");
                break;;
            }
        }
        [removeStream  close];
        [[NSFileManager defaultManager] removeItemAtPath:strziptmp error:nil];
    }
    
    
    printf("\noutput file:\n%s\n",outpath.UTF8String);
    
}
- (NSString *)dealPath:(NSString *)path{
    if ([path hasPrefix:@"/"]) {
        return path.stringByStandardizingPath;
    }
    else{
        char cwd[PATH_MAX];
        memset(cwd, 0, PATH_MAX);
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            
        } else {
            perror("getcwd() error");
        }
        NSString *path2 = [[NSString alloc] initWithFormat:@"%s/%@",cwd,path];
        return path2.stringByStandardizingPath;
    }
}
 
@end

#ifdef  DEBUG
XPC_CONSTRUCTOR static void test(){
    
    [[LTEccTool shared] getPublicKeyInKeychain];
    
}
#endif



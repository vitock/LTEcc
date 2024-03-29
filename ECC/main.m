//
//  main.m
//  ECC
//
//  Created by wei li on 2020/12/18.
//


#import <Foundation/Foundation.h>


#import <CommonCrypto/CommonDigest.h>
#import "LTEccTool.h"
#import "randomart.h"
NSData *readStdIn(){
    int c;
    UInt8 *buffer = malloc(10244 * 1024 * 10);
    size_t t = 0;
    while ((c = fgetc (stdin)) != EOF){
        buffer[t] = c;
        t ++;
    }
     
    NSData *data =[[NSData alloc] initWithBytes:buffer length:t];
    free(buffer);
    return data;
}

void printKey(const void *key,int  size){
    
    unsigned char keycpy[size];
    memcpy(keycpy, key , size);
    
    unsigned char digest[32];
    CC_SHA256(keycpy, size, digest);
    printf("\nECC encryption privateKey finggerprint: \n%s\nrandomart:\n",[[LTEccTool shared] bytesToBase64:digest lenOfByte:32].UTF8String);
    printRandomArt(digest, 32,"[Secp251k1]","[SHA 256]");
    
    if (!key) {
        PrintErr("No Key");
        return;
    }
    int ZeroCount= 0;
    int OneCount = 0;
    for (int i = 0 ; i < size; ++ i ) {
        uint8 p = ((uint8 *)key)[i];
        /// 1的个数
        unsigned int c =0 ;
        for (c =0; p; ++c)
        {
            p &= (p -1) ; // 清除最低位的1
        }
        OneCount += c;
        ZeroCount += 8-c;
         
    }
    
    printf("\n0/1 = %d/%d   %f\n\n",ZeroCount,OneCount,OneCount/(float)(OneCount + ZeroCount));
    
//    bit map
//    for (int i = 0 ; i < size; ++ i ) {
//        if ( i % 3 == 0) {
//            printf("\n");
//        }
//
//        uint8 p = ((uint8 *)key)[i];
//        for (int j = 0 ; j < 8; ++ j ) {
//            if(p & (1 << j)){
//                printf("o");
//                OneCount ++;
//
//            }else{
//                printf(".");
//                ZeroCount ++;
//            }
//        }
//    }
    printf("\n");
}

@interface NSMutableDictionary(xxx)

@end
@implementation NSMutableDictionary(xxx)
- (void)safe_setObject:(id)anObject forKey:(NSString *)aKey{
    if ( aKey ) {
        if ( anObject==nil ) {
            [self removeObjectForKey:aKey];
        }
        else {
            /// 同一个
            id anTempObject = anObject;
            [self setObject:anTempObject forKey:aKey];
        }
    }
}


- (NSString *)getString:(id)key{
    if (key ) {
        NSString *v = self[key];
        if ([v isKindOfClass:[NSString class]]) {
            return v;
        }
    }
    return nil;
}

@end

@interface NSMutableArray(xx)

@end

@implementation NSMutableArray(xx)

-(void)safe_addObject:(id)anObject {
    if ( anObject ) {
        [self addObject:anObject];
    }
}

@end

static NSString *defaultValue = @"1";

int main(int argc, const char * argv[]) {
    int i = 0;
    
    NSMutableDictionary *dicArg = [NSMutableDictionary new];
    
    NSString *strPreKey = nil;
    for (int i = 1 ; i < argc ; ++i ) {
        if(argv[i][0] == '-'){
            NSString *strKey = [[NSString alloc] initWithUTF8String:argv[i]+1];
            strPreKey = strKey;
            
            [dicArg setObject:defaultValue forKey:strPreKey];
            continue;
            i += 1;
            if(i < argc && strKey.length){
                NSRange rg = NSMakeRange(0, 1);
                NSString *strValue = [[NSString alloc] initWithUTF8String:argv[i]];
//                dicArg[strKey] = strValue;
                unsigned int len = strKey.length;
                while (rg.location < len) {
                    NSString *key = [strKey substringWithRange:rg];
                    if (rg.location == len - 1) {
                        dicArg[key] = strValue;
                    }
                    else{
                        dicArg[key] = @"1";
                    }
                    rg.location += 1;
                    
                }
            }else{
                dicArg[strKey] = @"1";
            }

        }else {
            NSString *strValue = [[NSString alloc] initWithUTF8String:argv[i]];
            MyLogFunc(@">>>>>....%@ %@",strPreKey,strValue);
            if (strPreKey) {
                id preValue = dicArg[strPreKey];
                if(!preValue){
                    if (strValue && strPreKey) {
                        [dicArg setObject:strValue forKey:strPreKey];
                    }
                }
                else if ([preValue isKindOfClass:[NSMutableArray class]]) {
                    if (strValue) {
                        [(NSMutableArray *)preValue addObject:strValue];
                    }
                }
                else if([preValue isKindOfClass:[NSString class]]){
                    NSMutableArray *arr = [NSMutableArray new];
                    if(defaultValue != preValue){
                        [arr safe_addObject:preValue];
                    }
                    
                    [arr safe_addObject:strValue];
                    [dicArg safe_setObject:arr  forKey:strPreKey];
                }
            }
            
            
            
        }
    }
    
    NSArray *arrkey = dicArg.allKeys;
    for (NSString *key in arrkey) {
        id v = dicArg[key];
        if ([v isKindOfClass:[NSArray class]] && ![key isEqualToString:@"f"]) {
            id v0 = [(NSArray *)v firstObject];
            [dicArg safe_setObject:v0 forKey:key];
        }
    }
    BOOL gzip = ![dicArg[@"z"] isEqualToString:@"0"];
    MyLogFunc(@"input %@",dicArg);

    NSString *strSecKey = dicArg[@"s"];
    if (!strSecKey) {
        strSecKey = dicArg[@"prikey"];
    }
    if (!strSecKey) {
        strSecKey = dicArg[@"secKey"];
    }
    
    NSString *strPubKey = dicArg[@"p"];
    if (!strPubKey) {
        strPubKey = dicArg[@"pubKey"];
    }
    
    const char *cmd = argc > 1 ? argv[1] : "";
//    cmd = "s";
//    argc = 2;
    if (argc >= 2  && 0 == strcmp(cmd, "g")) {
        
        NSString *keyphrase =  dicArg[@"k"];
        if(strSecKey && keyphrase){
            printf("seckey [s] is specified,the key phrass [k] will be ignored");
        }
        else if (keyphrase ) {
            if (keyphrase.length <= 5) {
                int c = [keyphrase intValue];
                if (c <= 1 ) {
                    c = 8;
                }
                keyphrase = [[LTEccTool shared] genKeyPhrase:MAX(c, 6)];
                printf("Passphrase:(PBKDF2,sha256 ,salt:base64-Kj3rk8+cKYG8sAhXO5gkU5nRrBzuhhS7ts953vdhVHE= rounds:123456)\n");
                RedPrint("%s",[keyphrase UTF8String]);
            }
            
            NSData *dataOfPhrase = [keyphrase dataUsingEncoding:NSUTF8StringEncoding];
            if (dataOfPhrase.length < 10) {
                PrintErr("key phrase length is too short (%lu < 10)",(unsigned long)dataOfPhrase.length);
                return 1;
            }
            
        }
        
        NSDictionary *dic = [[LTEccTool shared] genKeyPair:strSecKey keyPhrase:keyphrase];
        NSString *priKey = dic[@"priKey"];
        NSString *pubKey = dic[@"pubKey"];
        NSData *data2 = [LTEccTool  base64DeCode:priKey];
        printKey(data2.bytes,data2.length);
        printf("priKey:%s",[priKey  UTF8String]);
        printf("\npubKey:%s\n",[pubKey  UTF8String]);
        
        
        if ([dicArg[@"S"] isEqualTo:@"1"]) {
            fprintf(stdout, "\033[31;47m this action will overwite key in keychain. continue[y/n] ? \033[0m\n");
            
            int c = getc(stdin);
            if(c == 'y' || c == 'Y'){
                fprintf(stdout, "write keys to keychain");
                [[LTEccTool shared] saveKeyToKeyChain:priKey pubKey:pubKey];
            }
            else{
                fprintf(stdout, "skip\n");
            }
            return 0;
        }
    }
    else if (argc >= 2  && 0 == strcmp(cmd, "s")) {
        NSString *priKey = [[LTEccTool shared] getSecKeyInKeychain];
        NSString *pubKey = [[LTEccTool shared] getPublicKeyInKeychain];
        
        NSData *data2 = [LTEccTool  base64DeCode:priKey];
        if (data2.length) {
            printKey(data2.bytes,data2.length);
            printf("priKey:%s",[priKey  UTF8String]);
            printf("\npubKey:%s\n",[pubKey  UTF8String]);
        }
        else{
            printf("no key found in key chain");
        }
        
        
    }
    
    else if (argc >= 2  && 0 == strcmp(cmd, "e")) {
        if (strPubKey.length == 0) {
            strPubKey = [[LTEccTool shared] getPublicKeyInKeychain];
        }
        
        if (strPubKey.length == 0) {
            PrintErr("need pubkey ,use -p pubkey");
            return 1;
        }
        
        NSString *strmsg = dicArg[@"m"];
        NSData *dataMsg = [strmsg dataUsingEncoding:NSUTF8StringEncoding];
        
        if (!strmsg) {
            
            id inpath0 = dicArg[@"f"];
            
            NSArray *arrPath = nil;
            if ([inpath0 isKindOfClass:[NSString class]]) {
                arrPath = @[inpath0];
            }
            else if([inpath0 isKindOfClass:[NSArray class]]){
                arrPath = inpath0;
            }
            
            if (arrPath.count) {
                for (NSString *inpath in arrPath) {
                    if (inpath.length) {
                        
                        [[LTEccTool shared] ecc_encryptFile:inpath outPath:nil pubkey:strPubKey gzip:gzip];
                        
                    }
                }
                
                return 0;
            }
           
        }
        
        if (!strmsg) {
            dataMsg =  readStdIn();
        }
        NSData *data =  [[LTEccTool shared] ecc_encrypt:dataMsg pubkey:strPubKey];
        fwrite(data.bytes, 1, data.length, stdout);
        
        
    }
    else if (argc >= 2  && 0 == strcmp(cmd, "d")) {
        if (strSecKey.length == 0) {
            strSecKey = [[LTEccTool shared] getSecKeyInKeychain];
        }
        
        if (strSecKey.length == 0) {
            PrintErr("need secKey user -s seckey");
         
            return 1;
        }
        NSString *strmsg = dicArg[@"m"];
        
        
        
        if (!strmsg) {
            id inpath0 = dicArg[@"f"];
            
            NSArray *arrPath = nil;
            if ([inpath0 isKindOfClass:[NSString class]]) {
                arrPath = @[inpath0];
            }
            else if([inpath0 isKindOfClass:[NSArray class]]){
                arrPath = inpath0;
            }
            
            if (arrPath.count) {
                for (NSString *inpath in arrPath) {
                    if (inpath.length) {
                        
                        [[LTEccTool shared] ecc_decryptFile:inpath outPath:nil secKey:strSecKey gzip:gzip];
                        
                    }
                }
                
                return 0;
            }
            
            
            
        }
        
        NSData *dataMsg = nil;
        if (!strmsg) {
            dataMsg =  readStdIn();
        }else {
            /// message base64
            dataMsg =  [LTEccTool base64DeCode:strmsg];
        }
        
        
        
        NSData *dat = [[LTEccTool shared] ecc_decrypt:dataMsg private:strSecKey];
        fwrite(dat.bytes, 1, dat.length, stdout);
        
        
    }
    else if (argc >= 2  && 0 == strcmp(cmd, "r")) {
        
        NSString *strmsg = dicArg[@"m"];
        
        NSData *dataMsg = nil;
        if (!strmsg) {
            dataMsg =  readStdIn();
        }else {
            /// message base64
            dataMsg =  [strmsg dataUsingEncoding:NSUTF8StringEncoding];
        }
        
        NSString *title = dicArg[@"t"];
        NSString *bottom = dicArg[@"b"];
        
        
        printRandomArt(dataMsg.bytes , (int)dataMsg.length, title.UTF8String , bottom.UTF8String);
        
    }
    else {
        NSString *link = @"AAAQACAAQQB5KEiWgHoyx11nzuIpeJJmRCeB0dTfynTZIoR+zq4p8BEsBUD/73rzN4jsWWyP+FsEN5H73UttAIGvbz8yX4WMQq6m17B3PK2rR4Btq0vgJdmc9p6TfwmPK/rdHV/KxQI6pFzzNc3NNCLbOiqcBmwb4aEMhjFDWK955oxzq5+xb+/wtbXbhR/riLpqUWaaqIjGq2Aef5wxmxcvbcd3iqJcg4ppWqAdT+v9UBcxEd8bOBw=";
        
        NSData *data  = [[LTEccTool shared] ecc_decrypt:[LTEccTool base64DeCode:link] private:@"6rCih8Q2j2n8fbcBJh8632rGp5LsPhnktoTE6tBDIyY"];
        link = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        
        
        const NSString *helpfmt = @"ecc %s \n%@\ng [-prikey/secKey/s prikey]  generate keypair [-k  passphrase/count] [-S] saveto key chain\
        \ne  -pubkey/p pubkey -m msg [-f inputfilepath] [-o outpath]\
        \nd  -prikey/s prikey -m base64ciphermsg  binary data from stdin [-f inputfilepath] [-o outpath]\
        \nr  -m msg print random art of msg\
        \ns  show saved key in keychain\n\
        \n-z set 0 if you dont want gzip  ";
        ;
        NSString *help = [NSString stringWithFormat:helpfmt,Version,link];
        
        
        fprintf(stdout,"%s", help.UTF8String);
        fprintf(stdout,"\n\nbuild:%s %s\n",__DATE__,__TIME__);
        
    }
    
 
    fflush(stdout);
    
    
    
    return 0;
}



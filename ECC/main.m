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
    char map[153];
    printf("\nECC encrypttion privateKey finggerprint: \n%s\nrandomart:\n",[[LTEccTool shared] bytesToBase64:digest lenOfByte:32].UTF8String);
    randomArt(digest, 32, map,"[Secp251k1]","[SHA 256]");
    
    if (!key) {
        fprintf(stderr, "\033[31;47m No Key \033[0m");
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

int main(int argc, const char * argv[]) {
    
    
    NSMutableDictionary *dic = [NSMutableDictionary new];
    for (int i = 1 ; i < argc ; ++i ) {
        if(argv[i][0] == '-'){
            NSString *strKey = [[NSString alloc] initWithUTF8String:argv[i]+1];
            i += 1;
            if(i < argc && strKey.length){
                NSString *strValue = [[NSString alloc] initWithUTF8String:argv[i]];
                dic[strKey] = strValue;
            }else{
                dic[strKey] = @"";
            }

        }
    }
    

    NSString *strSecKey = dic[@"s"];
    if (!strSecKey) {
        strSecKey = dic[@"prikey"];
    }
    if (!strSecKey) {
        strSecKey = dic[@"secKey"];
    }
    
    NSString *strPubKey = dic[@"p"];
    if (!strPubKey) {
        strPubKey = dic[@"pubKey"];
    }

    
    if (argc >= 2  && 0 == strcmp(argv[1], "g")) {
        NSDictionary *dic = [[LTEccTool shared] genKeyPair:strSecKey];
        NSString *priKey = dic[@"priKey"];
        NSString *pubKey = dic[@"pubKey"];
        NSData *data2 = [LTEccTool  base64DeCode:priKey];
        printKey(data2.bytes,data2.length); 
        printf("priKey:%s",[priKey  UTF8String]);
        printf("\npubKey:%s\n",[pubKey  UTF8String]);
    }
    
    else if (argc >= 2  && 0 == strcmp(argv[1], "e")) {
        
        if (strPubKey.length == 0) {
            fprintf(stderr, "\033[31;47m need pubkey ,use -p pubkey\033[0m\n");
            return 1;
        }
        NSString *strmsg = dic[@"m"];
        NSData *dataMsg = [strmsg dataUsingEncoding:NSUTF8StringEncoding];
        if (!strmsg) {
            dataMsg =  readStdIn();
        }
        NSData *data =  [[LTEccTool shared] ecc_encrypt:dataMsg pubkey:strPubKey];
        fwrite(data.bytes, 1, data.length, stdout);
        
        
    }
    else if (argc >= 2  && 0 == strcmp(argv[1], "d")) {
        
        if (strSecKey.length == 0) {
            fprintf(stderr, "\033[31;47m need secKey user -s seckey\033[0m");
         
            return 1;
        }
        NSString *strmsg = dic[@"m"];
        
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
    else {
        NSString *help = @"lwEcc \ng [-prikey/secKey/s prikey]  generate keypair\
        \ne  -pubkey/p pubkey -m msg\
        \nd  -prikey/s prikey -m base64ciphermsg or binary data from stdin\n";
        fprintf(stdout,"%s", help.UTF8String);
        fprintf(stdout,"\nbuild:%s %s",__DATE__,__TIME__);
        
    }
    
      
    return 0;
}



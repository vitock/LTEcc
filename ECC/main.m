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
    int i = 0;
    
    NSMutableDictionary *dicArg = [NSMutableDictionary new];
    for (int i = 1 ; i < argc ; ++i ) {
        if(argv[i][0] == '-'){
            NSString *strKey = [[NSString alloc] initWithUTF8String:argv[i]+1];
            i += 1;
            if(i < argc && strKey.length){
                NSString *strValue = [[NSString alloc] initWithUTF8String:argv[i]];
                dicArg[strKey] = strValue;
            }else{
                dicArg[strKey] = @"1";
            }

        }
    }
    

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
     
    if (argc >= 2  && 0 == strcmp(argv[1], "g")) {
        NSDictionary *dic = [[LTEccTool shared] genKeyPair:strSecKey];
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
            return 1;
            
            
        }
        else{
            MyLogFunc(@"bb %@",dicArg);
        }
    }
    else if (argc >= 2  && 0 == strcmp(argv[1], "s")) {
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
    
    else if (argc >= 2  && 0 == strcmp(argv[1], "e")) {
        if (strPubKey.length == 0) {
            strPubKey = [[LTEccTool shared] getPublicKeyInKeychain];
        }
        
        if (strPubKey.length == 0) {
            fprintf(stderr, "\033[31;47m need pubkey ,use -p pubkey\033[0m\n");
            return 1;
        }
        
        NSString *strmsg = dicArg[@"m"];
        NSData *dataMsg = [strmsg dataUsingEncoding:NSUTF8StringEncoding];
        if (!strmsg) {
            dataMsg =  readStdIn();
        }
        NSData *data =  [[LTEccTool shared] ecc_encrypt:dataMsg pubkey:strPubKey];
        fwrite(data.bytes, 1, data.length, stdout);
        
        
    }
    else if (argc >= 2  && 0 == strcmp(argv[1], "d")) {
        if (strSecKey.length == 0) {
            strSecKey = [[LTEccTool shared] getSecKeyInKeychain];
        }
        
        if (strSecKey.length == 0) {
            fprintf(stderr, "\033[31;47m need secKey user -s seckey\033[0m");
         
            return 1;
        }
        NSString *strmsg = dicArg[@"m"];
        
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
    else if (argc >= 2  && 0 == strcmp(argv[1], "r")) {
        
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
        
        
        const NSString *helpfmt = @"lwEcc %s \n%@\ng [-prikey/secKey/s prikey]  generate keypair  [-S] saveto key chain\
        \ne  -pubkey/p pubkey -m msg\
        \nd  -prikey/s prikey -m base64ciphermsg or binary data from stdin\
        \nr  -m msg print random art of msg\
        \ns  show saved key in keychain";
        
        ;
        NSString *help = [NSString stringWithFormat:helpfmt,Version,link];
        
        fprintf(stdout,"%s", help.UTF8String);
        fprintf(stdout,"\n\nbuild:%s %s\n",__DATE__,__TIME__);
        
    }
    fflush(stdout);
      
    return 0;
}



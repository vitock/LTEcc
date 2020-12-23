//
//  main.m
//  ECC
//
//  Created by wei li on 2020/12/18.
//

#import <Foundation/Foundation.h>


#import <CommonCrypto/CommonDigest.h>
#import "LTEccTool.h"
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
    if (!key) {
        fprintf(stderr, "\033[31;47m No Key \033[0m");
        return;
    }
    int ZeroCount= 0;
    int OneCount = 0;
    for (int i = 0 ; i < size; ++ i ) {
        if ( i % 3 == 0) {
            printf("\n");
        }
        
        uint8 p = ((uint8 *)key)[i];
        for (int j = 0 ; j < 8; ++ j ) {
            if(p & (1 << j)){
                printf("o");
                OneCount ++;
                
            }else{
                printf(".");
                ZeroCount ++;
            }
        }
    }
    printf("\n0:%d  1:%d\n",ZeroCount,OneCount);
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
        
        printf("priKey:%s\n",[priKey  UTF8String]);
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
        
        NSData *dataMsg = [strmsg dataUsingEncoding:NSUTF8StringEncoding];
        if (!strmsg) {
            dataMsg =  readStdIn();
        }
        
        
        
        NSData *dat = [[LTEccTool shared] ecc_decrypt:dataMsg private:strSecKey];
        fwrite(dat.bytes, 1, dat.length, stdout);
        
        
    }
    else {
        NSString *help = @"lwEcc \ng [-prikey/secKey/s prikey]  generate keypair\
        \ne  -pubkey/p pubkey -m msg\
        \nd  -prikey/s prikey -m ciphermsg\n";
        fprintf(stdout,"%s", help.UTF8String);
        fprintf(stdout,"\nbuild:%s %s",__DATE__,__TIME__);
        
    }
    
      
    return 0;
}



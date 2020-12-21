//
//  main.m
//  ECC
//
//  Created by wei li on 2020/12/18.
//

#import <Foundation/Foundation.h>


#import <CommonCrypto/CommonDigest.h>
#import "LTEccTool.h"
int main(int argc, const char * argv[]) {
    
    
    NSString *help = @"lwEcc \ng [-prikey/secKey/s prikey]  generate keypair\
    \ne  -pubkey/secKey/s pubkey msg\
    \nd  -prikey/p prikey cipher\
    ";
    NSLog(@"%@",help);
    
    NSMutableDictionary *dic = [NSMutableDictionary new];
    for (int i = 1 ; i < argc ; ++i ) {
        if(argv[i][0] == '-'){
            NSString *strKey = [[NSString alloc] initWithUTF8String:argv[i]+1];
            i += 1;
            if(i < argc && strKey.length){
                NSString *strValue = [[NSString alloc] initWithUTF8String:argv[i]];
                dic[strKey] = strValue;
            }

        }
    }
    
    NSLog(@"%@",dic);
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
        printf("\npriKey:%s",[(NSString *)dic[@"priKey"]  UTF8String]);
        printf("\npubKey:%s",[(NSString *)dic[@"pubKey"]  UTF8String]);
    }
    
    else if (argc >= 2  && 0 == strcmp(argv[1], "e")) {
        
        if (strPubKey.length == 0) {
            fprintf(stderr, "need pubkey");
            return 1;
        }
        
        NSString *strmsg = [[NSString alloc] initWithUTF8String:argv[argc -1]];
        NSLog(@"%@",strmsg);
        
        NSString *result = [[LTEccTool shared] ecc_encrypt:strmsg pubkey:strPubKey];
        printf("\n%s",result.UTF8String);
        
    }
    else if (argc >= 2  && 0 == strcmp(argv[1], "d")) {
        
        if (strSecKey.length == 0) {
            fprintf(stderr, "need secKey");
            return 1;
        }
        
        NSString *strmsg = [[NSString alloc] initWithUTF8String:argv[argc -1]];
        NSLog(@"%@",strmsg);
        
        NSString *result = [[LTEccTool shared] ecc_decrypt:strmsg private:strSecKey];
        printf("\n%s",result.UTF8String);
        
    }
    
     
     
 
    return 0;
}



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
    \ne  -pubkey/secKey/s pubkey -m msg\
    \nd  -prikey/p prikey -m ciphermsg\
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
    
//    {
//        while (1) {
//            NSDictionary *dicTmp = [[LTEccTool shared] genKeyPair:nil];
//            NSDictionary *dicTmp2 = [[LTEccTool shared] genKeyPair:dicTmp[@"priKey"]];
//            
//            if (![dicTmp[@"pubKey"] isEqual:dicTmp2[@"pubKey"]])  {
//                NSLog(@"--------------------- 123");
//                
//                NSLog(@"dicTmp %@",dicTmp);
//                NSLog(@"dicTmp2 %@",dicTmp2);
//                return 1;
//            }
//            else{
//                static int j = 0;
//                if (j ++ % 9000 == 0) {
//                    NSLog(@"%d",j);
//                }
//                
//            }
//        }
//       
//    }
//    
 
    
    
 
    
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
        
        NSString *strmsg = dic[@"m"];
        NSLog(@"Msg:%@",strmsg);
        
        NSString *result = [[LTEccTool shared] ecc_encrypt:strmsg pubkey:strPubKey];
        printf("\n%s",result.UTF8String);
        
    }
    else if (argc >= 2  && 0 == strcmp(argv[1], "d")) {
        
        if (strSecKey.length == 0) {
            fprintf(stderr, "need secKey");
            return 1;
        }
        
        NSString *strmsg = dic[@"m"];
        NSLog(@"Msg:%@",strmsg);
        
        NSString *result = [[LTEccTool shared] ecc_decrypt:strmsg private:strSecKey];
        printf("\n%s",result.UTF8String);
        
    }
    
 
    return 0;
}



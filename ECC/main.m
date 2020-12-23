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
    UInt8 buffer[BUFSIZ * 10] ;
    size_t t = 0;
    while ((c = fgetc (stdin)) != EOF){
        buffer[t] = c;
        t ++;
    }
    
    return [[NSData alloc] initWithBytes:buffer length:t];
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
        printf("priKey:%s",[(NSString *)dic[@"priKey"]  UTF8String]);
        printf("\npubKey:%s",[(NSString *)dic[@"pubKey"]  UTF8String]);
    }
    
    else if (argc >= 2  && 0 == strcmp(argv[1], "e")) {
        
        if (strPubKey.length == 0) {
            fprintf(stderr, "\033[31;47m need pubkey ,use -p pubkey\033[0m");
            return 1;
        }
        NSString *strmsg = dic[@"m"];
        if (!strmsg) {
            NSData *data =  readStdIn();
            NSString *result = [[LTEccTool shared] ecc_encryptData:data pubkey:strPubKey];
            printf("\n%s",result.UTF8String);
        }
        else{
            
            NSString *result = [[LTEccTool shared] ecc_encrypt:strmsg pubkey:strPubKey];
            printf("\n%s",result.UTF8String);
        }
   
        
        
    }
    else if (argc >= 2  && 0 == strcmp(argv[1], "d")) {
        
        if (strSecKey.length == 0) {
            fprintf(stderr, "\033[31;47m need secKey user -s seckey\033[0m");
         
            return 1;
        }
        NSString *strmsg = dic[@"m"];
        if (!strmsg) {
            NSData *data =  readStdIn();
            NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            NSString *result = [[LTEccTool shared] ecc_decrypt:str private:strSecKey];
            printf("\n%s",result.UTF8String);
        }
        else{
            NSString *result = [[LTEccTool shared] ecc_decrypt:strmsg private:strSecKey];
            printf("\n%s",result.UTF8String);
        }
        
        
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



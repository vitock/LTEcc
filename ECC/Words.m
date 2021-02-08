//
//  Words.c
//  ECC
//
//  Created by wei li on 2021/2/8.
//

#import "Words.h"
NSArray *getWordList(){
    const char *allWordString =
#include "words.txt"
    ;
    
    static NSArray *arr = nil;
    if (arr == nil ) {
        NSString *strTmp = [[NSString alloc] initWithUTF8String:allWordString];
        arr = [strTmp componentsSeparatedByString:@"-"];        
    }
    return arr;
}


//
//  randomart.h
//  ECC
//
//  Created by wei li on 2020/12/23.
//

#ifndef randomart_h
#define randomart_h

#include <stdio.h>



void printRandomArt(const  unsigned char *hash, int byteOfHash,char *title,char *end);


/// 注意,上下左右有划线
/// 生成 outchar (17 + 2) * (9 + 2)
void randomArt(const  unsigned char *hash, int byteOfHash,char *title,char *end,unsigned char *outChar220);

void decodeRandomArt( unsigned char *hash, int *byteOfHash,unsigned char *mapOfCar);


void test(void);
#endif /* randomart_h */

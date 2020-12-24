//
//  randomart.c
//  ECC
//
//  Created by wei li on 2020/12/23.
//
#include<string.h>
#include "randomart.h"
#include <stdlib.h>
/***
 |   ..*o     o    |
 |. o =... o o .   |
 |+ooB.+. o = .    |
 |*E+o= o. + . .   |
 |==o... oS . . .  |
 |+oo.  ..o. . .   |
 |.. . . o  .      |
 |    ..o          |
 |    oo           |
 

 从中间开始 ,01 左上 10 右上 10 坐下 11 右下
 */
// 0-16 .o+=*BOX©%&#/^SE
// 17 * 9
#define RandomArtWidth 17
#define RandomArtHeight 9


#define indexXY(x,y) ((x) + (y) * RandomArtWidth)

#ifndef MIN
#define MIN(a,b)            (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a,b)            (((a) > (b)) ? (a) : (b))
#endif


 

void goWithValue(int dirction ,int *x ,int *y ,char outChar[153]){
    int realX = *x ;
    int realY = *y;
    switch (dirction) {
        case 0:
            realX -= 1;
            realY -= 1;
            realX = MAX(0,realX);
            realX = MIN(RandomArtWidth - 1,realX);
            realY = MAX(0,realY);
            realY = MIN(RandomArtHeight - 1,realY);
            break;
        case 1:
            realX += 1;
            realY -= 1;
            realX = MAX(0,realX);
            realX = MIN(RandomArtWidth - 1,realX);
            realY = MAX(0,realY);
            realY = MIN(RandomArtHeight - 1,realY);
            break;
        case 2:
            realX -= 1;
            realY += 1;
            realX = MAX(0,realX);
            realX = MIN(RandomArtWidth - 1,realX);
            realY = MAX(0,realY);
            realY = MIN(RandomArtHeight - 1,realY);
            break;
        case 3:
            realX += 1;
            realY += 1;
            realX = MAX(0,realX);
            realX = MIN(RandomArtWidth - 1,realX);
            realY = MAX(0,realY);
            realY = MIN(RandomArtHeight - 1,realY);
            break;
        default:
            printf("Error");
            break;
    }
    
    uint8_t v = outChar[indexXY(realX, realY)];
    outChar[indexXY(realX, realY)] = v + 1;
     
    *x = realX;
    *y = realY;
}

void randomArt(const unsigned char *hash, int byteOfHash,char outChar153[153],char *title,char *end){
    
    memset(outChar153,0,153);
    int x = 8;
    int y = 4;
    
    for (int i  = 0 ; i  < byteOfHash; ++ i ) {
        unsigned char tmp = hash[i];
        // 01110001
        int direction = tmp & 3;
        goWithValue(direction, &x , &y , outChar153);
        
        direction = (tmp & (3 << 2)) >> 2 ;
        goWithValue(direction, &x , &y , outChar153);
        
        direction = (tmp & (3 << 4)) >> 4 ;
        goWithValue(direction, &x , &y , outChar153);
        
        direction = (tmp & (3 << 6)) >> 6 ;
        goWithValue(direction, &x , &y , outChar153);
       
        
        
    }
    
    
    outChar153[indexXY(8, 4)] = 15;
    outChar153[indexXY(x, y)] = 16;
    
    static const char *Values = " .o+=*BOX@%&#/^SE";
    unsigned long lenMax =  strlen(Values);
    
    int titleLen = (int)strlen(title ? title :"");
    int _count = 17 - titleLen;
    printf("+");
    if (_count > 0 ) {
        int _count1 = _count / 2;
        int _count2 = _count - _count1;
        while (_count1 -- >0) {
            printf("-");
        }
        if(title){
            printf("%s",title);
        }
        
        while (_count2 -- >0) {
            printf("-");
        }
    }
    printf("+\n");
    
    
    for (int y = 0 ; y < RandomArtHeight ; ++ y  ) {
        for (int x = 0 ; x  < RandomArtWidth; ++ x  ) {
            if (x == 0 ) {
                printf("|");
            }
            unsigned char  v = outChar153[indexXY(x , y)];
            if (v >= 0 && v < lenMax) {
                printf("%c",Values[v]);
            }else{
                printf("K");
            }
            if (x == RandomArtWidth - 1 ) {
                printf("|");
            }
        }
        printf("\n");
        
    }
    
    titleLen = (int)strlen(end ? end : "");
    _count = 17 - titleLen;
    printf("+");
    if (_count > 0 ) {
        int _count1 = _count / 2;
        int _count2 = _count - _count1;
        while (_count1 -- >0) {
            printf("-");
        }
        if(end)
        {
            printf("%s",end);
        }
        while (_count2 -- >0) {
            printf("-");
        }
    }
    printf("+\n");
    printf("\n");
    
    
}






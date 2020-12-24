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

#define RandomArtMapWidth (RandomArtWidth + 3)
#define RandomArtMapHeight (RandomArtHeight + 2)


/// 实际的xy 变换成, 包含边框的 index

#define indexBorderXY(x,y) ((x) + ((y) * RandomArtMapWidth))
#define indexXY(x,y) indexBorderXY((x+1),(y + 1))

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

void printRandomArt(const unsigned char *hash, int byteOfHash,char *title,char *end){
    
    char outChar[RandomArtMapWidth * RandomArtMapHeight];
    randomArt(hash, byteOfHash, title, end, outChar);
    
    printf("\n");
    for (int y  = 0 ; y  < RandomArtMapHeight ; y ++ ) {
        for (int x  = 0 ; x  < RandomArtMapWidth ; x ++ ) {
            int idx = indexBorderXY(x , y);
            printf("%C",outChar[idx]);
        }
    }
    
    
}


void randomArt(const  unsigned char *hash, int byteOfHash,char *title,char *end,char *outChar209){
    
    memset(outChar209,0,(RandomArtMapWidth * RandomArtMapHeight));
    int startX = RandomArtWidth/2;
    int startY  = RandomArtHeight/2;
    int x = startX;
    int y = startY;
    
    for (int i  = 0 ; i  < byteOfHash; ++ i ) {
        unsigned char tmp = hash[i];
        // 01110001
        int direction = tmp & 3;
        goWithValue(direction, &x , &y , outChar209);
        
        direction = (tmp & (3 << 2)) >> 2 ;
        goWithValue(direction, &x , &y , outChar209);
        
        direction = (tmp & (3 << 4)) >> 4 ;
        goWithValue(direction, &x , &y , outChar209);
        
        direction = (tmp & (3 << 6)) >> 6 ;
        goWithValue(direction, &x , &y , outChar209);
       
        
        
    }
    
    
    outChar209[indexXY(startX, startY)] = 15;
    outChar209[indexXY(x, y)] = 16;
    
    static const char *Values = " .o+=*BOX@%&#/^SE";
    unsigned long lenMax =  strlen(Values);
    
    
    outChar209[indexBorderXY(0, 0)] = '+';
    
    for (int i = 0; i < RandomArtMapWidth; ++ i) {
        outChar209[indexBorderXY(i, 0)] = '-';
        outChar209[indexBorderXY(i ,RandomArtMapHeight - 1)] = '-';
    }
    
    for (int i = 0; i < RandomArtMapHeight; ++ i) {
        outChar209[indexBorderXY(0, i)] = '|';
        outChar209[indexBorderXY(RandomArtMapWidth - 2, i)] = '|';
        outChar209[indexBorderXY(RandomArtMapWidth - 1, i)] = '\n';
    }
    
    outChar209[indexBorderXY(0,0)] = '+';
    outChar209[indexBorderXY(RandomArtMapWidth - 2,0)] = '+';
    
    outChar209[indexBorderXY(0,RandomArtMapHeight -1)] = '+';
    outChar209[indexBorderXY(RandomArtMapWidth - 2,RandomArtMapHeight -1)] = '+';
    
   
    for (int y = 0 ; y < RandomArtHeight ; ++ y  ) {
        for (int x = 0 ; x  < RandomArtWidth; ++ x  ) {
            unsigned char  v = outChar209[indexXY(x , y)];
            if (v >= 0 && v < lenMax) {
                outChar209[indexXY(x , y)] = Values[v];
            }else{
                outChar209[indexXY(x , y)] = '!';
            }
        }
    
    }
    
    int titleLen = (int)strlen(title ? title :"");
    if (titleLen) {
        int titleStart  = (RandomArtWidth - titleLen)/2;
        if (titleStart < 0) {
            titleStart =  0;
        }
        for (int  i = titleStart,j = 0 ;  i < RandomArtWidth && j  < titleLen ; ++ j ,++ i ) {
            outChar209[indexXY(i , -1)] = title[j];
        }
    }
    
    int endLen = (int)strlen(end ? end :"");
    if (endLen) {
        int endLenStart  = (RandomArtWidth - endLen)/2;
        if (endLenStart < 0) {
            endLenStart =  0;
        }
        for (int  i = endLenStart,j = 0 ;  i < RandomArtWidth && j  < endLen ; ++ j ,++ i ) {
            outChar209[indexXY(i , RandomArtHeight )] = end[j];
        }
    }
    
   
}





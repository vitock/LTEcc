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
#define valify(realX,realY) \
{\
realX = MAX(0,realX);\
realX = MIN(RandomArtWidth - 1,realX);\
realY = MAX(0,realY);\
realY = MIN(RandomArtHeight - 1,realY);\
}
void *mMalloc(size_t t){
    void *p = malloc(t);
    memset(p , 0 , t);
    return p;
}
void mFree(void * p){
    free(p);
}
void goWithValue(int dirction ,int *x ,int *y ,char outChar[153]){
    int realX = *x ;
    int realY = *y;
    switch (dirction) {
        case 0:
            realX -= 1;
            realY -= 1;
            break;
        case 1:
            realX += 1;
            realY -= 1;
             
            break;
        case 2:
            realX -= 1;
            realY += 1;
  
            break;
        case 3:
            realX += 1;
            realY += 1;
  
            break;
        default:
            printf("Error");
            break;
    }
    
    valify(realX, realY);
    uint8_t v = outChar[indexXY(realX, realY)];
    outChar[indexXY(realX, realY)] = v + 1;
     
    *x = realX;
    *y = realY;
}
void printRandomArt(const unsigned char *hash, int byteOfHash,char *title,char *end){
    
    unsigned char outChar[RandomArtMapWidth * RandomArtMapHeight];
    randomArt(hash, byteOfHash, title, end, outChar);
    
    printf("\n");
    for (int y  = 0 ; y  < RandomArtMapHeight ; y ++ ) {
        for (int x  = 0 ; x  < RandomArtMapWidth ; x ++ ) {
            int idx = indexBorderXY(x , y);
            printf("%C",outChar[idx]);
        }
    }
    
    
}
void randomArt(const  unsigned char *hash, int byteOfHash,char *title,char *end,unsigned char *outChar209){
    
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
static char debugchar[220];
typedef struct _NodeList {
    struct _Node *node;
    struct _NodeList *next;
} NodeList;
typedef  struct _Node{
    int allDotCount;
    struct _Node *parrent;
    NodeList *children;
    int x;
    int y;
    int count;
    
    /**
     * 和生成相同, 子到父的方向  0 lt 1 rt 3 ld 4 rd
     */
    int dicretion;
    
    int isFinal;
    
    int isChildAdd;
    
} Node;
static int g_showLog = 0;
void setChartLog(int r  ){
    g_showLog = r;
}
void debugNode(Node *pre,Node *current,char *mapChar, char *ex,int showchart,int left){
    if(!g_showLog){
        return;
    }
    
    
    if (current) {
        int idx = indexXY(current->x , current->y);
        char mapDebug[220];
        memcpy(mapDebug, debugchar, 220);
        mapDebug[idx] = 'G';
        
        if (pre) {
            int idx2 = indexXY(pre->x , pre->y);
            mapDebug[idx2] = 'P';
             
        }
        
        char c = debugchar[idx];
        if(c == ' '){
            printf("oop");
        }
        static int z = 0;
        
        printf("\n>%02d %*c %c (%d,%d) %d  %s",z++,(left),' ',c,current->x,current->y,mapChar[idx],ex);
        if(showchart && 0){
            printf("\n");
            for (int y  = 0 ; y  < RandomArtMapHeight ; y ++ ) {
                for (int x  = 0 ; x  < RandomArtMapWidth ; x ++ ) {
                    int idx = indexBorderXY(x , y);
                    printf("%C",mapDebug[idx]);
                }
            }
            printf("\n");
            
            for (int y  = 0 ; y  < RandomArtMapHeight ; y ++ ) {
                for (int x  = 0 ; x  < RandomArtMapWidth ; x ++ ) {
                    int idx = indexBorderXY(x , y);
                    int v = mapChar[idx];
                    if (v > 0 && v < 18) {
                        printf("%x",v);
                    }else{
                        printf(" ");
                    }
                    
                }
                printf("\n");
            }
        }
       
          
        
    }
    else{
        printf("NULL  %s",ex);
    }
}
 
 
uint8_t char2Count(char c ){
    
    uint8_t t = 0;
//    .o+=*BOX@%&#/^SE
    switch (c) {
        case ' ':
            t = 0;
            break;
        case '.':
            t = 1;
            break;
        case 'o':
            t = 2;
            break;
        case '+':
            t = 3;
            break;
        case '=':
            t = 4;
            break;
        case '*':
            t = 5;
            break;
        case 'B':
            t = 6;
            break;
        case 'O':
            t = 7;
            break;
        case 'X':
            t = 8;
            break;
            //.o+=*BOX@%&#/^SE
        case '@':
            t = 9;
            break;
        case '%':
            t = 10;
            break;
        case '&':
            t = 11;
            break;
        case '#':
            t = 12;
            break;
        case '/':
            t = 13;
            break;
        case '^':
            t = 14;
            break;
        case 'S':
            t = 15;
            break;
        case 'E':
            t = 16;
            break;
        default:
            t = ~t;
            break;
    }
    
    return  t;
}
void increaseNode(Node *node,uint8_t *map){
    int idx = indexXY(node->x , node->y);
    uint8_t t = map[idx];
    if (t < 255 ) {
        t ++ ;
        map[idx] = t;
    }
}
void decreaseNode(Node *node,uint8_t *map){
    int idx = indexXY(node->x , node->y);
    uint8_t t = map[idx];
    if (t > 0) {
        t --;
        map[idx] = t;
    }
}
void insertChild(char *mapOfchar, Node *nodeParent,Node *child){
    debugNode(nodeParent,child,mapOfchar,"insert",1,5);
//    printf("\n > %c",debugchar[indexXY(child->x, child->y)]);
  
    
    if (nodeParent->children == NULL) {
        nodeParent->children = mMalloc(sizeof(NodeList));
        NodeList *list =  nodeParent->children;
        list->node = child;
        return;;
    }
    
  
    
    ///  升序排
    
    NodeList *listItem = nodeParent->children;
    
    NodeList *pre = NULL;
    
    int childv = child->count;
    do {
        // 插入到前面
        if ( childv < listItem->node->count ) {
            NodeList *current = mMalloc(sizeof(NodeList));
            current->node = child;
            current->next = listItem->next;
            current->next = listItem;
            if (pre) {
                pre->next = current;
            }
            else {
                nodeParent->children = current;
            }
            
            return;;
        }
        else if(listItem ->next){
            pre = listItem;
            listItem = listItem->next;
        }
        else{ // 末尾了,直接插入
            NodeList *next = mMalloc(sizeof(NodeList));
            next->node = child;
            next->next = NULL;
            listItem->next = next;
            
            return;;
        }
        
    } while (1);
    
     
}
Node * allocFromMap(Node **nodeMap,int x, int y,int v){
    int index = x + RandomArtWidth * y;
    Node *p = NULL;//nodeMap[index];
    if (p == NULL )
    {
        p = mMalloc(sizeof(Node));
        p->x = x;
        p->y = y;
        
        p->children = NULL;
//        nodeMap[index] = p;
    }
    
    /// 已经用过的,孩子顺序已经排咧好了,不需要了,这里用新的
    p->count = v;
    return  p;
}
#define MaxStackSize 1000
#define MaxResultSize (MaxStackSize << 2)
typedef struct _NodeStack{
    Node *stack[MaxStackSize];
    int current;
    
}NodeStack ;
 
Node *getTop(NodeStack *stack){
    int c = stack->current;
    if ( c >= 0) {
        Node *p = stack->stack[c];
        return p;
    }
    return NULL;
}
Node *pop(NodeStack *stack){
    int c = stack->current;
    if ( c >= 0) {
        Node *p = stack->stack[c];
        stack->stack[c] = NULL;
        stack->current = c - 1;
        return p;
    }
    return NULL;
}
void  push(NodeStack *stack,Node *p){
    int c = stack->current;
    if (c == MaxStackSize) {
        fprintf(stderr, "\nmax stack size %d\n",MaxStackSize);
        exit(1);
        return;
    }
    c++;
    stack->stack[c] = p;
    stack->current = c;
    
}
int  checkStackIsFinishState(NodeStack *stack,unsigned char *map,Node *topNode){
    
    int c = stack->current;
    
    
    while (c >=0 ) {
        Node *node = stack->stack[c];
        if (node == NULL ) {
            printf("-");
        }
        
        if (node && node->children) {
            NodeList *child = node->children;
            while (child) {
                int x = child->node->x;
                int y = child->node->y;
                
                if(map[indexXY(x, y)] != 0 && child->node->isFinal == 0){
                    return 0;
                }
                child =  child->next;
            }
        }
        
        c --;
        
    }
    
    c = stack->current;
    
    int depath = 0;
    if(topNode){
        Node *tmp = topNode;
        
        while (tmp) {
            depath ++;
            if(tmp->children){
                tmp = tmp->children->node;
            }
            else{
                tmp = NULL;
            }
            
        }
        
        
        return  depath % 4 == 1;
        
    }
    
    
    /// 满足深度为 4的倍数
    return 1;
}
 
int8_t getNodeDirection(Node *parent,Node *child){
    int dx =  child->x - parent->x ;
    int dy =  child->y - parent->y ;
    
    //撞墙判断
    if(dx == 0){
        if (child->x > 0) {
            dx = 1;
        }
        else{
            dx = -1;
        }
    }
    
    //撞墙判断
    if(dy == 0){
        if (child->y == 0) {
            dx = -1;
        }
        else{
            dx = 1;
        }
    }
    /// 0 3
    if (dx < 0 ) {
        return dy > 0 ? 2 : 0;
    }else {
        return dy > 0 ? 3 : 1;
    }
}
///
int  searchNode(uint8_t *mapOfCar,Node *topE, Node **nodeMap,Node *node,int valueSum,NodeStack*stack ,int eX,int eY,int sX,int sY){
    
    node->count = mapOfCar[indexXY(node->x, node->y)];
    node->count -=1;
    debugNode(NULL,node,mapOfCar,"search",1,0);
    if(node->isChildAdd == 0){
        node->isChildAdd = 1;
        int x = node->x;
        int y = node->y;
        {
            int x0 = x-1;
            int y0 = y-1;
            valify(x0, y0);
            int v = mapOfCar[indexXY(x0, y0)];
            if(v!= 0){
                Node *lt =   allocFromMap(nodeMap,x0,y0,v);
                
                if (lt->count > 0 ) {
                    lt->allDotCount = node->allDotCount;
                    /// 方向逆转
                    lt->dicretion = 3;
                    if ((x0 == eX && y0 == eY )||  (x0 == sX && y0 == sY )) {
                        lt->isFinal = 1;
                    }
                    
                    insertChild(mapOfCar,node, lt);
                }
               
                
            }
        }
        
        /// right top
        {
            int x0 = x+1;
            int y0 = y-1;
            valify(x0, y0);
            int v = mapOfCar[indexXY(x0, y0)];
            if(v!= 0){
                Node *lt =   allocFromMap(nodeMap,x0,y0,v);
                
                lt->allDotCount = node->allDotCount;
                /// 方向逆转
                lt->dicretion = 2;
                if ((x0 == eX && y0 == eY )||  (x0 == sX && y0 == sY )) {
                    lt->isFinal = 1;
                }
                
                insertChild(mapOfCar,node, lt);
                 
            }
        }
        /// left bottom
        {
            int x0 = x-1;
            int y0 = y+1;
            valify(x0, y0);
            int v = mapOfCar[indexXY(x0, y0)];
            if(v!= 0){
                Node *lt = allocFromMap(nodeMap,x0,y0,v);
                
                lt->allDotCount = node->allDotCount;
                /// 方向逆转
                lt->dicretion = 1;
                if ((x0 == eX && y0 == eY )||  (x0 == sX && y0 == sY )) {
                    lt->isFinal = 1;
                }
                
                insertChild(mapOfCar,node, lt);
                
            }
        }
        /// right bottom
        {
            int x0 = x+1;
            int y0 = y+1;
            valify(x0, y0);
            int v = mapOfCar[indexXY(x0, y0)];
            if(v!= 0){
                Node *lt =   allocFromMap(nodeMap,x0,y0,v);
                lt->allDotCount = node->allDotCount;
                lt->dicretion = 0;
                lt->count = v;
                
                if ((x0 == eX && y0 == eY )||  (x0 == sX && y0 == sY )) {
                    lt->isFinal = 1;
                }
                insertChild(mapOfCar,node, lt);
                
            }
        }
    }
    else {
        /// DEBUG
    }
        
    return 1;
}
void decodeRandomArt(uint8_t *hash, int *byteOfHash,unsigned char *mapOfCar){
    
    memcpy(debugchar, mapOfCar, 220);
    
    int sX = -1,sY = -1; ;
    int sumOfdotvalue = 0;
    
    int eX = -1, eY = -1;
    for (int x  = 0; x < RandomArtWidth ; ++ x  ) {
        for (int y = 0 ; y < RandomArtHeight; ++ y ) {
            
            /// 这里把找到的第一个E 作为end ,如果有多个E,可能会失败. ,暂时不处理这种
            char c = mapOfCar[indexXY(x , y)];
            if (eX == -1 && c == 'E') {
                eX = x ;
                eY = y ;
            }
            
            if (sY == -1 && c == 'S') {
                sX = x ;
                sY = y ;
            }
            
            /// 把ascii 变成 计数
            int s = char2Count(c);
            mapOfCar[indexXY(x , y)] = s;
            if(s > 0 && s < 17){
                sumOfdotvalue += s;
            }
        }
    }
    
    /// S 和 E 重合
    if (sX == -1) {
        sX = eX;
        sY = eY;
    }
    
    /// 去掉开始和结束强制的 15 和 16;
     
    Node *startNode = mMalloc(sizeof(Node));
    startNode->children = NULL;
    startNode->x = sX;
    startNode->y = sY;
    startNode->allDotCount = sumOfdotvalue;
    
    /// 保存 Node 对象
    Node **nodeMap =  mMalloc(RandomArtWidth * RandomArtHeight * sizeof(Node *));
    memset(nodeMap, 0,RandomArtWidth * RandomArtHeight * sizeof(Node *) );
    
    
    NodeStack *stack = mMalloc(sizeof(NodeStack));
    stack->current = -1;
    
    int finish = 0;
    
    Node *node = startNode;
    
    int DEBUGMAXC = 1100;
    do {
        if (DEBUGMAXC -- < 0) {
            printf("EEEEEEEEError\n");
            break;
        }
        
        push(stack, node);
        decreaseNode(node,mapOfCar);
        searchNode(mapOfCar,nodeMap,startNode,node,sumOfdotvalue,stack,eX,eY,sX,sY);
         
        /// 已经是叶子节点了
        if (node->children == NULL) {
            
            /// 所有节点都遍历 成功
            if( node->x == eX && node->y == eY && checkStackIsFinishState(stack,mapOfCar,startNode ) ){
                finish = 1;
    
            }
            else {
                pop(stack);
                debugNode(NULL,node, mapOfCar,"pop",1,6);
                increaseNode(node,mapOfCar);
                ///
                Node *father = getTop(stack);
                while(father){
                    // 有其他子孙,
                   if (father && father->children && father->children->next) {
                       NodeList *childToRemove = father->children;
                       father->children = childToRemove->next;
                       mFree(childToRemove);
                       node = father->children->node;
                       break;
                   }
                   /// 一袋单传
                   else {
                       father = pop(stack);
                       if (father) {
                           increaseNode(father,mapOfCar);
                           debugNode(NULL,node, mapOfCar,"pop",1,6);
                       }
                       else{
                           break;
                       }
    
                   }
                }
                
            }
        }
        else {
            node = node->children->node;
        }
        
    } while (!finish && node);
    
    
    ///
    uint8_t *direction = malloc(sizeof(uint8_t) *10000);
    
    int count = 0;
    printf("\n----result --");
    while (startNode) {
        debugNode(NULL,startNode, mapOfCar,"result",0,0);
        if (startNode->children ) {
            
            Node *child = startNode->children->node;
            
            int8_t dir =  getNodeDirection(startNode, child);
            printf("  %d",dir);
            
            direction[count] = dir;
            startNode =child;
            count ++;
        }
        else {
            startNode = NULL;
        }
    }
    
    int byteLen = count/4;
    *byteOfHash =byteLen;
    
    for (int i = 0 ,byteIdx = 0 ; i < count ; i += 4,byteIdx ++) {
        uint8_t d0 = direction[i];
        uint8_t d1 = direction[i + 1];
        uint8_t d2 = direction[i + 2];
        uint8_t d3 = direction[i + 3];
        
        //            10110010   2  + 8  + 16
        
        
        
        uint8_t r = d0  |  (d1 << 2) |  (d2 << 4) | (d3 << 6);
        hash[byteIdx] = r;
        
    }
    
    
    
    
    printf("\n r: %d\n",hash[0]);
  
    
}
void test1(){
    
}
void test(){
    
    
    if(0)
    {
        uint8_t t = 53;
        printRandomArt(&t , 1, NULL, NULL);
        
        t = 89;
        printRandomArt(&t , 1, NULL, NULL);
        
        return;;
    }
    
    
    setChartLog(1);
    int C = 111;
    
    int v = 0;
    int unfitCount = 0;
    uint8_t unfit[200] ;
    
    
    while (C -- > 0) {
        const int size = 1;
        unsigned char a[size];
        arc4random_buf(a , size);
        
        a[0] =  116;
        
        
        
        uint8_t map[220];
        printRandomArt(a , size, NULL , NULL);
 
        randomArt(a , size , NULL , NULL, map);
        
        
        
        uint8_t hash[100];
        int len =0;
        decodeRandomArt(hash, &len, map);
        
        
        //00 10 01 10
        
        
        if(0 != memcmp(a , hash, size)){
            
            
            char *map0_220[220];
            char *map1_220[220];
            
            randomArt(hash, size, NULL , NULL , map0_220);
            randomArt(a, size, NULL , NULL , map1_220);
            
            if(0 == memcmp(map1_220 , map0_220, 220)){
                 
                printf("--- same  %d %d ----",hash[0],a[0]);
                printRandomArt(a , size, "a", "a");
                
                printRandomArt(hash , size, "b", "b");
                continue;;
            }
            
            
            
            printf("\n result\n");
            for (int i = 0 ; i < size ; ++ i ) {
                printf(" %d,",hash[i]);
            }
            printf("\n origin\n");
            for (int i = 0 ; i < size ; ++ i ) {
                printf(" %0d",a[i]);
            }
            printf("\n-----------NotFit-----------------org %d---result  %d---------\n",a[0],hash[0]);
            
   
            
            
            unfit[unfitCount] = a[0];
            unfitCount ++ ;
            break;
        }
        else {
         
        }
        
    }
    
    printf("\n unfitCount :%d\n",unfitCount);
    while (unfitCount >= 0 ) {
        printf(" %d,",unfit[unfitCount]);
        
        unfitCount -= 1;
    }
    
    printf("\n unfitCount :%d\n",unfitCount);
   
   
}

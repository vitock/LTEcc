//
//  Header.h
//  ECC
//
//  Created by wei li on 2020/12/31.
//

#ifndef Header_h
#define Header_h

#define metamacro_head(FIRST, ...) FIRST
#define metamacro_at20(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19,...) metamacro_head(__VA_ARGS__)

#define metamacro_is_only_one(...) \
metamacro_at20( __VA_ARGS__, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0)


 
#define MyLogFunc0(fmt)   NSLog((@"%s line_%d " fmt),__FUNCTION__,__LINE__  )
#define MyLogFunc1(fmt,...)   NSLog((@"%s line_%d " fmt),__FUNCTION__,__LINE__ ,__VA_ARGS__ )

#define CAT(A,B) CAT_(A,B)
#define CAT_(A,B) A##B
#define MyLogFunc(...)  CAT(MyLogFunc,metamacro_is_only_one(__VA_ARGS__) )(__VA_ARGS__)

 

#define Version "0.0.1"

#endif /* Header_h */

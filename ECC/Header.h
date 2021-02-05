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


 
#define __L_L_L_0(fmt)   NSLog((@"%s line_%d " fmt),__FUNCTION__,__LINE__  )
#define __L_L_L_1(fmt,...)   NSLog((@"%s line_%d " fmt),__FUNCTION__,__LINE__ ,__VA_ARGS__ )

#define CAT(A,B) CAT_(A,B)
#define CAT_(A,B) A##B

#ifdef DEBUG
#define MyLogFunc(...)  CAT(__L_L_L_,metamacro_is_only_one(__VA_ARGS__) )(__VA_ARGS__)
#else
#define MyLogFunc(...)
#endif

 
#define __err__0(fmt) fprintf(stderr, ("\033[31;47m" fmt "\033[0m\n"))
#define __err__1(fmt,...) fprintf(stderr, ("\033[31;47m" fmt "\033[0m\n"),__VA_ARGS__)

#define PrintErr(...) CAT(__err__,metamacro_is_only_one(__VA_ARGS__))(__VA_ARGS__)

#define Version "0.0.4.2"

#endif /* Header_h */

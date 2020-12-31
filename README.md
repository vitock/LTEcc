# LTEcc

# 利用椭圆曲线`secp256k1` 进行加解密工具
用法

## 生成密钥对
> ecc g 


或者指定随机私钥 (32字节的base64 ) 
> ecc g -s  ZGLesiQ5A09PfRDDvJqNM7FxZcf2j0dMeGyV0E/A74Q=
输出 会显示公钥和私钥,同时显示私钥的sha256指纹,以及其randomart
```

ECC encryption privateKey finggerprint: 
ZGLesiQ5A09PfRDDvJqNM7FxZcf2j0dMeGyV0E/A74Q=
randomart:

+---[Secp251k1]---+
|       o+. . o+++|
|       .ooo + oo*|
|  . . + ++.o . O.|
|   + *o=o.    E *|
|    * =XS      * |
|     =Bo.     . +|
|      .o       . |
|                 |
|                 |
+----[SHA 256]----+

0/1 = 123/133   0.519531


priKey:A5ey2d8ddoiSCxW2p/2RnLbME1YyrrCaVbyONF7ynuQ=
pubKey:BKZ2iYIYZxAtxsw/ovquy67sS5nhVoWydYB+JEvwMxMRM26tdCux0f7oSuUgMZa/Sqh3+7ZqWTONarra2BGW9OM=


```


## 加密

>  ecc e -p BGjWSuufcBmXmfM6Tdvu0GQfhQRmigD9hD+C+cDgdAKRGug/ZTPC4eZrMlGR3dv4A798g4SyvyoJAg+wWUgOIMo= -m hello 

或者
> cat a.txt | ecc -p BGjWSuufcBmXmfM6Tdvu0GQfhQRmigD9hD+C+cDgdAKRGug/ZTPC4eZrMlGR3dv4A798g4SyvyoJAg+wWUgOIMo= 

默认输出是二进制,如果想base64 输出可以,使用pip

 ecc e -p BGjWSuufcBmXmfM6Tdvu0GQfhQRmigD9hD+C+cDgdAKRGug/ZTPC4eZrMlGR3dv4A798g4SyvyoJAg+wWUgOIMo= -m hello | base64


 ## 解密
 

 > echo 'encrypte base64 ' | base64 -d | ecc d -s A5ey2d8ddoiSCxW2p/2RnLbME1YyrrCaVbyONF7ynuQ=

 ## randomart 
 > ecc r -m msg
 这是我在ssh-keygen 上第一次看到,觉得蛮有趣的,就自己弄了个。

 ```
 ecc r -m 'hello world'
+-----------------+
|                 |
|       o         |
|      . E . o    |
|       O = *     |
|      o S = *    |
|     .   . =     |
|                 |
|                 |
|                 |
+-----------------+


 ```




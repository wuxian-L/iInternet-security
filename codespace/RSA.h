#include<iostream>
#include<ctime>
#include<cstdlib>
#include<fstream>
#include<utility>
#include<cstdint>
#include<windows.h>
struct Key{
    uint32_t exp;
    uint32_t n;
    Key(uint32_t e,uint32_t num){
        exp = e;
        n = num;
    }
    Key(){}
};
struct Keys{
    Key publickey;
    Key privatekey;
    Keys(Key puk,Key prk){
        publickey = puk;
        privatekey = prk;
    }
};
Keys ProductKeys();
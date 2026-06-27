#include<iostream>
#include<ctime>
#include<cstdlib>
#include<fstream>
#include<utility>
#include<cstdint>
#include<windows.h>
struct Key{
    uint64_t exp;
    uint64_t n;
    Key(uint64_t e,uint64_t num){
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
uint64_t EncryptOrDecryptMessage(uint64_t ms,Key key);
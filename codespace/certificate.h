#include <string>
#include "RSA.h"
#include "MD5_hash.h"
struct Certificate{
    std::string site;
    Key publickey;
    uint64_t signal[4];
    Certificate(){}
    Certificate(std::string s, Key pkey, uint64_t* si){
        site = s;
        publickey = pkey;
        for(int i = 0; i < 4; i++)
            signal[i] = si[i];
    }
};

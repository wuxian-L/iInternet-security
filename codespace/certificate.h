#include "RSA.h"
#include "MD5_hash.h"
struct Certificate{
    std::string site;
    uint32_t signal;
    Certificate(){}
    Certificate(std::string s,uint32_t si){
        site = s;
        signal = si;
    }
};
int main(){
    
    return 0;
}
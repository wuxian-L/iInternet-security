/*
两个质数 p q
质数相乘 N = p * q
欧拉函数 ol(N) = (p-1)*(q-1) = T
选择公钥 E E为质数且1 < 公钥 < T且不是T的因子
(E,T)
计算私钥 D (D*E)%T = 1
(D,T)
*/
#include "RSA.h"
bool isPrime(int n) {
    if (n <= 1) return false;
    for (int i = 2; i * i <= n; ++i) {
        if (n % i == 0)
            return false;
    }
    return true;
}
void selectPQ(int &p, int &q){
    std::srand(std::time(0));
    p = 0; q = 0;
    while(!isPrime(p)){
        p = std::rand()%50 + 2;
    }
    while(!isPrime(q) || q == p){
        q = std::rand()%50 + 2;
    }
}
int calculateT(int p,int q){
    return (p-1)*(q-1);
}
int calculatePublicKey(int T){
    for(int e = 2;e < T;e++){
        if(isPrime(e) && T%e != 0)
            return e;
    }
    return 0;
}
int calculatePrivateKey(int T,int b){
    int r1 = T,r2 = b,t1 = 0,t2 = 1;
    while(r2 > 0){
        int q = r1/r2;
        int r = r1 - q*r2;
        r1 = r2;
        r2 = r;

        int t = t1 - q*t2;
        t1 = t2;
        t2 = t;
    }
    if(r1 == 1)
        return t1 > 0? t1:t1 + T;
    return 0;
}
uint32_t Square_and_Multiply(uint32_t a,uint32_t x,uint32_t n){
    uint32_t y = 1;
    while(x > 0){
        if(x & 1)
            y = (a*y)%n;
        a = (a*a)%n;
        x >>= 1;
    }
    return y;
}
struct Key;
struct Keys;
uint32_t EncryptOrDecryptMessage(uint32_t ms,Key key){
    return Square_and_Multiply(ms,key.exp,key.n);
}
Keys ProductKeys(){
    int p, q;
    selectPQ(p, q);
    int n = p * q;
    int T = calculateT(p,q);
    int e = calculatePublicKey(T);
    int d = calculatePrivateKey(T,e);
    Key publickey = Key(e, n);
    Key privatekey = Key(d, n);
    return Keys(publickey,privatekey);
}
int main(){
    SetConsoleOutputCP(65001);
    int p, q;
    selectPQ(p, q);
    int n = p * q;
    int T = calculateT(p,q);
    int e = calculatePublicKey(T);
    int d = calculatePrivateKey(T,e);
    Key publickey = Key(e, n);
    Key privatekey = Key(d, n);
    uint32_t ms = 19;
    uint32_t C = EncryptOrDecryptMessage(ms,publickey);
    uint32_t M = EncryptOrDecryptMessage(C,privatekey);

    std::cout << "p = " << p << ", q = " << q << std::endl;
    std::cout << "n = " << n << ", T = " << T << std::endl;
    std::cout << "e = " << e << ", d = " << d << std::endl;
    std::cout << "Plaintext:  " << ms << std::endl;
    std::cout << "Ciphertext: " << C << std::endl;
    std::cout << "Decrypted:  " << M << std::endl;
    std::cout << "-----------example---------" << std::endl;
    Key examplepublickey = Key(5, 119);
    Key exampleprivatekey = Key(77, 119);
    uint32_t ems = 19;
    uint32_t eC = EncryptOrDecryptMessage(ems,examplepublickey);
    uint32_t eM = EncryptOrDecryptMessage(eC,exampleprivatekey);
    std::cout << "Plaintext:  " << ems << std::endl;
    std::cout << "Ciphertext: " << eC << std::endl;
    std::cout << "Decrypted:  " << eM << std::endl;
    return 0;
}
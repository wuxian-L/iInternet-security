/*
两个质数 p q
质数相乘 N = p * q
欧拉函数 ol(N) = (p-1)*(q-1) = T
选择公钥 E，满足 1 < E < T 且 gcd(E,T)=1
(E,N)
计算私钥 D，满足 (D*E)%T = 1
(D,N)
*/
#include "RSA.h"
#include <algorithm>

bool isPrime(uint64_t n) {
    if (n <= 1) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;
    for (uint64_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0)
            return false;
    }
    return true;
}

// 生成较大的质数，使 N > 2^32，从而能够加密 32 位的哈希块
void selectPQ(uint64_t &p, uint64_t &q){
    p = 0; q = 0;
    while(!isPrime(p)){
        p = static_cast<uint64_t>(std::rand()) % 30001 + 70000;
    }
    while(!isPrime(q) || q == p){
        q = static_cast<uint64_t>(std::rand()) % 30001 + 70000;
    }
}

uint64_t calculateT(uint64_t p, uint64_t q){
    return (p-1)*(q-1);
}

static uint64_t gcd(uint64_t a, uint64_t b){
    while(b != 0){
        uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

uint64_t calculatePublicKey(uint64_t T){
    // 从 3 开始找第一个与 T 互质的奇数即可，避免遍历整个 T
    for(uint64_t e = 3; e < T; e += 2){
        if(gcd(e, T) == 1)
            return e;
    }
    return 0;
}

uint64_t calculatePrivateKey(uint64_t T, uint64_t b){
    long long r1 = static_cast<long long>(T);
    long long r2 = static_cast<long long>(b);
    long long t1 = 0, t2 = 1;
    while(r2 > 0){
        long long q = r1 / r2;
        long long r = r1 - q * r2;
        r1 = r2;
        r2 = r;

        long long t = t1 - q * t2;
        t1 = t2;
        t2 = t;
    }
    if(r1 == 1){
        if(t1 > 0) return static_cast<uint64_t>(t1);
        else return static_cast<uint64_t>(t1 + static_cast<long long>(T));
    }
    return 0;
}

uint64_t Square_and_Multiply(uint64_t a, uint64_t x, uint64_t n){
    uint64_t y = 1;
    a %= n;
    while(x > 0){
        if(x & 1)
            y = static_cast<uint64_t>((__uint128_t)a * y % n);
        a = static_cast<uint64_t>((__uint128_t)a * a % n);
        x >>= 1;
    }
    return y;
}

uint64_t EncryptOrDecryptMessage(uint64_t ms, Key key){
    return Square_and_Multiply(ms, key.exp, key.n);
}

Keys ProductKeys(){
    uint64_t p, q;
    selectPQ(p, q);
    uint64_t n = p * q;
    uint64_t T = calculateT(p, q);
    uint64_t e = calculatePublicKey(T);
    uint64_t d = calculatePrivateKey(T, e);
    Key publickey = Key(e, n);
    Key privatekey = Key(d, n);
    return Keys(publickey, privatekey);
}

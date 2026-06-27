// 数字证书签发与验证模拟
#include "certificate.h"
#include <iostream>
#include <string>
#include <cstdint>
#include <ctime>
#include <cstdlib>
#include <vector>

// 用网站地址和网站公钥生成 128bit（16 字节）哈希，按 4 个 uint32_t 处理
void CalculateSiteHash(const std::string& site, const Key& pkey, uint8_t out[16]) {
    std::string str_data = site + std::to_string(pkey.exp) + std::to_string(pkey.n);

    std::vector<uint8_t> data(str_data.begin(), str_data.end());
    MD5Hash(data, out);
}

// 用户用 CA 公钥解密签名，并与重新计算的哈希对比
void ProveLegit(const Certificate& site_certi, const Key& CApublickey){
    // 计算哈希值
    uint8_t digest[16];
    CalculateSiteHash(site_certi.site, site_certi.publickey, digest);
    const uint32_t *cal_p = reinterpret_cast<const uint32_t*>(digest);

    // 解密证书中的哈希值
    uint64_t de_signal[4];
    for(int i = 0; i < 4; i++){
        de_signal[i] = EncryptOrDecryptMessage(site_certi.signal[i], CApublickey);
    }

    // 对比哈希值
    for(int i = 0; i < 4; i++){
        if(cal_p[i] != de_signal[i]){
            std::cout << "认证失败，可能受到攻击" << std::endl;
            return;
        }
    }
    std::cout << "认证成功，通讯安全" << std::endl;
}

int main(){
    // 设置控制台输出为 UTF-8，避免中文在 Windows 终端乱码
    SetConsoleOutputCP(65001);

    // 只初始化一次随机种子，避免同一秒内两次调用 ProductKeys 得到完全相同的密钥
    std::srand(static_cast<unsigned int>(std::time(nullptr)));

    std::cout << "hello world" << std::endl;

    // 1. 获取网站地址和网站公钥
    std::string site = "https//passport2.chaoxing.com";
    Keys siteKeys = ProductKeys();
    Keys CAKeys   = ProductKeys();

    // 2. 对网站地址和公钥进行哈希运算
    uint8_t digest[16];
    CalculateSiteHash(site, siteKeys.publickey, digest);
    const uint32_t *p = reinterpret_cast<const uint32_t*>(digest);

    // 3. CA 用私钥加密哈希值，得到数字签名
    uint64_t signal[4];
    for(int i = 0; i < 4; i++){
        signal[i] = EncryptOrDecryptMessage(p[i], CAKeys.privatekey);
    }

    Certificate site_certi = Certificate(site, siteKeys.publickey, signal);

    // 4. 用户验证网站合法通讯安全
    ProveLegit(site_certi, CAKeys.publickey);
    return 0;
}

#include "MD5_hash.h"
//循环左移
uint32_t RotateLeft(uint32_t value, uint32_t shift)
{
    return (value << shift) | (value >> (32 - shift));
}
//step1填充比特
void AppendPadding(std::vector<uint8_t> &message)
{
    uint64_t originalBitLength = message.size() * 8;
    message.push_back(0x80);
    while (message.size() % 64 != 56)
    {
        message.push_back(0x00);
    }
}
//step2附加原始信息长度
void AppendLength(std::vector<uint8_t> &message, uint64_t originalBitLength)
{
    for (int i = 0; i < 8; ++i)
    {
        message.push_back(static_cast<uint8_t>(originalBitLength & 0xFF));
        originalBitLength >>= 8;
    }
}
//step3初始化哈希数值
struct MD5Context
{
    uint32_t A = 0x67452301;
    uint32_t B = 0xefcdab89;
    uint32_t C = 0x98badcfe;
    uint32_t D = 0x10325476;
};
//step4压缩
uint32_t F(uint32_t X, uint32_t Y, uint32_t Z)
{
    return (X & Y) | (~X & Z);
}
uint32_t G(uint32_t X, uint32_t Y, uint32_t Z)
{
    return (X & Z) | (Y & ~Z);
}
uint32_t H(uint32_t X, uint32_t Y, uint32_t Z)
{
    return X ^ Y ^ Z;
}
uint32_t I(uint32_t X, uint32_t Y, uint32_t Z)
{
    return Y ^ (X | ~Z);
}
const uint32_t T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
const uint32_t s[4][4] = {
    {7, 12, 17, 22},
    {5, 9, 14, 20},
    {4, 11, 16, 23},
    {6, 10, 15, 21}};
const uint32_t k[4][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12},
    {5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2},
    {0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9}};
void ProcessMessageBlocks(MD5Context &ctx, const uint8_t block[64])
{
    //a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
    uint32_t X[16];
    for (int i = 0; i < 16; ++i)
    {//小端法 倒序 每32位4字节为单位
        X[i] = block[i * 4] | (block[i * 4 + 1] << 8) | (block[i * 4 + 2] << 16) | (block[i * 4 + 3] << 24);
    }
    uint32_t AA = ctx.A, BB = ctx.B, CC = ctx.C, DD = ctx.D;
    auto Round = [&](int round, uint32_t (&func)(uint32_t, uint32_t, uint32_t)) {
        for (int i = 0; i < 16; ++i)
        {
            uint32_t temp = AA + func(BB, CC, DD) + X[k[round][i]] + T[round * 16 + i];
            temp = RotateLeft(temp, s[round][i % 4]);
            temp += BB;
            AA = DD;
            DD = CC;
            CC = BB;
            BB = temp;//循环右移 ABCD DABC CDAB BCDA
        }
    };
    //四轮压缩
    Round(0, F);
    Round(1, G);
    Round(2, H);
    Round(3, I);
    ctx.A += AA;
    ctx.B += BB;
    ctx.C += CC;
    ctx.D += DD;
}
void MD5Hash(const std::vector<uint8_t> input, uint8_t digest[16])
{
    std::vector<uint8_t> msg = input;
    uint64_t bitlen = msg.size() * 8;//比特数
    AppendPadding(msg);//填充比特
    AppendLength(msg, bitlen);//附加原始消息长度
    MD5Context ctx;//哈希值结构体
    for (size_t i = 0; i < msg.size(); i += 64)//按块512bit，64字节为处理单位
        ProcessMessageBlocks(ctx, msg.data() + i);//压缩
    uint32_t *p = (uint32_t *)digest;
    p[0] = ctx.A;
    p[1] = ctx.B;
    p[2] = ctx.C;
    p[3] = ctx.D;
}
int main()
{
    std::ifstream in("C:/Users/10497/Documents/InternetSecurity/input.txt", std::ios::binary);
    //std::istreambuf_iterator<char>流缓冲区迭代器，以字节为单位
    //std::istreambuf_iterator<char>(in)起始迭代器，std::istreambuf_iterator<char>()结束迭代器，相当于EOF
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    uint8_t digest[16];//16个字节，MD5结果
    MD5Hash(data, digest);
    std::cout << "MD5: ";
    for (int i = 0; i < 16; ++i)
        printf("%02x", digest[i]);
    return 0;
}
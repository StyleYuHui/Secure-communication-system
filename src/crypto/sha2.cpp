//
// Created by PaperPlane on 2025/6/7.
//
// sha256.cpp
#include <crypto/sha256.h>

#include <iostream>
#include <vector>
#include <bitset>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdint>

using namespace std;

// 循环右移
auto ROTR = [](bitset<32> x, int n) {
    return (x >> n) | (x << (32 - n));
};

// 逻辑右移
auto SHR = [](bitset<32> x, int n) {
    return x >> n;
};

// SHA-256辅助函数
auto Ch = [](bitset<32> x, bitset<32> y, bitset<32> z) {
    return (x & y) ^ (~x & z);
};

auto Maj = [](bitset<32> x, bitset<32> y, bitset<32> z) {
    return (x & y) ^ (x & z) ^ (y & z);
};

auto Sigma0 = [](bitset<32> x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
};

auto Sigma1 = [](bitset<32> x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
};

auto sigma0 = [](bitset<32> x) {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
};

auto sigma1 = [](bitset<32> x) {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
};

// 模2^32加法
auto add = [](bitset<32> a, bitset<32> b) {
    unsigned long sum = a.to_ulong() + b.to_ulong();
    return bitset<32>(sum);
};

// 多个32位加法
auto add_multi = [](vector<bitset<32>> nums) {
    unsigned long sum = 0;
    for (auto& num : nums) {
        sum += num.to_ulong();
    }
    return bitset<32>(sum);
};

// SHA-256常量定义
const vector<bitset<32>> K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const vector<bitset<32>> H_init = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// SHA-256主函数
string sha256(const string& input) {
    // 1. 消息填充
    vector<uint8_t> bytes(input.begin(), input.end());
    uint64_t bit_len = bytes.size() * 8;
    bytes.push_back(0x80);
    while ((bytes.size() * 8) % 512 != 448) {
        bytes.push_back(0x00);
    }
    for (int i = 7; i >= 0; --i) {
        bytes.push_back((bit_len >> (i * 8)) & 0xFF);
    }

    // 2. 分块处理
    vector<vector<bitset<32>>> blocks;
    for (size_t i = 0; i < bytes.size(); i += 64) {
        vector<bitset<32>> block;
        for (int j = 0; j < 16; ++j) {
            uint32_t word = 0;
            for (int k = 0; k < 4; ++k) {
                if (i + j * 4 + k < bytes.size()) {
                    word = (word << 8) | bytes[i + j * 4 + k];
                }
            }
            block.push_back(bitset<32>(word));
        }
        blocks.push_back(block);
    }

    // 3. 哈希计算
    vector<bitset<32>> H = H_init;
    for (auto& block : blocks) {
        // 消息扩展
        vector<bitset<32>> W(64);
        for (int t = 0; t < 16; ++t) {
            W[t] = block[t];
        }
        for (int t = 16; t < 64; ++t) {
            W[t] = add_multi({sigma1(W[t - 2]), W[t - 7], sigma0(W[t - 15]), W[t - 16]});
        }

        // 初始化工作变量
        bitset<32> a = H[0];
        bitset<32> b = H[1];
        bitset<32> c = H[2];
        bitset<32> d = H[3];
        bitset<32> e = H[4];
        bitset<32> f = H[5];
        bitset<32> g = H[6];
        bitset<32> h = H[7];

        // 压缩函数
        for (int t = 0; t < 64; ++t) {
            bitset<32> T1 = add_multi({h, Sigma1(e), Ch(e, f, g), K[t], W[t]});
            bitset<32> T2 = add(Sigma0(a), Maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = add(d, T1);
            d = c;
            c = b;
            b = a;
            a = add(T1, T2);
        }

        // 更新哈希值
        H[0] = add(H[0], a);
        H[1] = add(H[1], b);
        H[2] = add(H[2], c);
        H[3] = add(H[3], d);
        H[4] = add(H[4], e);
        H[5] = add(H[5], f);
        H[6] = add(H[6], g);
        H[7] = add(H[7], h);
    }

    // 4. 生成最终哈希值
    stringstream ss;
    for (auto& h : H) {
        ss << hex << setfill('0') << setw(8) << h.to_ulong();
    }
    return ss.str();
}

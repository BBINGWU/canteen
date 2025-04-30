#pragma once
#include <emp-tool/emp-tool.h>
std::vector<emp::Bit> ripemd160(const std::vector<emp::Bit> &input_bits);

#include <emp-tool/emp-tool.h>
using namespace emp;
using std::vector;

typedef Integer dword;

inline dword F(const dword &x, const dword &y, const dword &z) { return x ^ y ^ z; }
// inline dword G(const dword &x, const dword &y, const dword &z) { return (x & y) | (~x & z); }
// inline dword H(const dword &x, const dword &y, const dword &z) { return (x | ~y) ^ z; }
// inline dword I(const dword &x, const dword &y, const dword &z) { return (x & z) | (y & ~z); }
// inline dword J(const dword &x, const dword &y, const dword &z) { return x ^ (y | ~z); }
inline dword G(const dword &x, const dword &y, const dword &z) {
    dword notx = x ^ Integer(x.size(), -1, PUBLIC);
    return (x & y) | (notx & z);
}

inline dword H(const dword &x, const dword &y, const dword &z) {
    dword noty = y ^ Integer(y.size(), -1, PUBLIC);
    return (x | noty) ^ z;
}

inline dword I(const dword &x, const dword &y, const dword &z) {
    dword notz = z ^ Integer(z.size(), -1, PUBLIC);
    return (x & z) | (y & notz);
}

inline dword J(const dword &x, const dword &y, const dword &z) {
    dword notz = z ^ Integer(z.size(), -1, PUBLIC);
    return x ^ (y | notz);
}



inline dword ROL(const dword &x, int n) { return (x << n) | (x >> (32 - n)); }

inline void FF(dword &a, dword &b, dword &c, dword &d, dword &e, const dword &x, int s) {
    a = a + F(b, c, d) + x;
    a = ROL(a, s) + e;
    c = ROL(c, 10);
}
inline void GG(dword &a, dword &b, dword &c, dword &d, dword &e, const dword &x, int s) {
    a = a + G(b, c, d) + x + Integer(32, 0x5a827999, PUBLIC);
    a = ROL(a, s) + e;
    c = ROL(c, 10);
}
inline void HH(dword &a, dword &b, dword &c, dword &d, dword &e, const dword &x, int s) {
    a = a + H(b, c, d) + x + Integer(32, 0x6ed9eba1, PUBLIC);
    a = ROL(a, s) + e;
    c = ROL(c, 10);
}
inline void II(dword &a, dword &b, dword &c, dword &d, dword &e, const dword &x, int s) {
    a = a + I(b, c, d) + x + Integer(32, 0x8f1bbcdc, PUBLIC);
    a = ROL(a, s) + e;
    c = ROL(c, 10);
}
inline void JJ(dword &a, dword &b, dword &c, dword &d, dword &e, const dword &x, int s) {
    a = a + J(b, c, d) + x + Integer(32, 0xa953fd4e, PUBLIC);
    a = ROL(a, s) + e;
    c = ROL(c, 10);
}

inline void FFF(dword &a, dword &b, dword &c, dword &d, dword &e, const dword &x, int s) {
    a = a + F(b, c, d) + x;
    a = ROL(a, s) + e;
    c = ROL(c, 10);
}
inline void GGG(dword &a, dword &b, dword &c, dword &d, dword &e, const dword &x, int s) {
    a = a + G(b, c, d) + x + Integer(32, 0x7a6d76e9, PUBLIC);
    a = ROL(a, s) + e;
    c = ROL(c, 10);
}
inline void HHH(dword &a, dword &b, dword &c, dword &d, dword &e, const dword &x, int s) {
    a = a + H(b, c, d) + x + Integer(32, 0x6d703ef3, PUBLIC);
    a = ROL(a, s) + e;
    c = ROL(c, 10);
}
inline void III(dword &a, dword &b, dword &c, dword &d, dword &e, const dword &x, int s) {
    a = a + I(b, c, d) + x + Integer(32, 0x5c4dd124, PUBLIC);
    a = ROL(a, s) + e;
    c = ROL(c, 10);
}
inline void JJJ(dword &a, dword &b, dword &c, dword &d, dword &e, const dword &x, int s) {
    a = a + J(b, c, d) + x + Integer(32, 0x50a28be6, PUBLIC);
    a = ROL(a, s) + e;
    c = ROL(c, 10);
}

void MDinit(dword MDbuf[5]) {
    MDbuf[0] = Integer(32, 0x67452301, PUBLIC);
    MDbuf[1] = Integer(32, 0xefcdab89, PUBLIC);
    MDbuf[2] = Integer(32, 0x98badcfe, PUBLIC);
    MDbuf[3] = Integer(32, 0x10325476, PUBLIC);
    MDbuf[4] = Integer(32, 0xc3d2e1f0, PUBLIC);
}

void compress(dword MDbuf[5], dword X[16]) {
    dword aa = MDbuf[0], bb = MDbuf[1], cc = MDbuf[2], dd = MDbuf[3], ee = MDbuf[4];
    dword aaa = MDbuf[0], bbb = MDbuf[1], ccc = MDbuf[2], ddd = MDbuf[3], eee = MDbuf[4];

    // Round 1
    FF(aa, bb, cc, dd, ee, X[ 0], 11);
    FF(ee, aa, bb, cc, dd, X[ 1], 14);
    FF(dd, ee, aa, bb, cc, X[ 2], 15);
    FF(cc, dd, ee, aa, bb, X[ 3], 12);
    FF(bb, cc, dd, ee, aa, X[ 4], 5);
    FF(aa, bb, cc, dd, ee, X[ 5], 8);
    FF(ee, aa, bb, cc, dd, X[ 6], 7);
    FF(dd, ee, aa, bb, cc, X[ 7], 9);
    FF(cc, dd, ee, aa, bb, X[ 8], 11);
    FF(bb, cc, dd, ee, aa, X[ 9], 13);
    FF(aa, bb, cc, dd, ee, X[10], 14);
    FF(ee, aa, bb, cc, dd, X[11], 15);
    FF(dd, ee, aa, bb, cc, X[12], 6);
    FF(cc, dd, ee, aa, bb, X[13], 7);
    FF(bb, cc, dd, ee, aa, X[14], 9);
    FF(aa, bb, cc, dd, ee, X[15], 8);

    // Round 2
    GG(ee, aa, bb, cc, dd, X[ 7], 7);
    GG(dd, ee, aa, bb, cc, X[ 4], 6);
    GG(cc, dd, ee, aa, bb, X[13], 8);
    GG(bb, cc, dd, ee, aa, X[ 1], 13);
    GG(aa, bb, cc, dd, ee, X[10], 11);
    GG(ee, aa, bb, cc, dd, X[ 6], 9);
    GG(dd, ee, aa, bb, cc, X[15], 7);
    GG(cc, dd, ee, aa, bb, X[ 3], 15);
    GG(bb, cc, dd, ee, aa, X[12], 7);
    GG(aa, bb, cc, dd, ee, X[ 0], 12);
    GG(ee, aa, bb, cc, dd, X[ 9], 15);
    GG(dd, ee, aa, bb, cc, X[ 5], 9);
    GG(cc, dd, ee, aa, bb, X[ 2], 11);
    GG(bb, cc, dd, ee, aa, X[14], 7);
    GG(aa, bb, cc, dd, ee, X[11], 13);
    GG(ee, aa, bb, cc, dd, X[ 8], 12);

    // Round 3
    HH(dd, ee, aa, bb, cc, X[ 3], 11);
    HH(cc, dd, ee, aa, bb, X[10], 13);
    HH(bb, cc, dd, ee, aa, X[14], 6);
    HH(aa, bb, cc, dd, ee, X[ 4], 7);
    HH(ee, aa, bb, cc, dd, X[ 9], 14);
    HH(dd, ee, aa, bb, cc, X[15], 9);
    HH(cc, dd, ee, aa, bb, X[ 8], 13);
    HH(bb, cc, dd, ee, aa, X[ 1], 15);
    HH(aa, bb, cc, dd, ee, X[ 2], 14);
    HH(ee, aa, bb, cc, dd, X[ 7], 8);
    HH(dd, ee, aa, bb, cc, X[ 0], 13);
    HH(cc, dd, ee, aa, bb, X[ 6], 6);
    HH(bb, cc, dd, ee, aa, X[13], 5);
    HH(aa, bb, cc, dd, ee, X[11], 12);
    HH(ee, aa, bb, cc, dd, X[ 5], 7);
    HH(dd, ee, aa, bb, cc, X[12], 5);

    // Round 4
    II(cc, dd, ee, aa, bb, X[ 1], 11);
    II(bb, cc, dd, ee, aa, X[ 9], 12);
    II(aa, bb, cc, dd, ee, X[11], 14);
    II(ee, aa, bb, cc, dd, X[10], 15);
    II(dd, ee, aa, bb, cc, X[ 0], 14);
    II(cc, dd, ee, aa, bb, X[ 8], 15);
    II(bb, cc, dd, ee, aa, X[12], 9);
    II(aa, bb, cc, dd, ee, X[ 4], 8);
    II(ee, aa, bb, cc, dd, X[13], 9);
    II(dd, ee, aa, bb, cc, X[ 3], 14);
    II(cc, dd, ee, aa, bb, X[ 7], 5);
    II(bb, cc, dd, ee, aa, X[15], 6);
    II(aa, bb, cc, dd, ee, X[14], 8);
    II(ee, aa, bb, cc, dd, X[ 5], 6);
    II(dd, ee, aa, bb, cc, X[ 6], 5);
    II(cc, dd, ee, aa, bb, X[ 2], 12);

    // Round 5
    JJ(bb, cc, dd, ee, aa, X[ 4], 9);
    JJ(aa, bb, cc, dd, ee, X[ 0], 15);
    JJ(ee, aa, bb, cc, dd, X[ 5], 5);
    JJ(dd, ee, aa, bb, cc, X[ 9], 11);
    JJ(cc, dd, ee, aa, bb, X[ 7], 6);
    JJ(bb, cc, dd, ee, aa, X[12], 8);
    JJ(aa, bb, cc, dd, ee, X[ 2], 13);
    JJ(ee, aa, bb, cc, dd, X[10], 12);
    JJ(dd, ee, aa, bb, cc, X[14], 5);
    JJ(cc, dd, ee, aa, bb, X[ 1], 12);
    JJ(bb, cc, dd, ee, aa, X[ 3], 13);
    JJ(aa, bb, cc, dd, ee, X[ 8], 14);
    JJ(ee, aa, bb, cc, dd, X[11], 11);
    JJ(dd, ee, aa, bb, cc, X[ 6], 8);
    JJ(cc, dd, ee, aa, bb, X[15], 5);
    JJ(bb, cc, dd, ee, aa, X[13], 6);

    // Parallel Round 1
    JJJ(aaa, bbb, ccc, ddd, eee, X[ 5], 8);
    JJJ(eee, aaa, bbb, ccc, ddd, X[14], 9);
    JJJ(ddd, eee, aaa, bbb, ccc, X[ 7], 9);
    JJJ(ccc, ddd, eee, aaa, bbb, X[ 0], 11);
    JJJ(bbb, ccc, ddd, eee, aaa, X[ 9], 13);
    JJJ(aaa, bbb, ccc, ddd, eee, X[ 2], 15);
    JJJ(eee, aaa, bbb, ccc, ddd, X[11], 15);
    JJJ(ddd, eee, aaa, bbb, ccc, X[ 4], 5);
    JJJ(ccc, ddd, eee, aaa, bbb, X[13], 7);
    JJJ(bbb, ccc, ddd, eee, aaa, X[ 6], 7);
    JJJ(aaa, bbb, ccc, ddd, eee, X[15], 8);
    JJJ(eee, aaa, bbb, ccc, ddd, X[ 8], 11);
    JJJ(ddd, eee, aaa, bbb, ccc, X[ 1], 14);
    JJJ(ccc, ddd, eee, aaa, bbb, X[10], 14);
    JJJ(bbb, ccc, ddd, eee, aaa, X[ 3], 12);
    JJJ(aaa, bbb, ccc, ddd, eee, X[12], 6);

    // Parallel Round 2
    III(eee, aaa, bbb, ccc, ddd, X[ 6], 9);
    III(ddd, eee, aaa, bbb, ccc, X[11], 13);
    III(ccc, ddd, eee, aaa, bbb, X[ 3], 15);
    III(bbb, ccc, ddd, eee, aaa, X[ 7], 7);
    III(aaa, bbb, ccc, ddd, eee, X[ 0], 12);
    III(eee, aaa, bbb, ccc, ddd, X[13], 8);
    III(ddd, eee, aaa, bbb, ccc, X[ 5], 9);
    III(ccc, ddd, eee, aaa, bbb, X[10], 11);
    III(bbb, ccc, ddd, eee, aaa, X[14], 7);
    III(aaa, bbb, ccc, ddd, eee, X[15], 7);
    III(eee, aaa, bbb, ccc, ddd, X[ 8], 12);
    III(ddd, eee, aaa, bbb, ccc, X[12], 7);
    III(ccc, ddd, eee, aaa, bbb, X[ 4], 6);
    III(bbb, ccc, ddd, eee, aaa, X[ 9], 15);
    III(aaa, bbb, ccc, ddd, eee, X[ 1], 13);
    III(eee, aaa, bbb, ccc, ddd, X[ 2], 11);

    // Parallel Round 3
    HHH(ddd, eee, aaa, bbb, ccc, X[15], 9);
    HHH(ccc, ddd, eee, aaa, bbb, X[ 5], 7);
    HHH(bbb, ccc, ddd, eee, aaa, X[ 1], 15);
    HHH(aaa, bbb, ccc, ddd, eee, X[ 3], 11);
    HHH(eee, aaa, bbb, ccc, ddd, X[ 7], 8);
    HHH(ddd, eee, aaa, bbb, ccc, X[14], 6);
    HHH(ccc, ddd, eee, aaa, bbb, X[ 6], 6);
    HHH(bbb, ccc, ddd, eee, aaa, X[ 9], 14);
    HHH(aaa, bbb, ccc, ddd, eee, X[11], 12);
    HHH(eee, aaa, bbb, ccc, ddd, X[ 8], 13);
    HHH(ddd, eee, aaa, bbb, ccc, X[12], 5);
    HHH(ccc, ddd, eee, aaa, bbb, X[ 2], 14);
    HHH(bbb, ccc, ddd, eee, aaa, X[10], 13);
    HHH(aaa, bbb, ccc, ddd, eee, X[ 0], 13);
    HHH(eee, aaa, bbb, ccc, ddd, X[ 4], 7);
    HHH(ddd, eee, aaa, bbb, ccc, X[13], 5);

    // Parallel Round 4
    GGG(ccc, ddd, eee, aaa, bbb, X[ 8], 15);
    GGG(bbb, ccc, ddd, eee, aaa, X[ 6], 5);
    GGG(aaa, bbb, ccc, ddd, eee, X[ 4], 8);
    GGG(eee, aaa, bbb, ccc, ddd, X[ 1], 11);
    GGG(ddd, eee, aaa, bbb, ccc, X[ 3], 14);
    GGG(ccc, ddd, eee, aaa, bbb, X[11], 14);
    GGG(bbb, ccc, ddd, eee, aaa, X[15], 6);
    GGG(aaa, bbb, ccc, ddd, eee, X[ 0], 14);
    GGG(eee, aaa, bbb, ccc, ddd, X[ 5], 6);
    GGG(ddd, eee, aaa, bbb, ccc, X[12], 9);
    GGG(ccc, ddd, eee, aaa, bbb, X[ 2], 12);
    GGG(bbb, ccc, ddd, eee, aaa, X[13], 9);
    GGG(aaa, bbb, ccc, ddd, eee, X[ 9], 12);
    GGG(eee, aaa, bbb, ccc, ddd, X[ 7], 5);
    GGG(ddd, eee, aaa, bbb, ccc, X[10], 15);
    GGG(ccc, ddd, eee, aaa, bbb, X[14], 8);

    // Parallel Round 5
    FFF(bbb, ccc, ddd, eee, aaa, X[12], 8);
    FFF(aaa, bbb, ccc, ddd, eee, X[15], 5);
    FFF(eee, aaa, bbb, ccc, ddd, X[10], 12);
    FFF(ddd, eee, aaa, bbb, ccc, X[ 4], 9);
    FFF(ccc, ddd, eee, aaa, bbb, X[ 1], 12);
    FFF(bbb, ccc, ddd, eee, aaa, X[ 5], 5);
    FFF(aaa, bbb, ccc, ddd, eee, X[ 8], 14);
    FFF(eee, aaa, bbb, ccc, ddd, X[ 7], 6);
    FFF(ddd, eee, aaa, bbb, ccc, X[ 6], 8);
    FFF(ccc, ddd, eee, aaa, bbb, X[ 2], 13);
    FFF(bbb, ccc, ddd, eee, aaa, X[13], 6);
    FFF(aaa, bbb, ccc, ddd, eee, X[14], 5);
    FFF(eee, aaa, bbb, ccc, ddd, X[ 0], 15);
    FFF(ddd, eee, aaa, bbb, ccc, X[ 3], 13);
    FFF(ccc, ddd, eee, aaa, bbb, X[ 9], 11);
    FFF(bbb, ccc, ddd, eee, aaa, X[11], 11);

    // Combine final results
    ddd = ddd + cc + MDbuf[1];
    MDbuf[1] = MDbuf[2] + dd + eee;
    MDbuf[2] = MDbuf[3] + ee + aaa;
    MDbuf[3] = MDbuf[4] + aa + bbb;
    MDbuf[4] = MDbuf[0] + bb + ccc;
    MDbuf[0] = ddd;
}


// 工具函数：把 input bits 转成 dword数组
void bits_to_words(vector<Bit> input, dword X[16]) {
    for (int i = 0; i < 16; ++i) {
        X[i] = Integer(32, 0, PUBLIC);
        for (int j = 0; j < 32; ++j) {
            if (i*32 + j < input.size()) {
                X[i][j] = input[i*32 + j];
            }
        }
    }
}

// 工具函数：把5个MDbuf拼成160比特
vector<Bit> MDbuf_to_bits(dword MDbuf[5]) {
    vector<Bit> res;
    for (int i = 0; i < 5; ++i) {
        for (int j = 0; j < 32; ++j) {
            res.push_back(MDbuf[i][j]);
        }
    }
    return res;
}

// 主接口：RIPEMD-160 哈希，输入bit数组
vector<Bit> ripemd160(const vector<Bit> &input_bits) {
    dword MDbuf[5];
    MDinit(MDbuf);

    dword X[16];
    bits_to_words(input_bits, X);

    compress(MDbuf, X);

    return MDbuf_to_bits(MDbuf);
}

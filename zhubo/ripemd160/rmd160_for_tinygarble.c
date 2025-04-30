#include <stdint.h>
#include <string.h>

typedef uint8_t byte;
typedef uint32_t dword;

// 输入64字节
byte __input__ input[64];

// 输出4个dword（128位）
dword __output__ hash[4];

dword ROL(dword x, int n) {
    return (x << n) | (x >> (32 - n));
}

dword F(dword x, dword y, dword z) {
    return x ^ y ^ z;
}

dword G(dword x, dword y, dword z) {
    return (x & y) | (~x & z);
}

dword H(dword x, dword y, dword z) {
    return (x | ~y) ^ z;
}

dword I(dword x, dword y, dword z) {
    return (x & z) | (y & ~z);
}

void FF(dword *a, dword b, dword c, dword d, dword x, int s) {
    *a += F(b, c, d) + x;
    *a = ROL(*a, s);
}

void GG(dword *a, dword b, dword c, dword d, dword x, int s) {
    *a += G(b, c, d) + x + 0x5a827999UL;
    *a = ROL(*a, s);
}

void HH(dword *a, dword b, dword c, dword d, dword x, int s) {
    *a += H(b, c, d) + x + 0x6ed9eba1UL;
    *a = ROL(*a, s);
}

void II(dword *a, dword b, dword c, dword d, dword x, int s) {
    *a += I(b, c, d) + x + 0x8f1bbcdcUL;
    *a = ROL(*a, s);
}

void MDinit(dword *MDbuf) {
    MDbuf[0] = 0x67452301UL;
    MDbuf[1] = 0xefcdab89UL;
    MDbuf[2] = 0x98badcfeUL;
    MDbuf[3] = 0x10325476UL;
}

void compress(dword *MDbuf, dword *X) {
    dword aa = MDbuf[0], bb = MDbuf[1], cc = MDbuf[2], dd = MDbuf[3];
    dword aaa = MDbuf[0], bbb = MDbuf[1], ccc = MDbuf[2], ddd = MDbuf[3];

    // 只写round 1，完整的你有了就继续

    // round 1
    FF(&aa, bb, cc, dd, X[0], 11);
    FF(&dd, aa, bb, cc, X[1], 14);
    FF(&cc, dd, aa, bb, X[2], 15);
    FF(&bb, cc, dd, aa, X[3], 12);
    // … 后面继续你的轮数

    ddd += cc + MDbuf[1];
    MDbuf[1] = MDbuf[2] + dd + aaa;
    MDbuf[2] = MDbuf[3] + aa + bbb;
    MDbuf[3] = MDbuf[0] + bb + ccc;
    MDbuf[0] = ddd;
}

void mpc_main() {
    dword X[16];
    memset(X, 0, sizeof(X));

    for (int i = 0; i < 64; ++i) {
        X[i >> 2] ^= (dword)input[i] << (8 * (i & 3));
    }

    MDinit(hash);
    compress(hash, X);
}


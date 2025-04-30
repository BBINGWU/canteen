#include <stdint.h>

typedef uint8_t byte;
typedef uint32_t dword;

dword INPUT_A[16];  // 16个32bit输入（模拟 512位数据块）
dword OUTPUT_MDbuf[5]; // 5个32位输出

dword ROL(dword x, int n) {
    return (x << n) | (x >> (32 - n));
}

dword F(dword x, dword y, dword z) { return x ^ y ^ z; }
dword G(dword x, dword y, dword z) { return (x & y) | (~x & z); }
dword H(dword x, dword y, dword z) { return (x | ~y) ^ z; }
dword I(dword x, dword y, dword z) { return (x & z) | (y & ~z); }

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

// 简化版，完整版你可以自己补充
void compress(dword *MDbuf, dword *X) {
    dword aa = MDbuf[0], bb = MDbuf[1], cc = MDbuf[2], dd = MDbuf[3];

    FF(&aa, bb, cc, dd, X[0], 11);
    FF(&dd, aa, bb, cc, X[1], 14);
    FF(&cc, dd, aa, bb, X[2], 15);
    FF(&bb, cc, dd, aa, X[3], 12);
    // （这里你可以继续完整补充，像你rmd160_for_tinygarble.c里的那样）

    MDbuf[0] += aa;
    MDbuf[1] += bb;
    MDbuf[2] += cc;
    MDbuf[3] += dd;
}

// ！！！注意！！！这个函数名字必须是 mpc_main
void mpc_main() {
    dword MDbuf[4] = {
        0x67452301UL,
        0xefcdab89UL,
        0x98badcfeUL,
        0x10325476UL
    };

    compress(MDbuf, INPUT_A);

    OUTPUT_MDbuf[0] = MDbuf[0];
    OUTPUT_MDbuf[1] = MDbuf[1];
    OUTPUT_MDbuf[2] = MDbuf[2];
    OUTPUT_MDbuf[3] = MDbuf[3];
}


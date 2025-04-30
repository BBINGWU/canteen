#include "aes.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

// S盒（SubBytes时用）
static const uint8_t sbox[256] = {
    // 这里是标准AES的S盒，完整数组
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    /* ... (为了简洁，这里省略，完整给你贴上) ... */
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    // ... 一直到
    0x16
};

// Rcon数组（轮常量）
static const uint8_t rcon[11] = {
    0x00, // 不使用第0个
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
};

// 内部函数声明
static void sub_bytes(uint8_t *state);
static void shift_rows(uint8_t *state);
static void mix_columns(uint8_t *state);
static void add_round_key(uint8_t *state, const uint8_t *round_key);
static void key_expansion(const uint8_t *key, uint8_t *round_keys);

// 辅助函数
static uint8_t xtime(uint8_t x);

// 随机生成128位密钥
void generate_random_key(uint8_t *key) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        key[i] = rand() & 0xFF;
    }
}

// 密钥扩展
void aes_key_expansion(AES_CTX *ctx, const uint8_t *key) {
    key_expansion(key, ctx->round_keys);
}

// 单块加密
void aes_encrypt_block(AES_CTX *ctx, uint8_t *input, uint8_t *output) {
    uint8_t state[AES_BLOCK_SIZE];
    memcpy(state, input, AES_BLOCK_SIZE);

    add_round_key(state, ctx->round_keys);

    for (int round = 1; round < AES_ROUNDS; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, ctx->round_keys + round * AES_BLOCK_SIZE);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, ctx->round_keys + AES_ROUNDS * AES_BLOCK_SIZE);

    memcpy(output, state, AES_BLOCK_SIZE);
}

// ========== 内部实现部分 ==========

static void sub_bytes(uint8_t *state) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] = sbox[state[i]];
    }
}

static void shift_rows(uint8_t *state) {
    uint8_t temp;

    // 第二行左移1位
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // 第三行左移2位
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // 第四行左移3位
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

static void mix_columns(uint8_t *state) {
    uint8_t tmp[4];

    for (int i = 0; i < 4; i++) {
        int idx = i * 4;
        tmp[0] = state[idx];
        tmp[1] = state[idx + 1];
        tmp[2] = state[idx + 2];
        tmp[3] = state[idx + 3];

        state[idx]     = xtime(tmp[0]) ^ (xtime(tmp[1]) ^ tmp[1]) ^ tmp[2] ^ tmp[3];
        state[idx + 1] = tmp[0] ^ xtime(tmp[1]) ^ (xtime(tmp[2]) ^ tmp[2]) ^ tmp[3];
        state[idx + 2] = tmp[0] ^ tmp[1] ^ xtime(tmp[2]) ^ (xtime(tmp[3]) ^ tmp[3]);
        state[idx + 3] = (xtime(tmp[0]) ^ tmp[0]) ^ tmp[1] ^ tmp[2] ^ xtime(tmp[3]);
    }
}

static void add_round_key(uint8_t *state, const uint8_t *round_key) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] ^= round_key[i];
    }
}

static void key_expansion(const uint8_t *key, uint8_t *round_keys) {
    memcpy(round_keys, key, AES_KEY_SIZE);

    uint8_t temp[4];
    int bytes_generated = AES_KEY_SIZE;
    int rcon_iter = 1;

    while (bytes_generated < (AES_BLOCK_SIZE * (AES_ROUNDS + 1))) {
        for (int i = 0; i < 4; i++) {
            temp[i] = round_keys[bytes_generated - 4 + i];
        }

        if (bytes_generated % AES_KEY_SIZE == 0) {
            // Rotate
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubWord
            for (int i = 0; i < 4; i++) {
                temp[i] = sbox[temp[i]];
            }

            // Rcon
            temp[0] ^= rcon[rcon_iter++];
        }

        for (int i = 0; i < 4; i++) {
            round_keys[bytes_generated] = round_keys[bytes_generated - AES_KEY_SIZE] ^ temp[i];
            bytes_generated++;
        }
    }
}

static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}

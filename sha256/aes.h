#ifndef AES_H
#define AES_H

#include <stdint.h>

// AES-128参数
#define AES_BLOCK_SIZE 16  // 16字节 = 128位
#define AES_KEY_SIZE   16
#define AES_ROUNDS     10

// AES上下文结构体
typedef struct {
    uint8_t round_keys[(AES_ROUNDS + 1) * AES_BLOCK_SIZE];
} AES_CTX;

// 接口函数
void aes_key_expansion(AES_CTX *ctx, const uint8_t *key);
void aes_encrypt_block(AES_CTX *ctx, uint8_t *input, uint8_t *output);

// 生成随机密钥（简单版，真实项目建议用更安全的随机数）
void generate_random_key(uint8_t *key);

#endif // AES_H

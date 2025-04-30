#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "aes.h"
#include "sha256.h"
#include "ripemd160.h"
#include "compound_hash.h"

#define TEST_ROUNDS 50

// 辅助函数：打印字节数组
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main() {
    // AES相关变量
    uint8_t plaintext[AES_BLOCK_SIZE] = {0};  // 16字节全0
    uint8_t ciphertext[AES_BLOCK_SIZE];
    uint8_t key[AES_KEY_SIZE];
    AES_CTX aes_ctx;

    // 复合哈希相关变量
    uint8_t hash_input[64] = {0};  // 输入64字节，可以自定义大小
    uint8_t compound_output[COMPOUND_HASH_DIGEST_LENGTH];

    clock_t start, end;
    double aes_total_time = 0.0;
    double hash_total_time = 0.0;

    // 生成随机AES密钥
    generate_random_key(key);
    aes_key_expansion(&aes_ctx, key);

    // 测AES加密的时间
    for (int i = 0; i < TEST_ROUNDS; i++) {
        start = clock();
        aes_encrypt_block(&aes_ctx, plaintext, ciphertext);
        end = clock();
        aes_total_time += (double)(end - start) / CLOCKS_PER_SEC;
    }

    // 测复合哈希的时间
    for (int i = 0; i < TEST_ROUNDS; i++) {
        start = clock();
        compound_hash(hash_input, sizeof(hash_input), compound_output);
        end = clock();
        hash_total_time += (double)(end - start) / CLOCKS_PER_SEC;
    }

    printf("======= 测试结果 =======\n");

    print_hex("AES随机密钥", key, AES_KEY_SIZE);
    print_hex("AES加密输出", ciphertext, AES_BLOCK_SIZE);

    print_hex("复合哈希输出", compound_output, COMPOUND_HASH_DIGEST_LENGTH);

    printf("\nAES加密平均耗时:     %.6f 秒\n", aes_total_time / TEST_ROUNDS);
    printf("复合哈希平均耗时:    %.6f 秒\n", hash_total_time / TEST_ROUNDS);

    return 0;
}

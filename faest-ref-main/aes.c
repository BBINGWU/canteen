/*
 *  SPDX-License-Identifier: MIT
 */

// sha256
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>     // 加这个，为了 printf()
#include <time.h>      // 加这个，为了 clock()

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[64];
} SHA256_CTX;

/* SHA-256 constants */
static const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SIG0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define SIG1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define sig0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define sig1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[64]) {
  uint32_t W[64], a,b,c,d,e,f,g,h,T1,T2;
  for(int i=0;i<16;i++) {
      W[i] = (data[4*i]<<24) | (data[4*i+1]<<16) | (data[4*i+2]<<8) | (data[4*i+3]);
  }
  for(int i=16;i<64;i++) {
      W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];
  }
  a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
  e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
  for(int i=0;i<64;i++) {
      T1 = h + SIG1(e) + CH(e,f,g) + K[i] + W[i];
      T2 = SIG0(a) + MAJ(a,b,c);
      h=g; g=f; f=e; e=d+T1;
      d=c; c=b; b=a; a=T1+T2;
  }
  ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
  ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

void SHA256_Init(SHA256_CTX *ctx) {
  ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
  ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
  ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
  ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
  ctx->bitcount=0; memset(ctx->buffer,0,64);
}

void SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len) {
  size_t i,j;
  j = (ctx->bitcount>>3) % 64;
  ctx->bitcount += (uint64_t)len<<3;
  for(i=0;i<len;i++) {
      ctx->buffer[j++] = ((const uint8_t*)data)[i];
      if(j==64) { sha256_transform(ctx, ctx->buffer); j=0; }
  }
}

void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx) {
  uint8_t bits[8];
  for(int i=0;i<8;i++) bits[7-i] = ctx->bitcount >> (i*8);
  size_t idx = (ctx->bitcount>>3) % 64;
  ctx->buffer[idx++] = 0x80;
  if(idx>56) { while(idx<64) ctx->buffer[idx++]=0; sha256_transform(ctx,ctx->buffer); idx=0; }
  while(idx<56) ctx->buffer[idx++]=0;
  memcpy(ctx->buffer+56,bits,8);
  sha256_transform(ctx,ctx->buffer);
  for(int i=0;i<8;i++) {
      digest[4*i]   = (ctx->state[i]>>24)&0xff;
      digest[4*i+1] = (ctx->state[i]>>16)&0xff;
      digest[4*i+2] = (ctx->state[i]>>8)&0xff;
      digest[4*i+3] = ctx->state[i]&0xff;
  }
}



#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include "aes.h"

#include "cpu.h"
#include "fields.h"
#include "compat.h"
#include "utils.h"

#if defined(HAVE_AESNI)
#include "aesni.h"
#endif
#if defined(HAVE_OPENSSL)
#include <openssl/evp.h>
#elif defined(_WIN32)
#include <windows.h>
#endif
// #include <string.h>

#define KEY_WORDS_128 4
#define KEY_WORDS_192 6
#define KEY_WORDS_256 8

#define AES_BLOCK_WORDS 4
#define RIJNDAEL_BLOCK_WORDS_192 6
#define RIJNDAEL_BLOCK_WORDS_256 8

static const bf8_t round_constants[30] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91,
};

static bf8_t compute_sbox(bf8_t in) {
  bf8_t t  = bf8_inv(in);
  bf8_t t0 = set_bit(parity8(t & (1 | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7))), 0);
  t0 ^= set_bit(parity8(t & (1 | (1 << 1) | (1 << 5) | (1 << 6) | (1 << 7))), 1);
  t0 ^= set_bit(parity8(t & (1 | (1 << 1) | (1 << 2) | (1 << 6) | (1 << 7))), 2);
  t0 ^= set_bit(parity8(t & (1 | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 7))), 3);
  t0 ^= set_bit(parity8(t & (1 | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4))), 4);
  t0 ^= set_bit(parity8(t & ((1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5))), 5);
  t0 ^= set_bit(parity8(t & ((1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6))), 6);
  t0 ^= set_bit(parity8(t & ((1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7))), 7);
  return t0 ^ (1 | (1 << 1) | (1 << 5) | (1 << 6));
}

#if defined(FAEST_TESTS)
void aes_increment_iv(uint8_t* iv)
#else
static inline void aes_increment_iv(uint8_t* iv)
#endif
{
  uint32_t iv0;
  memcpy(&iv0, iv, sizeof(uint32_t));
  iv0 = htole32(le32toh(iv0) + 1);
  memcpy(iv, &iv0, sizeof(uint32_t));
}

// ## AES ##
// Round Functions
static void add_round_key(unsigned int round, aes_block_t state, const aes_round_keys_t* round_key,
                          unsigned int block_words) {
  for (unsigned int c = 0; c < block_words; c++) {
    xor_u8_array(&state[c][0], &round_key->round_keys[round][c][0], &state[c][0], AES_NR);
  }
}

static void sub_bytes(aes_block_t state, unsigned int block_words) {
  for (unsigned int c = 0; c < block_words; c++) {
    for (unsigned int r = 0; r < AES_NR; r++) {
      state[c][r] = compute_sbox(state[c][r]);
    }
  }
}

static void shift_row(aes_block_t state, unsigned int block_words) {
  aes_block_t new_state;
  switch (block_words) {
  case 4:
  case 6:
    for (unsigned int i = 0; i < block_words; ++i) {
      new_state[i][0] = state[i][0];
      new_state[i][1] = state[(i + 1) % block_words][1];
      new_state[i][2] = state[(i + 2) % block_words][2];
      new_state[i][3] = state[(i + 3) % block_words][3];
    }
    break;
  case 8:
    for (unsigned int i = 0; i < block_words; i++) {
      new_state[i][0] = state[i][0];
      new_state[i][1] = state[(i + 1) % 8][1];
      new_state[i][2] = state[(i + 3) % 8][2];
      new_state[i][3] = state[(i + 4) % 8][3];
    }
    break;
  }

  for (unsigned int i = 0; i < block_words; ++i) {
    memcpy(&state[i][0], &new_state[i][0], AES_NR);
  }
}

static void mix_column(aes_block_t state, unsigned int block_words) {
  for (unsigned int c = 0; c < block_words; c++) {
    bf8_t tmp[4];
    tmp[0] = bf8_mul(state[c][0], 0x02) ^ bf8_mul(state[c][1], 0x03) ^ state[c][2] ^ state[c][3];
    tmp[1] = state[c][0] ^ bf8_mul(state[c][1], 0x02) ^ bf8_mul(state[c][2], 0x03) ^ state[c][3];
    tmp[2] = state[c][0] ^ state[c][1] ^ bf8_mul(state[c][2], 0x02) ^ bf8_mul(state[c][3], 0x03);
    tmp[3] = bf8_mul(state[c][0], 0x03) ^ state[c][1] ^ state[c][2] ^ bf8_mul(state[c][3], 0x02);

    memcpy(state[c], tmp, sizeof(tmp));
  }
}

// Key Expansion functions
static void sub_words(bf8_t* words) {
  words[0] = compute_sbox(words[0]);
  words[1] = compute_sbox(words[1]);
  words[2] = compute_sbox(words[2]);
  words[3] = compute_sbox(words[3]);
}

static void rot_word(bf8_t* words) {
#if 0
  bf8_t tmp = words[0];
  words[0]  = words[1];
  words[1]  = words[2];
  words[2]  = words[3];
  words[3]  = tmp;
#else
  // in the most ideal case, this generates a simple rord instruction
  uint32_t w;
  memcpy(&w, words, sizeof(w));
  w = htole32(rotr32(le32toh(w), 8));
  memcpy(words, &w, sizeof(w));
#endif
}

void expand_key(aes_round_keys_t* round_keys, const uint8_t* key, unsigned int key_words,
                unsigned int block_words, unsigned int num_rounds) {
  for (unsigned int k = 0; k < key_words; k++) {
    memcpy(round_keys->round_keys[k / block_words][k % block_words], &key[4 * k], 4);
  }

  for (unsigned int k = key_words; k < block_words * (num_rounds + 1); ++k) {
    bf8_t tmp[AES_NR];
    memcpy(tmp, round_keys->round_keys[(k - 1) / block_words][(k - 1) % block_words], sizeof(tmp));

    if (k % key_words == 0) {
      rot_word(tmp);
      sub_words(tmp);
      tmp[0] ^= round_constants[(k / key_words) - 1];
    }

    if (key_words > 6 && (k % key_words) == 4) {
      sub_words(tmp);
    }

    const unsigned int m = k - key_words;
    xor_u8_array(round_keys->round_keys[m / block_words][m % block_words], tmp,
                 round_keys->round_keys[k / block_words][k % block_words], 4);
  }
}

// Calling Functions

void aes128_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  expand_key(round_key, key, KEY_WORDS_128, AES_BLOCK_WORDS, AES_ROUNDS_128);
}

void aes192_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  expand_key(round_key, key, KEY_WORDS_192, AES_BLOCK_WORDS, AES_ROUNDS_192);
}

void aes256_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  expand_key(round_key, key, KEY_WORDS_256, AES_BLOCK_WORDS, AES_ROUNDS_256);
}

void rijndael192_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  expand_key(round_key, key, KEY_WORDS_192, RIJNDAEL_BLOCK_WORDS_192, AES_ROUNDS_192);
}

void rijndael256_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  expand_key(round_key, key, KEY_WORDS_256, RIJNDAEL_BLOCK_WORDS_256, AES_ROUNDS_256);
}

static void load_state(aes_block_t state, const uint8_t* src, unsigned int block_words) {
  for (unsigned int i = 0; i != block_words * 4; ++i) {
    state[i / 4][i % 4] = bf8_load(&src[i]);
  }
}

ATTR_CONST static bf8_t bf_exp_238(bf8_t x) {
  // 238 == 0b11101110
  bf8_t y = bf8_square(x); // x^2
  x       = bf8_square(y); // x^4
  y       = bf8_mul(x, y);
  x       = bf8_square(x); // x^8
  y       = bf8_mul(x, y);
  x       = bf8_square(x); // x^16
  x       = bf8_square(x); // x^32
  y       = bf8_mul(x, y);
  x       = bf8_square(x); // x^64
  y       = bf8_mul(x, y);
  x       = bf8_square(x); // x^128
  return bf8_mul(x, y);
}

#if !defined(FAEST_TESTS)
static
#endif
    uint8_t
    invnorm(uint8_t in) {
  // instead of computing in^(-17), we calculate in^238
  in = bf_exp_238(in);
  return set_bit(get_bit(in, 0), 0) ^ set_bit(get_bit(in, 6), 1) ^ set_bit(get_bit(in, 7), 2) ^
         set_bit(get_bit(in, 2), 3);
}

static uint8_t* store_invnorm_state(uint8_t* dst, aes_block_t state, unsigned int block_words) {
  for (unsigned int i = 0; i != block_words * 4; i += 2, ++dst) {
    uint8_t normstate_lo = invnorm(state[i / 4][i % 4]);
    uint8_t normstate_hi = invnorm(state[i / 4][(i + 1) % 4]);
    bf8_store(dst, (normstate_hi << 4) | normstate_lo);
  }
  return dst;
}

static uint8_t* store_state(uint8_t* dst, aes_block_t state, unsigned int block_words) {
  for (unsigned int i = 0; i != block_words * 4; ++i, ++dst) {
    bf8_store(dst, state[i / 4][i % 4]);
  }
  return dst;
}

static void aes_encrypt(const aes_round_keys_t* keys, aes_block_t state, unsigned int block_words,
                        unsigned int num_rounds) {
  // first round
  add_round_key(0, state, keys, block_words);

  for (unsigned int round = 1; round < num_rounds; ++round) {
    sub_bytes(state, block_words);
    shift_row(state, block_words);
    mix_column(state, block_words);
    add_round_key(round, state, keys, block_words);
  }

  // last round
  sub_bytes(state, block_words);
  shift_row(state, block_words);
  add_round_key(num_rounds, state, keys, block_words);
}

void aes128_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                          uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, AES_BLOCK_WORDS);
  aes_encrypt(key, state, AES_BLOCK_WORDS, AES_ROUNDS_128);
  store_state(ciphertext, state, AES_BLOCK_WORDS);
}

void aes192_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                          uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, AES_BLOCK_WORDS);
  aes_encrypt(key, state, AES_BLOCK_WORDS, AES_ROUNDS_192);
  store_state(ciphertext, state, AES_BLOCK_WORDS);
}

void aes256_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                          uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, AES_BLOCK_WORDS);
  aes_encrypt(key, state, AES_BLOCK_WORDS, AES_ROUNDS_256);
  store_state(ciphertext, state, AES_BLOCK_WORDS);
}

void rijndael192_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                               uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, RIJNDAEL_BLOCK_WORDS_192);
  aes_encrypt(key, state, RIJNDAEL_BLOCK_WORDS_192, AES_ROUNDS_192);
  store_state(ciphertext, state, RIJNDAEL_BLOCK_WORDS_192);
}

void rijndael256_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                               uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, RIJNDAEL_BLOCK_WORDS_256);
  aes_encrypt(key, state, RIJNDAEL_BLOCK_WORDS_256, AES_ROUNDS_256);
  store_state(ciphertext, state, RIJNDAEL_BLOCK_WORDS_256);
}

static void add_to_upper_word(uint8_t* iv, uint32_t tweak) {
  uint32_t iv3;
  memcpy(&iv3, iv + IV_SIZE - sizeof(uint32_t), sizeof(uint32_t));
  iv3 = htole32(le32toh(iv3) + tweak);
  memcpy(iv + IV_SIZE - sizeof(uint32_t), &iv3, sizeof(uint32_t));
}

#if defined(HAVE_AESNI)
ATTR_TARGET_AESNI ATTR_ALWAYS_INLINE static inline __m128i sse2_increment_iv(__m128i iv) {
  return _mm_add_epi32(iv, _mm_set_epi32(0, 0, 0, 1));
}

ATTR_TARGET_AESNI static void prg_aesni_128(const uint8_t* key, const uint8_t* iv, uint8_t* out,
                                            size_t outlen) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni(rk, key);

  __m128i miv = _mm_loadu_si128((const __m128i_u*)iv);
  for (size_t idx = 0; idx < outlen / IV_SIZE; idx += 1, out += IV_SIZE) {
    __m128i m = _mm_xor_si128(miv, rk[0]);
    for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
      m = _mm_aesenc_si128(m, rk[round]);
    }
    m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_128]);
    _mm_storeu_si128((__m128i_u*)out, m);
    miv = sse2_increment_iv(miv);
  }

  if (outlen % IV_SIZE) {
    __m128i m = _mm_xor_si128(miv, rk[0]);
    for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
      m = _mm_aesenc_si128(m, rk[round]);
    }
    m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_128]);

    uint8_t last_block[IV_SIZE];
    _mm_storeu_si128((__m128i_u*)last_block, m);

    memcpy(out, last_block, outlen % IV_SIZE);
  }
}

ATTR_TARGET_AESNI static void prg_2_aesni_128(const uint8_t* key, const uint8_t* iv, uint8_t* out) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni(rk, key);

  __m128i temp[2];
  temp[0] = _mm_loadu_si128((const __m128i_u*)iv);
  temp[1] = sse2_increment_iv(temp[0]);
  temp[0] = _mm_xor_si128(temp[0], rk[0]);
  temp[1] = _mm_xor_si128(temp[1], rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
    temp[0] = _mm_aesenc_si128(temp[0], rk[round]);
    temp[1] = _mm_aesenc_si128(temp[1], rk[round]);
  }
  _mm_storeu_si128((__m128i_u*)out, _mm_aesenclast_si128(temp[0], rk[AES_ROUNDS_128]));
  _mm_storeu_si128((__m128i_u*)out + 1, _mm_aesenclast_si128(temp[1], rk[AES_ROUNDS_128]));
}

ATTR_TARGET_AESNI static void prg_4_aesni_128(const uint8_t* key, const uint8_t* iv, uint8_t* out) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni(rk, key);

  __m128i temp[4];
  temp[0] = _mm_loadu_si128((const __m128i_u*)iv);
  temp[1] = sse2_increment_iv(temp[0]);
  temp[2] = sse2_increment_iv(temp[1]);
  temp[3] = sse2_increment_iv(temp[2]);
  temp[0] = _mm_xor_si128(temp[0], rk[0]);
  temp[1] = _mm_xor_si128(temp[1], rk[0]);
  temp[2] = _mm_xor_si128(temp[2], rk[0]);
  temp[3] = _mm_xor_si128(temp[3], rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
    temp[0] = _mm_aesenc_si128(temp[0], rk[round]);
    temp[1] = _mm_aesenc_si128(temp[1], rk[round]);
    temp[2] = _mm_aesenc_si128(temp[2], rk[round]);
    temp[3] = _mm_aesenc_si128(temp[3], rk[round]);
  }
  _mm_storeu_si128((__m128i_u*)out, _mm_aesenclast_si128(temp[0], rk[AES_ROUNDS_128]));
  _mm_storeu_si128((__m128i_u*)out + 1, _mm_aesenclast_si128(temp[1], rk[AES_ROUNDS_128]));
  _mm_storeu_si128((__m128i_u*)out + 2, _mm_aesenclast_si128(temp[2], rk[AES_ROUNDS_128]));
  _mm_storeu_si128((__m128i_u*)out + 3, _mm_aesenclast_si128(temp[3], rk[AES_ROUNDS_128]));
}

ATTR_TARGET_AESNI static void prg_aesni_192(const uint8_t* key, uint8_t* iv, uint8_t* out,
                                            size_t outlen) {
  __m128i rk[AES_ROUNDS_192 + 1];
  aes192_expand_key_aesni(rk, key);

  __m128i miv = _mm_loadu_si128((const __m128i_u*)iv);
  for (size_t idx = 0; idx < outlen / IV_SIZE; idx += 1, out += IV_SIZE) {
    __m128i m = _mm_xor_si128(miv, rk[0]);
    for (unsigned int round = 1; round != AES_ROUNDS_192; ++round) {
      m = _mm_aesenc_si128(m, rk[round]);
    }
    m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_192]);
    _mm_storeu_si128((__m128i_u*)out, m);
    miv = sse2_increment_iv(miv);
  }

  if (outlen % IV_SIZE) {
    __m128i m = _mm_xor_si128(miv, rk[0]);
    for (unsigned int round = 1; round != AES_ROUNDS_192; ++round) {
      m = _mm_aesenc_si128(m, rk[round]);
    }
    m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_192]);

    uint8_t last_block[IV_SIZE];
    _mm_storeu_si128((__m128i_u*)last_block, m);

    memcpy(out, last_block, outlen % IV_SIZE);
  }
}

ATTR_TARGET_AESNI static void prg_2_aesni_192(const uint8_t* key, uint8_t* iv, uint8_t* out) {
  __m128i rk[AES_ROUNDS_192 + 1];
  aes192_expand_key_aesni(rk, key);

  __m128i temp[3];
  temp[0] = _mm_loadu_si128((const __m128i_u*)iv);
  temp[1] = sse2_increment_iv(temp[0]);
  temp[2] = sse2_increment_iv(temp[1]);
  temp[0] = _mm_xor_si128(temp[0], rk[0]);
  temp[1] = _mm_xor_si128(temp[1], rk[0]);
  temp[2] = _mm_xor_si128(temp[2], rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_192; ++round) {
    temp[0] = _mm_aesenc_si128(temp[0], rk[round]);
    temp[1] = _mm_aesenc_si128(temp[1], rk[round]);
    temp[2] = _mm_aesenc_si128(temp[2], rk[round]);
  }
  _mm_storeu_si128((__m128i_u*)out, _mm_aesenclast_si128(temp[0], rk[AES_ROUNDS_192]));
  _mm_storeu_si128((__m128i_u*)out + 1, _mm_aesenclast_si128(temp[1], rk[AES_ROUNDS_192]));
  _mm_storeu_si128((__m128i_u*)out + 2, _mm_aesenclast_si128(temp[2], rk[AES_ROUNDS_192]));
}

ATTR_TARGET_AESNI static void prg_4_aesni_192(const uint8_t* key, uint8_t* iv, uint8_t* out) {
  __m128i rk[AES_ROUNDS_192 + 1];
  aes192_expand_key_aesni(rk, key);

  __m128i temp[6];
  temp[0] = _mm_loadu_si128((const __m128i_u*)iv);
  for (unsigned int i = 1; i != 6; ++i) {
    temp[i] = sse2_increment_iv(temp[i - 1]);
  }
  for (unsigned int i = 0; i != 6; ++i) {
    temp[i] = _mm_xor_si128(temp[i], rk[0]);
  }
  for (unsigned int round = 1; round != AES_ROUNDS_192; ++round) {
    for (unsigned int i = 0; i != 6; ++i) {
      temp[i] = _mm_aesenc_si128(temp[i], rk[round]);
    }
  }
  for (unsigned int i = 0; i != 6; ++i) {
    _mm_storeu_si128((__m128i_u*)out + i, _mm_aesenclast_si128(temp[i], rk[AES_ROUNDS_192]));
  }
}

ATTR_TARGET_AESNI static void prg_aesni_256(const uint8_t* key, uint8_t* iv, uint8_t* out,
                                            size_t outlen) {
  __m128i rk[AES_ROUNDS_256 + 1];
  aes256_expand_key_aesni(rk, key);

  __m128i miv = _mm_loadu_si128((const __m128i_u*)iv);
  for (size_t idx = 0; idx < outlen / IV_SIZE; idx += 1, out += IV_SIZE) {
    __m128i m = _mm_xor_si128(miv, rk[0]);
    for (unsigned int round = 1; round != AES_ROUNDS_256; ++round) {
      m = _mm_aesenc_si128(m, rk[round]);
    }
    m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_256]);
    _mm_storeu_si128((__m128i_u*)out, m);
    miv = sse2_increment_iv(miv);
  }

  if (outlen % IV_SIZE) {
    __m128i m = _mm_xor_si128(miv, rk[0]);
    for (unsigned int round = 1; round != AES_ROUNDS_256; ++round) {
      m = _mm_aesenc_si128(m, rk[round]);
    }
    m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_256]);

    uint8_t last_block[IV_SIZE];
    _mm_storeu_si128((__m128i_u*)last_block, m);

    memcpy(out, last_block, outlen % IV_SIZE);
  }
}

ATTR_TARGET_AESNI static void prg_2_aesni_256(const uint8_t* key, uint8_t* iv, uint8_t* out) {
  __m128i rk[AES_ROUNDS_256 + 1];
  aes256_expand_key_aesni(rk, key);

  __m128i temp[4];
  temp[0] = _mm_loadu_si128((const __m128i_u*)iv);
  for (unsigned int i = 1; i != 4; ++i) {
    temp[i] = sse2_increment_iv(temp[i - 1]);
  }
  for (unsigned int i = 0; i != 4; ++i) {
    temp[i] = _mm_xor_si128(temp[i], rk[0]);
  }
  for (unsigned int round = 1; round != AES_ROUNDS_256; ++round) {
    for (unsigned int i = 0; i != 4; ++i) {
      temp[i] = _mm_aesenc_si128(temp[i], rk[round]);
    }
  }
  for (unsigned int i = 0; i != 4; ++i) {
    _mm_storeu_si128((__m128i_u*)out + i, _mm_aesenclast_si128(temp[i], rk[AES_ROUNDS_256]));
  }
}

ATTR_TARGET_AESNI static void prg_4_aesni_256(const uint8_t* key, uint8_t* iv, uint8_t* out) {
  __m128i rk[AES_ROUNDS_256 + 1];
  aes256_expand_key_aesni(rk, key);

  __m128i temp[8];
  temp[0] = _mm_loadu_si128((const __m128i_u*)iv);
  for (unsigned int i = 1; i != 8; ++i) {
    temp[i] = sse2_increment_iv(temp[i - 1]);
  }
  for (unsigned int i = 0; i != 8; ++i) {
    temp[i] = _mm_xor_si128(temp[i], rk[0]);
  }
  for (unsigned int round = 1; round != AES_ROUNDS_256; ++round) {
    for (unsigned int i = 0; i != 8; ++i) {
      temp[i] = _mm_aesenc_si128(temp[i], rk[round]);
    }
  }
  for (unsigned int i = 0; i != 8; ++i) {
    _mm_storeu_si128((__m128i_u*)out + i, _mm_aesenclast_si128(temp[i], rk[AES_ROUNDS_256]));
  }
}

#if defined(HAVE_AVX2)
ATTR_TARGET_AESNI_AVX2 static void prg_aesni_avx_128(const uint8_t* key, const uint8_t* iv,
                                                     uint8_t* out, size_t outlen) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni_avx2(rk, key);

  __m128i miv = _mm_loadu_si128((const __m128i_u*)iv);
  for (size_t idx = 0; idx < outlen / IV_SIZE; idx += 1, out += IV_SIZE) {
    __m128i m = _mm_xor_si128(miv, rk[0]);
    for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
      m = _mm_aesenc_si128(m, rk[round]);
    }
    m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_128]);
    _mm_storeu_si128((__m128i_u*)out, m);
    miv = sse2_increment_iv(miv);
  }

  if (outlen % IV_SIZE) {
    __m128i m = _mm_xor_si128(miv, rk[0]);
    for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
      m = _mm_aesenc_si128(m, rk[round]);
    }
    m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_128]);

    uint8_t last_block[IV_SIZE];
    _mm_storeu_si128((__m128i_u*)last_block, m);

    memcpy(out, last_block, outlen % IV_SIZE);
  }
}

ATTR_TARGET_AESNI_AVX2 static void prg_2_aesni_avx_128(const uint8_t* key, const uint8_t* iv,
                                                       uint8_t* out) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni_avx2(rk, key);

  __m128i temp[2];
  temp[0] = _mm_loadu_si128((const __m128i_u*)iv);
  temp[1] = sse2_increment_iv(temp[0]);
  temp[0] = _mm_xor_si128(temp[0], rk[0]);
  temp[1] = _mm_xor_si128(temp[1], rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
    temp[0] = _mm_aesenc_si128(temp[0], rk[round]);
    temp[1] = _mm_aesenc_si128(temp[1], rk[round]);
  }
  temp[0] = _mm_aesenclast_si128(temp[0], rk[AES_ROUNDS_128]);
  temp[1] = _mm_aesenclast_si128(temp[1], rk[AES_ROUNDS_128]);
  _mm_storeu_si128((__m128i_u*)out, temp[0]);
  _mm_storeu_si128((__m128i_u*)(out + IV_SIZE), temp[1]);
}

ATTR_TARGET_AESNI_AVX2 static void prg_4_aesni_avx_128(const uint8_t* key, const uint8_t* iv,
                                                       uint8_t* out) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni_avx2(rk, key);

  __m128i temp[4];
  temp[0] = _mm_loadu_si128((const __m128i_u*)iv);
  temp[1] = sse2_increment_iv(temp[0]);
  temp[2] = sse2_increment_iv(temp[1]);
  temp[3] = sse2_increment_iv(temp[2]);
  temp[0] = _mm_xor_si128(temp[0], rk[0]);
  temp[1] = _mm_xor_si128(temp[1], rk[0]);
  temp[2] = _mm_xor_si128(temp[2], rk[0]);
  temp[3] = _mm_xor_si128(temp[3], rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
    temp[0] = _mm_aesenc_si128(temp[0], rk[round]);
    temp[1] = _mm_aesenc_si128(temp[1], rk[round]);
    temp[2] = _mm_aesenc_si128(temp[2], rk[round]);
    temp[3] = _mm_aesenc_si128(temp[3], rk[round]);
  }
  _mm_storeu_si128((__m128i_u*)out, _mm_aesenclast_si128(temp[0], rk[AES_ROUNDS_128]));
  _mm_storeu_si128((__m128i_u*)out + 1, _mm_aesenclast_si128(temp[1], rk[AES_ROUNDS_128]));
  _mm_storeu_si128((__m128i_u*)out + 2, _mm_aesenclast_si128(temp[2], rk[AES_ROUNDS_128]));
  _mm_storeu_si128((__m128i_u*)out + 3, _mm_aesenclast_si128(temp[3], rk[AES_ROUNDS_128]));
}

ATTR_TARGET_AESNI_AVX2 static void prg_aesni_avx_192(const uint8_t* key, uint8_t* iv, uint8_t* out,
                                                     size_t outlen) {
  __m128i rk[AES_ROUNDS_192 + 1];
  aes192_expand_key_aesni_avx2(rk, key);

  __m128i miv = _mm_loadu_si128((const __m128i_u*)iv);
  for (size_t idx = 0; idx < outlen / IV_SIZE; idx += 1, out += IV_SIZE) {
    __m128i m = _mm_xor_si128(miv, rk[0]);
    for (unsigned int round = 1; round != AES_ROUNDS_192; ++round) {
      m = _mm_aesenc_si128(m, rk[round]);
    }
    m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_192]);
    _mm_storeu_si128((__m128i_u*)out, m);
    miv = sse2_increment_iv(miv);
  }

  if (outlen % IV_SIZE) {
    __m128i m = _mm_xor_si128(miv, rk[0]);
    for (unsigned int round = 1; round != AES_ROUNDS_192; ++round) {
      m = _mm_aesenc_si128(m, rk[round]);
    }
    m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_192]);

    uint8_t last_block[IV_SIZE];
    _mm_storeu_si128((__m128i_u*)last_block, m);

    memcpy(out, last_block, outlen % IV_SIZE);
  }
}

ATTR_TARGET_AESNI_AVX2 static void prg_2_aesni_avx_192(const uint8_t* key, uint8_t* iv,
                                                       uint8_t* out) {
  __m128i rk[AES_ROUNDS_192 + 1];
  aes192_expand_key_aesni(rk, key);

  __m128i temp[3];
  temp[0] = _mm_loadu_si128((const __m128i_u*)iv);
  temp[1] = sse2_increment_iv(temp[0]);
  temp[2] = sse2_increment_iv(temp[1]);
  temp[0] = _mm_xor_si128(temp[0], rk[0]);
  temp[1] = _mm_xor_si128(temp[1], rk[0]);
  temp[2] = _mm_xor_si128(temp[2], rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_192; ++round) {
    temp[0] = _mm_aesenc_si128(temp[0], rk[round]);
    temp[1] = _mm_aesenc_si128(temp[1], rk[round]);
    temp[2] = _mm_aesenc_si128(temp[2], rk[round]);
  }
  _mm_storeu_si128((__m128i_u*)out, _mm_aesenclast_si128(temp[0], rk[AES_ROUNDS_192]));
  _mm_storeu_si128((__m128i_u*)out + 1, _mm_aesenclast_si128(temp[1], rk[AES_ROUNDS_192]));
  _mm_storeu_si128((__m128i_u*)out + 2, _mm_aesenclast_si128(temp[2], rk[AES_ROUNDS_192]));
}

ATTR_TARGET_AESNI_AVX2 static void prg_4_aesni_avx_192(const uint8_t* key, uint8_t* iv,
                                                       uint8_t* out) {
  __m128i rk[AES_ROUNDS_192 + 1];
  aes192_expand_key_aesni(rk, key);

  __m128i temp[6];
  temp[0] = _mm_loadu_si128((const __m128i_u*)iv);
  for (unsigned int i = 1; i != 6; ++i) {
    temp[i] = sse2_increment_iv(temp[i - 1]);
  }
  for (unsigned int i = 0; i != 6; ++i) {
    temp[i] = _mm_xor_si128(temp[i], rk[0]);
  }
  for (unsigned int round = 1; round != AES_ROUNDS_192; ++round) {
    for (unsigned int i = 0; i != 6; ++i) {
      temp[i] = _mm_aesenc_si128(temp[i], rk[round]);
    }
  }
  for (unsigned int i = 0; i != 6; ++i) {
    _mm_storeu_si128((__m128i_u*)out + i, _mm_aesenclast_si128(temp[i], rk[AES_ROUNDS_192]));
  }
}

ATTR_TARGET_AESNI_AVX2 static void prg_aesni_avx_256(const uint8_t* key, uint8_t* iv, uint8_t* out,
                                                     size_t outlen) {
  __m128i rk[AES_ROUNDS_256 + 1];
  aes256_expand_key_aesni_avx2(rk, key);

  __m128i miv = _mm_loadu_si128((const __m128i_u*)iv);
  for (size_t idx = 0; idx < outlen / IV_SIZE; idx += 1, out += IV_SIZE) {
    __m128i m = _mm_xor_si128(miv, rk[0]);
    for (unsigned int round = 1; round != AES_ROUNDS_256; ++round) {
      m = _mm_aesenc_si128(m, rk[round]);
    }
    m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_256]);
    _mm_storeu_si128((__m128i_u*)out, m);
    miv = sse2_increment_iv(miv);
  }

  if (outlen % IV_SIZE) {
    __m128i m = _mm_xor_si128(miv, rk[0]);
    for (unsigned int round = 1; round != AES_ROUNDS_256; ++round) {
      m = _mm_aesenc_si128(m, rk[round]);
    }
    m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_256]);

    uint8_t last_block[IV_SIZE];
    _mm_storeu_si128((__m128i_u*)last_block, m);

    memcpy(out, last_block, outlen % IV_SIZE);
  }
}

ATTR_TARGET_AESNI_AVX2 static void prg_2_aesni_avx_256(const uint8_t* key, uint8_t* iv,
                                                       uint8_t* out) {
  __m128i rk[AES_ROUNDS_256 + 1];
  aes256_expand_key_aesni(rk, key);

  __m128i temp[4];
  temp[0] = _mm_loadu_si128((const __m128i_u*)iv);
  for (unsigned int i = 1; i != 4; ++i) {
    temp[i] = sse2_increment_iv(temp[i - 1]);
  }
  for (unsigned int i = 0; i != 4; ++i) {
    temp[i] = _mm_xor_si128(temp[i], rk[0]);
  }
  for (unsigned int round = 1; round != AES_ROUNDS_256; ++round) {
    for (unsigned int i = 0; i != 4; ++i) {
      temp[i] = _mm_aesenc_si128(temp[i], rk[round]);
    }
  }
  for (unsigned int i = 0; i != 4; ++i) {
    _mm_storeu_si128((__m128i_u*)out + i, _mm_aesenclast_si128(temp[i], rk[AES_ROUNDS_256]));
  }
}

ATTR_TARGET_AESNI_AVX2 static void prg_4_aesni_avx_256(const uint8_t* key, uint8_t* iv,
                                                       uint8_t* out) {
  __m128i rk[AES_ROUNDS_256 + 1];
  aes256_expand_key_aesni(rk, key);

  __m128i temp[8];
  temp[0] = _mm_loadu_si128((const __m128i_u*)iv);
  for (unsigned int i = 1; i != 8; ++i) {
    temp[i] = sse2_increment_iv(temp[i - 1]);
  }
  for (unsigned int i = 0; i != 8; ++i) {
    temp[i] = _mm_xor_si128(temp[i], rk[0]);
  }
  for (unsigned int round = 1; round != AES_ROUNDS_256; ++round) {
    for (unsigned int i = 0; i != 8; ++i) {
      temp[i] = _mm_aesenc_si128(temp[i], rk[round]);
    }
  }
  for (unsigned int i = 0; i != 8; ++i) {
    _mm_storeu_si128((__m128i_u*)out + i, _mm_aesenclast_si128(temp[i], rk[AES_ROUNDS_256]));
  }
}
#endif
#endif

static void generic_prg(const uint8_t* key, uint8_t* internal_iv, uint8_t* out, unsigned int seclvl,
                        size_t outlen) {
#if defined(HAVE_OPENSSL)
  const EVP_CIPHER* cipher;
  switch (seclvl) {
  case 256:
    cipher = EVP_aes_256_ecb();
    break;
  case 192:
    cipher = EVP_aes_192_ecb();
    break;
  default:
    cipher = EVP_aes_128_ecb();
    break;
  }
  assert(cipher);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  assert(ctx);

  EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);

  int len = 0;
  for (size_t idx = 0; idx < outlen / IV_SIZE; idx += 1, out += IV_SIZE) {
    int ret = EVP_EncryptUpdate(ctx, out, &len, internal_iv, IV_SIZE);
    assert(ret == 1);
    assert(len == (int)IV_SIZE);
    (void)ret;
    (void)len;
    aes_increment_iv(internal_iv);
  }
  if (outlen % IV_SIZE) {
    uint8_t last_block[IV_SIZE];
    int ret = EVP_EncryptUpdate(ctx, last_block, &len, internal_iv, IV_SIZE);
    assert(ret == 1);
    assert(len == (int)IV_SIZE);
    (void)ret;
    (void)len;
    memcpy(out, last_block, outlen % IV_SIZE);
  }
  EVP_CIPHER_CTX_free(ctx);
#elif defined(_WIN32)
  BCRYPT_ALG_HANDLE aes_handle = NULL;
  BCRYPT_KEY_HANDLE key_handle = NULL;

  NTSTATUS ret = BCryptOpenAlgorithmProvider(&aes_handle, BCRYPT_AES_ALGORITHM, NULL, 0);
  assert(BCRYPT_SUCCESS(ret));
  ret = BCryptGenerateSymmetricKey(aes_handle, &key_handle, NULL, 0, (PUCHAR)key, seclvl / 8, 0);
  assert(BCRYPT_SUCCESS(ret));

  ret = BCryptSetProperty(aes_handle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                          (ULONG)((wcslen(BCRYPT_CHAIN_MODE_ECB) + 1) * sizeof(wchar_t)), 0);
  assert(BCRYPT_SUCCESS(ret));

  for (size_t idx = 0; idx < outlen / IV_SIZE; idx += 1, out += IV_SIZE) {
    ULONG len = 0;
    ret = BCryptEncrypt(key_handle, internal_iv, IV_SIZE, NULL, NULL, 0, out, IV_SIZE, &len, 0);
    assert(BCRYPT_SUCCESS(ret));
    assert(len == (ULONG)IV_SIZE);
    (void)ret;
    (void)len;
    aes_increment_iv(internal_iv);
  }
  if (outlen % IV_SIZE) {
    uint8_t last_block[IV_SIZE];
    ULONG len = 0;
    ret = BCryptEncrypt(key_handle, internal_iv, IV_SIZE, NULL, NULL, 0, last_block, IV_SIZE, &len,
                        0);
    assert(BCRYPT_SUCCESS(ret));
    assert(len == (ULONG)IV_SIZE);
    (void)ret;
    (void)len;
    memcpy(out, last_block, outlen % IV_SIZE);
  }

  BCryptDestroyKey(key_handle);
  BCryptCloseAlgorithmProvider(aes_handle, 0);
#else
  aes_round_keys_t round_key;

  switch (seclvl) {
  case 256:
    aes256_init_round_keys(&round_key, key);
    for (; outlen >= 16; outlen -= 16, out += 16) {
      aes_block_t state;
      load_state(state, internal_iv, AES_BLOCK_WORDS);
      aes_encrypt(&round_key, state, AES_BLOCK_WORDS, AES_ROUNDS_256);
      store_state(out, state, AES_BLOCK_WORDS);
      aes_increment_iv(internal_iv);
    }
    if (outlen) {
      aes_block_t state;
      load_state(state, internal_iv, AES_BLOCK_WORDS);
      aes_encrypt(&round_key, state, AES_BLOCK_WORDS, AES_ROUNDS_256);
      uint8_t tmp[16];
      store_state(tmp, state, AES_BLOCK_WORDS);
      memcpy(out, tmp, outlen);
    }
    return;
  case 192:
    aes192_init_round_keys(&round_key, key);
    for (; outlen >= 16; outlen -= 16, out += 16) {
      aes_block_t state;
      load_state(state, internal_iv, AES_BLOCK_WORDS);
      aes_encrypt(&round_key, state, AES_BLOCK_WORDS, AES_ROUNDS_192);
      store_state(out, state, AES_BLOCK_WORDS);
      aes_increment_iv(internal_iv);
    }
    if (outlen) {
      aes_block_t state;
      load_state(state, internal_iv, AES_BLOCK_WORDS);
      aes_encrypt(&round_key, state, AES_BLOCK_WORDS, AES_ROUNDS_192);
      uint8_t tmp[16];
      store_state(tmp, state, AES_BLOCK_WORDS);
      memcpy(out, tmp, outlen);
    }
    return;
  default:
    aes128_init_round_keys(&round_key, key);
    for (; outlen >= 16; outlen -= 16, out += 16) {
      aes_block_t state;
      load_state(state, internal_iv, AES_BLOCK_WORDS);
      aes_encrypt(&round_key, state, AES_BLOCK_WORDS, AES_ROUNDS_128);
      store_state(out, state, AES_BLOCK_WORDS);
      aes_increment_iv(internal_iv);
    }
    if (outlen) {
      aes_block_t state;
      load_state(state, internal_iv, AES_BLOCK_WORDS);
      aes_encrypt(&round_key, state, AES_BLOCK_WORDS, AES_ROUNDS_128);
      uint8_t tmp[16];
      store_state(tmp, state, AES_BLOCK_WORDS);
      memcpy(out, tmp, outlen);
    }
    return;
  }
#endif
}

void prg(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out, unsigned int seclvl,
         size_t outlen) {
  uint8_t internal_iv[IV_SIZE];
  memcpy(internal_iv, iv, IV_SIZE);
  add_to_upper_word(internal_iv, tweak);

#if defined(HAVE_AESNI)
// use AES-NI if possible
#if defined(HAVE_AVX2)
  if (CPU_SUPPORTS_AESNI_AVX2) {
    switch (seclvl) {
    case 256:
      prg_aesni_avx_256(key, internal_iv, out, outlen);
      return;
    case 192:
      prg_aesni_avx_192(key, internal_iv, out, outlen);
      return;
    default:
      prg_aesni_avx_128(key, internal_iv, out, outlen);
      return;
    }
  }
#endif

  if (CPU_SUPPORTS_AESNI) {
    switch (seclvl) {
    case 256:
      prg_aesni_256(key, internal_iv, out, outlen);
      return;
    case 192:
      prg_aesni_192(key, internal_iv, out, outlen);
      return;
    default:
      prg_aesni_128(key, internal_iv, out, outlen);
      return;
    }
  }
#endif

  generic_prg(key, internal_iv, out, seclvl, outlen);
}

void prg_2_lambda(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
                  unsigned int seclvl) {
  uint8_t internal_iv[IV_SIZE];
  memcpy(internal_iv, iv, IV_SIZE);
  add_to_upper_word(internal_iv, tweak);

#if defined(HAVE_AESNI)
// use AES-NI if possible
#if defined(HAVE_AVX2)
  if (CPU_SUPPORTS_AESNI_AVX2) {
    switch (seclvl) {
    case 256:
      prg_2_aesni_avx_256(key, internal_iv, out);
      return;
    case 192:
      prg_2_aesni_avx_192(key, internal_iv, out);
      return;
    default:
      prg_2_aesni_avx_128(key, internal_iv, out);
      return;
    }
  }
#endif

  if (CPU_SUPPORTS_AESNI) {
    switch (seclvl) {
    case 256:
      prg_2_aesni_256(key, internal_iv, out);
      return;
    case 192:
      prg_2_aesni_192(key, internal_iv, out);
      return;
    default:
      prg_2_aesni_128(key, internal_iv, out);
      return;
    }
  }
#endif

  generic_prg(key, internal_iv, out, seclvl, seclvl * 2 / 8);
}

void prg_4_lambda(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
                  unsigned int seclvl) {
  uint8_t internal_iv[IV_SIZE];
  memcpy(internal_iv, iv, IV_SIZE);
  add_to_upper_word(internal_iv, tweak);

#if defined(HAVE_AESNI)
// use AES-NI if possible
#if defined(HAVE_AVX2)
  if (CPU_SUPPORTS_AESNI_AVX2) {
    switch (seclvl) {
    case 256:
      prg_4_aesni_avx_256(key, internal_iv, out);
      return;
    case 192:
      prg_4_aesni_avx_192(key, internal_iv, out);
      return;
    default:
      prg_4_aesni_avx_128(key, internal_iv, out);
      return;
    }
  }
#endif

  if (CPU_SUPPORTS_AESNI) {
    switch (seclvl) {
    case 256:
      prg_4_aesni_256(key, internal_iv, out);
      return;
    case 192:
      prg_4_aesni_192(key, internal_iv, out);
      return;
    default:
      prg_4_aesni_128(key, internal_iv, out);
      return;
    }
  }
#endif

  generic_prg(key, internal_iv, out, seclvl, seclvl * 4 / 8);
}

// TODO：要改一个sha256和ripmd的实现出来
void aes_extend_witness(uint8_t* w, const uint8_t* key, const uint8_t* in,
                        const faest_paramset_t* params) {
  const unsigned int lambda      = params->lambda;
  const unsigned int num_rounds  = params->R;
  const unsigned int blocksize   = 32 * params->Nst;
  const unsigned int beta        = (lambda + blocksize - 1) / blocksize;
  const unsigned int block_words = blocksize / 32;
  const bool is_em               = faest_is_em(params);

#if !defined(NDEBUG)
  uint8_t* const w_out = w;
#endif

  if (is_em) {
    // switch input and key for EM
    const uint8_t* tmp = key;
    key                = in;
    in                 = tmp;
  }

  // Step 3
  aes_round_keys_t round_keys;
  switch (lambda) {
  case 256:
    if (is_em) {
      // for scan-build
      assert(block_words == RIJNDAEL_BLOCK_WORDS_256);
      rijndael256_init_round_keys(&round_keys, key);
    } else {
      aes256_init_round_keys(&round_keys, key);
    }
    break;
  case 192:
    if (is_em) {
      // for scan-build
      assert(block_words == RIJNDAEL_BLOCK_WORDS_192);
      rijndael192_init_round_keys(&round_keys, key);
    } else {
      aes192_init_round_keys(&round_keys, key);
    }
    break;
  default:
  // 进这个
    aes128_init_round_keys(&round_keys, key);
    break;
  }

  // Step 4
  if (!is_em) {
    const unsigned int nk = lambda / 32;

    // Key schedule constraints only needed for normal AES, not EM variant.
    for (unsigned int i = 0; i != nk; ++i) {
      memcpy(w, round_keys.round_keys[i / 4][i % 4], sizeof(aes_word_t));
      w += sizeof(aes_word_t);
    }

    const unsigned int S_ke = params->Ske;
    for (unsigned int j = 0, ik = nk; j < S_ke / 4; ++j) {
      memcpy(w, round_keys.round_keys[ik / 4][ik % 4], sizeof(aes_word_t));
      w += sizeof(aes_word_t);
      ik += lambda == 192 ? 6 : 4;
    }
  } else {
    const unsigned int lambda_bytes = lambda / 8;

    // saving the OWF key to the extended witness
    memcpy(w, in, lambda_bytes);
    w += lambda_bytes;
  }

  assert(w - w_out == params->Lke / 8);

  // Step 10
  // common part for AES-128, EM-128, EM-192, EM-256, first part for AES-192 and AES-256
  {
    // Step 12
    aes_block_t state;
    load_state(state, in, block_words);

    // Step 13
    add_round_key(0, state, &round_keys, block_words);

    for (unsigned int round = 1; round < num_rounds; ++round) {
      if (round % 2 == 1) {
        // save inverse norm of the S-box inputs, in coloumn major order
        w = store_invnorm_state(w, state, block_words);
      }
      // Step 15
      sub_bytes(state, block_words);
      // Step 16
      shift_row(state, block_words);
      if (round % 2 == 0) {
        // Step 17
        w = store_state(w, state, block_words);
      }
      // Step 18
      mix_column(state, block_words);
      // Step 19
      add_round_key(round, state, &round_keys, block_words);
    }
    // last round is not commited to, so not computed
  }

  if (beta == 2) {
    // AES-192 and AES-256
    uint8_t buf[16];
    memcpy(buf, in, sizeof(buf));
    buf[0] ^= 0x1;

    // Step 12
    aes_block_t state;
    load_state(state, buf, block_words);

    // Step 13
    add_round_key(0, state, &round_keys, block_words);

    for (unsigned int round = 1; round < num_rounds; ++round) {
      if (round % 2 == 1) {
        // save inverse norm of the S-box inputs, in coloumn major order
        w = store_invnorm_state(w, state, block_words);
      }
      // Step 15
      sub_bytes(state, block_words);
      // Step 16
      shift_row(state, block_words);
      if (round % 2 == 0) {
        // Step 17
        w = store_state(w, state, block_words);
      }
      // Step 18
      mix_column(state, block_words);
      // Step 19
      add_round_key(round, state, &round_keys, block_words);
    }
    // last round is not commited to, so not computed
  }

  assert(w - w_out == params->l / 8);
}


void sha256_extend_witness(uint8_t* w, const uint8_t* key, const uint8_t* in, const faest_paramset_t* params) {
  (void)key; // SHA256版的extend_witness中，key参数无用，忽略

  clock_t start_time = clock(); // 记录开始时间

  const unsigned int num_rounds = 64; // SHA-256固定有64轮
  const unsigned int blocksize = 512; // 每个消息块大小512位

#if !defined(NDEBUG)
  uint8_t* const w_out = w; // 用于debug模式下检查Witness长度
#endif

  // 1. 解析输入（512位 = 64字节）为16个32位字W[0..15]
  uint32_t W[64];
  for (int i = 0; i < 16; ++i) {
    W[i] = ((uint32_t)in[4*i] << 24) | ((uint32_t)in[4*i+1] << 16) | ((uint32_t)in[4*i+2] << 8) | ((uint32_t)in[4*i+3]);
  }
  // 扩展消息调度数组W到64个word
  for (int i = 16; i < 64; ++i) {
    W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];
  }

  // 保存全部W[i]到Witness
  for (int i = 0; i < 64; ++i) {
    w[0] = (W[i] >> 24) & 0xff;
    w[1] = (W[i] >> 16) & 0xff;
    w[2] = (W[i] >> 8) & 0xff;
    w[3] = W[i] & 0xff;
    w += 4;
  }

  // 2. 初始化SHA-256的内部状态(a,b,c,d,e,f,g,h)
  uint32_t a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
  uint32_t e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

  // 3. 进行SHA-256压缩主循环
  for (int i = 0; i < 64; ++i) {
    uint32_t T1 = h + SIG1(e) + CH(e,f,g) + K[i] + W[i];
    uint32_t T2 = SIG0(a) + MAJ(a,b,c);

    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;

    if (i % 2 == 0) {
      // 每两轮保存一次完整寄存器(a,b,c,d,e,f,g,h)
      for (int j = 0; j < 8; ++j) {
        uint32_t reg = ((uint32_t[]){a,b,c,d,e,f,g,h})[j];
        w[0] = (reg >> 24) & 0xff;
        w[1] = (reg >> 16) & 0xff;
        w[2] = (reg >> 8) & 0xff;
        w[3] = reg & 0xff;
        w += 4;
      }
    } else {
      // 奇数轮保存部分寄存器位（高4位a，低4位e，中间4位h）
      uint8_t y_a = (a >> 28) & 0xf;
      uint8_t y_e = (e >> 0) & 0xf;
      uint8_t y_h = (h >> 12) & 0xf;
      uint8_t combined = (y_a << 4) | y_e;
      w[0] = combined;
      w[1] = y_h;
      w += 2; // 每次保存12位，用2字节打包
    }
  }

// #if !defined(NDEBUG)
//   // Debug模式下检查Witness长度是否正确
//   assert((uintptr_t)(w - w_out) == params->l / 8);
// #endif

  clock_t end_time = clock(); // 记录结束时间
  double elapsed_time_ms = (double)(end_time - start_time) * 1000.0 / CLOCKS_PER_SEC;

  printf("sha256_extend_witness finished in %.3f ms\n", elapsed_time_ms);
  printf("Witness size: %u bytes\n", params->l / 8);
}
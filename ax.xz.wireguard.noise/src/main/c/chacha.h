#pragma once

#include <stdint.h>

#define CHACHA_BLOCK_SIZE 64

void chacha_cipher(uint32_t *state, uint8_t *dst, const uint8_t *src, unsigned int bytes, int nrounds);
void chacha_block_keystream(uint32_t *state, uint8_t *dst, int nrounds);

// arm64 and neon support
#if (defined(__arm64__) || defined(__aarch64__)) && defined(__ARM_NEON__)
void chacha_4block_xor_neon(uint32_t *state, uint8_t *dst, uint8_t const* src, int nrounds, int bytes);
void chacha_block_xor_neon(uint32_t *state, uint8_t *dst, uint8_t const* src, int nrounds, int bytes);
#endif
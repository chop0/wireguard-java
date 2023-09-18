#include "chacha.h"

#include <string.h>
#include <stdint.h>

//#if (defined(__arm64__) || defined(__aarch64__)) && defined(__ARM_NEON__)
//#define CHACHA_4BLOCK_XOR chacha_4block_xor_neon
//#define CHACHA_1BLOCK_XOR chacha_block_xor_neon
//#elif defined(__AVX2__)
//#define CHACHA_4BLOCK_XOR chacha_4block_xor_avx2
//#define CHACHA_2BLOCK_XOR chacha_2block_xor_avx2
//#define CHACHA_1BLOCK_XOR chacha_block_xor_avx2
//#elif defined(__SSE2__)
//#define CHACHA_2BLOCK_XOR chacha_2block_xor_sse2
//#define CHACHA_1BLOCK_XOR chacha_block_xor_sse2
//#else
#include "chacha-generic.h"
#define CHACHA_1BLOCK_XOR chacha_block_xor_generic
//#endif

void chacha_cipher(uint32_t *state, uint8_t *dst, const uint8_t *src,
			  unsigned int bytes, int nrounds)
{
	chacha_block_xor_generic(state, dst, src, nrounds, bytes);
}

void chacha_block_keystream(uint32_t *state, uint8_t *dst, int nrounds)
{
	uint8_t empty[CHACHA_BLOCK_SIZE] = {0};
	chacha_cipher(state, dst, empty, CHACHA_BLOCK_SIZE, nrounds);
}

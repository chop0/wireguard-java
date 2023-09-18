#pragma once

#include <stdint.h>

void chacha_cipher_generic(uint32_t *state, uint8_t *dst, const uint8_t *src, unsigned int bytes, int nrounds);
void chacha_block_keystream(uint32_t *state, uint8_t *dst, int nrounds);

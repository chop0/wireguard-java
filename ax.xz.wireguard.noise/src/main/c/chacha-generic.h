#pragma once

#include <stdint.h>

void chacha_block_xor_generic(uint32_t *state, uint8_t *dst, const uint8_t *src, int nrounds, unsigned int bytes);
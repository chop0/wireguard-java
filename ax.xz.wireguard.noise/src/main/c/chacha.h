#pragma once

#include <stdint.h>

#define CHACHA_BLOCK_SIZE 64

void chacha_cipher(uint32_t *state, uint8_t *dst, const uint8_t *src, unsigned int bytes, int nrounds);
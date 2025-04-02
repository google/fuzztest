// Copyright 2024 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./common/sha1.h"

#include <cstdint>
#include <cstring>

#include "absl/base/nullability.h"

namespace centipede {
namespace {

// We vendor our own implementation of SHA1 (taken from public domain) to avoid
// availability and linkage issues with implementations from OpenSSL/BoringSSL.

#ifdef __BIG_ENDIAN__
#define SHA_BIG_ENDIAN
#elif defined __LITTLE_ENDIAN__
/* override */
#elif defined __BYTE_ORDER
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define SHA_BIG_ENDIAN
#endif
#else                // ! defined __LITTLE_ENDIAN__
#include <endian.h>  // machine/endian.h
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define SHA_BIG_ENDIAN
#endif
#endif

/* header */

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

typedef struct sha1nfo {
  uint32_t buffer[BLOCK_LENGTH / 4];
  uint32_t state[HASH_LENGTH / 4];
  uint32_t byteCount;
  uint8_t bufferOffset;
  uint8_t keyBuffer[BLOCK_LENGTH];
  uint8_t innerHash[HASH_LENGTH];
} sha1nfo;

/* public API - prototypes - TODO: doxygen*/

/**
 */
void sha1_init(sha1nfo *s);
/**
 */
void sha1_writebyte(sha1nfo *s, uint8_t data);
/**
 */
void sha1_write(sha1nfo *s, const char *data, size_t len);
/**
 */
uint8_t *sha1_result(sha1nfo *s);

/* code */
#define SHA1_K0 0x5a827999
#define SHA1_K20 0x6ed9eba1
#define SHA1_K40 0x8f1bbcdc
#define SHA1_K60 0xca62c1d6

void sha1_init(sha1nfo *s) {
  s->state[0] = 0x67452301;
  s->state[1] = 0xefcdab89;
  s->state[2] = 0x98badcfe;
  s->state[3] = 0x10325476;
  s->state[4] = 0xc3d2e1f0;
  s->byteCount = 0;
  s->bufferOffset = 0;
}

uint32_t sha1_rol32(uint32_t number, uint8_t bits) {
  return ((number << bits) | (number >> (32 - bits)));
}

void sha1_hashBlock(sha1nfo *s) {
  uint8_t i;
  uint32_t a, b, c, d, e, t;

  a = s->state[0];
  b = s->state[1];
  c = s->state[2];
  d = s->state[3];
  e = s->state[4];
  for (i = 0; i < 80; i++) {
    if (i >= 16) {
      t = s->buffer[(i + 13) & 15] ^ s->buffer[(i + 8) & 15] ^
          s->buffer[(i + 2) & 15] ^ s->buffer[i & 15];
      s->buffer[i & 15] = sha1_rol32(t, 1);
    }
    if (i < 20) {
      t = (d ^ (b & (c ^ d))) + SHA1_K0;
    } else if (i < 40) {
      t = (b ^ c ^ d) + SHA1_K20;
    } else if (i < 60) {
      t = ((b & c) | (d & (b | c))) + SHA1_K40;
    } else {
      t = (b ^ c ^ d) + SHA1_K60;
    }
    t += sha1_rol32(a, 5) + e + s->buffer[i & 15];
    e = d;
    d = c;
    c = sha1_rol32(b, 30);
    b = a;
    a = t;
  }
  s->state[0] += a;
  s->state[1] += b;
  s->state[2] += c;
  s->state[3] += d;
  s->state[4] += e;
}

void sha1_addUncounted(sha1nfo *s, uint8_t data) {
  uint8_t *const b = (uint8_t *)s->buffer;
#ifdef SHA_BIG_ENDIAN
  b[s->bufferOffset] = data;
#else
  b[s->bufferOffset ^ 3] = data;
#endif
  s->bufferOffset++;
  if (s->bufferOffset == BLOCK_LENGTH) {
    sha1_hashBlock(s);
    s->bufferOffset = 0;
  }
}

void sha1_writebyte(sha1nfo *s, uint8_t data) {
  ++s->byteCount;
  sha1_addUncounted(s, data);
}

void sha1_write(sha1nfo *s, const char *data, size_t len) {
  for (; len--;) sha1_writebyte(s, (uint8_t)*data++);
}

void sha1_pad(sha1nfo *s) {
  // Implement SHA-1 padding (fips180-2 §5.1.1)

  // Pad with 0x80 followed by 0x00 until the end of the block
  sha1_addUncounted(s, 0x80);
  while (s->bufferOffset != 56) sha1_addUncounted(s, 0x00);

  // Append length in the last 8 bytes
  sha1_addUncounted(s, 0);  // We're only using 32 bit lengths
  sha1_addUncounted(s, 0);  // But SHA-1 supports 64 bit lengths
  sha1_addUncounted(s, 0);  // So zero pad the top bits
  sha1_addUncounted(s, s->byteCount >> 29);  // Shifting to multiply by 8
  sha1_addUncounted(
      s, s->byteCount >> 21);  // as SHA-1 supports bitstreams as well as
  sha1_addUncounted(s, s->byteCount >> 13);  // byte.
  sha1_addUncounted(s, s->byteCount >> 5);
  sha1_addUncounted(s, s->byteCount << 3);
}

uint8_t *sha1_result(sha1nfo *s) {
  // Pad to complete the last block
  sha1_pad(s);

#ifndef SHA_BIG_ENDIAN
  // Swap byte order back
  int i;
  for (i = 0; i < 5; i++) {
    s->state[i] = (((s->state[i]) << 24) & 0xff000000) |
                  (((s->state[i]) << 8) & 0x00ff0000) |
                  (((s->state[i]) >> 8) & 0x0000ff00) |
                  (((s->state[i]) >> 24) & 0x000000ff);
  }
#endif

  // Return pointer to hash (20 characters)
  return (uint8_t *)s->state;
}

static_assert(kShaDigestLength == HASH_LENGTH);

}  // namespace

void SHA1(const uint8_t *absl_nonnull data, size_t len,
          uint8_t *absl_nonnull out) {
  sha1nfo s;
  sha1_init(&s);
  sha1_write(&s, reinterpret_cast<const char *>(data), len);
  memcpy(out, sha1_result(&s), kShaDigestLength);
}

}  // namespace centipede

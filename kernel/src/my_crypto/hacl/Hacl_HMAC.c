/* MIT License
 *
 * Copyright (c) 2016-2022 INRIA, CMU and Microsoft Corporation
 * Copyright (c) 2022-2023 HACL* Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#include "internal/Hacl_HMAC.h"

#include "internal/Hacl_Krmllib.h"
#include "internal/Hacl_Hash_SHA2.h"
#include "internal/Hacl_Hash_SHA1.h"
#include "internal/Hacl_Hash_Blake2s.h"
#include "internal/Hacl_Hash_Blake2b.h"

/**
Write the HMAC-SHA-1 MAC of a message (`data`) by using a key (`key`) into `dst`.

The key can be any length and will be hashed if it is longer and padded if it is shorter than 64 byte.
`dst` must point to 20 bytes of memory.
*/
void
Hacl_HMAC_compute_sha1(
  uint8_t *dst,
  uint8_t *key,
  uint32_t key_len,
  uint8_t *data,
  uint32_t data_len
)
{
  uint32_t l = 64U;
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t key_block[l];
  memset(key_block, 0U, l * sizeof (uint8_t));
  uint8_t *nkey = key_block;
  uint32_t ite;
  if (key_len <= 64U)
  {
    ite = key_len;
  }
  else
  {
    ite = 20U;
  }
  uint8_t *zeroes = key_block + ite;
  KRML_MAYBE_UNUSED_VAR(zeroes);
  if (key_len <= 64U)
  {
    memcpy(nkey, key, key_len * sizeof (uint8_t));
  }
  else
  {
    Hacl_Hash_SHA1_hash_oneshot(nkey, key, key_len);
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t ipad[l];
  memset(ipad, 0x36U, l * sizeof (uint8_t));
  for (uint32_t i = 0U; i < l; i++)
  {
    uint8_t xi = ipad[i];
    uint8_t yi = key_block[i];
    ipad[i] = (uint32_t)xi ^ (uint32_t)yi;
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t opad[l];
  memset(opad, 0x5cU, l * sizeof (uint8_t));
  for (uint32_t i = 0U; i < l; i++)
  {
    uint8_t xi = opad[i];
    uint8_t yi = key_block[i];
    opad[i] = (uint32_t)xi ^ (uint32_t)yi;
  }
  uint32_t s[5U] = { 0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U, 0xc3d2e1f0U };
  uint8_t *dst1 = ipad;
  if (data_len == 0U)
  {
    Hacl_Hash_SHA1_update_last(s, 0ULL, ipad, 64U);
  }
  else
  {
    uint32_t block_len = 64U;
    uint32_t n_blocks0 = data_len / block_len;
    uint32_t rem0 = data_len % block_len;
    K___uint32_t_uint32_t scrut;
    if (n_blocks0 > 0U && rem0 == 0U)
    {
      uint32_t n_blocks_ = n_blocks0 - 1U;
      scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks_, .snd = data_len - n_blocks_ * block_len });
    }
    else
    {
      scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks0, .snd = rem0 });
    }
    uint32_t n_blocks = scrut.fst;
    uint32_t rem_len = scrut.snd;
    uint32_t full_blocks_len = n_blocks * block_len;
    uint8_t *full_blocks = data;
    uint8_t *rem = data + full_blocks_len;
    Hacl_Hash_SHA1_update_multi(s, ipad, 1U);
    Hacl_Hash_SHA1_update_multi(s, full_blocks, n_blocks);
    Hacl_Hash_SHA1_update_last(s, (uint64_t)64U + (uint64_t)full_blocks_len, rem, rem_len);
  }
  Hacl_Hash_SHA1_finish(s, dst1);
  uint8_t *hash1 = ipad;
  Hacl_Hash_SHA1_init(s);
  uint32_t block_len = 64U;
  uint32_t n_blocks0 = 20U / block_len;
  uint32_t rem0 = 20U % block_len;
  K___uint32_t_uint32_t scrut;
  if (n_blocks0 > 0U && rem0 == 0U)
  {
    uint32_t n_blocks_ = n_blocks0 - 1U;
    scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks_, .snd = 20U - n_blocks_ * block_len });
  }
  else
  {
    scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks0, .snd = rem0 });
  }
  uint32_t n_blocks = scrut.fst;
  uint32_t rem_len = scrut.snd;
  uint32_t full_blocks_len = n_blocks * block_len;
  uint8_t *full_blocks = hash1;
  uint8_t *rem = hash1 + full_blocks_len;
  Hacl_Hash_SHA1_update_multi(s, opad, 1U);
  Hacl_Hash_SHA1_update_multi(s, full_blocks, n_blocks);
  Hacl_Hash_SHA1_update_last(s, (uint64_t)64U + (uint64_t)full_blocks_len, rem, rem_len);
  Hacl_Hash_SHA1_finish(s, dst);
}

/**
Write the HMAC-SHA-2-256 MAC of a message (`data`) by using a key (`key`) into `dst`.

The key can be any length and will be hashed if it is longer and padded if it is shorter than 64 bytes.
`dst` must point to 32 bytes of memory.
*/
void
Hacl_HMAC_compute_sha2_256(
  uint8_t *dst,
  uint8_t *key,
  uint32_t key_len,
  uint8_t *data,
  uint32_t data_len
)
{
  uint32_t l = 64U;
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t key_block[l];
  memset(key_block, 0U, l * sizeof (uint8_t));
  uint8_t *nkey = key_block;
  uint32_t ite;
  if (key_len <= 64U)
  {
    ite = key_len;
  }
  else
  {
    ite = 32U;
  }
  uint8_t *zeroes = key_block + ite;
  KRML_MAYBE_UNUSED_VAR(zeroes);
  if (key_len <= 64U)
  {
    memcpy(nkey, key, key_len * sizeof (uint8_t));
  }
  else
  {
    Hacl_Hash_SHA2_hash_256(nkey, key, key_len);
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t ipad[l];
  memset(ipad, 0x36U, l * sizeof (uint8_t));
  for (uint32_t i = 0U; i < l; i++)
  {
    uint8_t xi = ipad[i];
    uint8_t yi = key_block[i];
    ipad[i] = (uint32_t)xi ^ (uint32_t)yi;
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t opad[l];
  memset(opad, 0x5cU, l * sizeof (uint8_t));
  for (uint32_t i = 0U; i < l; i++)
  {
    uint8_t xi = opad[i];
    uint8_t yi = key_block[i];
    opad[i] = (uint32_t)xi ^ (uint32_t)yi;
  }
  uint32_t st[8U] = { 0U };
  KRML_MAYBE_FOR8(i,
    0U,
    8U,
    1U,
    uint32_t *os = st;
    uint32_t x = Hacl_Hash_SHA2_h256[i];
    os[i] = x;);
  uint32_t *s = st;
  uint8_t *dst1 = ipad;
  if (data_len == 0U)
  {
    Hacl_Hash_SHA2_sha256_update_last(0ULL + (uint64_t)64U, 64U, ipad, s);
  }
  else
  {
    uint32_t block_len = 64U;
    uint32_t n_blocks0 = data_len / block_len;
    uint32_t rem0 = data_len % block_len;
    K___uint32_t_uint32_t scrut;
    if (n_blocks0 > 0U && rem0 == 0U)
    {
      uint32_t n_blocks_ = n_blocks0 - 1U;
      scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks_, .snd = data_len - n_blocks_ * block_len });
    }
    else
    {
      scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks0, .snd = rem0 });
    }
    uint32_t n_blocks = scrut.fst;
    uint32_t rem_len = scrut.snd;
    uint32_t full_blocks_len = n_blocks * block_len;
    uint8_t *full_blocks = data;
    uint8_t *rem = data + full_blocks_len;
    Hacl_Hash_SHA2_sha256_update_nblocks(64U, ipad, s);
    Hacl_Hash_SHA2_sha256_update_nblocks(n_blocks * 64U, full_blocks, s);
    Hacl_Hash_SHA2_sha256_update_last((uint64_t)64U + (uint64_t)full_blocks_len + (uint64_t)rem_len,
      rem_len,
      rem,
      s);
  }
  Hacl_Hash_SHA2_sha256_finish(s, dst1);
  uint8_t *hash1 = ipad;
  Hacl_Hash_SHA2_sha256_init(s);
  uint32_t block_len = 64U;
  uint32_t n_blocks0 = 32U / block_len;
  uint32_t rem0 = 32U % block_len;
  K___uint32_t_uint32_t scrut;
  if (n_blocks0 > 0U && rem0 == 0U)
  {
    uint32_t n_blocks_ = n_blocks0 - 1U;
    scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks_, .snd = 32U - n_blocks_ * block_len });
  }
  else
  {
    scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks0, .snd = rem0 });
  }
  uint32_t n_blocks = scrut.fst;
  uint32_t rem_len = scrut.snd;
  uint32_t full_blocks_len = n_blocks * block_len;
  uint8_t *full_blocks = hash1;
  uint8_t *rem = hash1 + full_blocks_len;
  Hacl_Hash_SHA2_sha256_update_nblocks(64U, opad, s);
  Hacl_Hash_SHA2_sha256_update_nblocks(n_blocks * 64U, full_blocks, s);
  Hacl_Hash_SHA2_sha256_update_last((uint64_t)64U + (uint64_t)full_blocks_len + (uint64_t)rem_len,
    rem_len,
    rem,
    s);
  Hacl_Hash_SHA2_sha256_finish(s, dst);
}

/**
Write the HMAC-SHA-2-384 MAC of a message (`data`) by using a key (`key`) into `dst`.

The key can be any length and will be hashed if it is longer and padded if it is shorter than 128 bytes.
`dst` must point to 48 bytes of memory.
*/
void
Hacl_HMAC_compute_sha2_384(
  uint8_t *dst,
  uint8_t *key,
  uint32_t key_len,
  uint8_t *data,
  uint32_t data_len
)
{
  uint32_t l = 128U;
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t key_block[l];
  memset(key_block, 0U, l * sizeof (uint8_t));
  uint8_t *nkey = key_block;
  uint32_t ite;
  if (key_len <= 128U)
  {
    ite = key_len;
  }
  else
  {
    ite = 48U;
  }
  uint8_t *zeroes = key_block + ite;
  KRML_MAYBE_UNUSED_VAR(zeroes);
  if (key_len <= 128U)
  {
    memcpy(nkey, key, key_len * sizeof (uint8_t));
  }
  else
  {
    Hacl_Hash_SHA2_hash_384(nkey, key, key_len);
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t ipad[l];
  memset(ipad, 0x36U, l * sizeof (uint8_t));
  for (uint32_t i = 0U; i < l; i++)
  {
    uint8_t xi = ipad[i];
    uint8_t yi = key_block[i];
    ipad[i] = (uint32_t)xi ^ (uint32_t)yi;
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t opad[l];
  memset(opad, 0x5cU, l * sizeof (uint8_t));
  for (uint32_t i = 0U; i < l; i++)
  {
    uint8_t xi = opad[i];
    uint8_t yi = key_block[i];
    opad[i] = (uint32_t)xi ^ (uint32_t)yi;
  }
  uint64_t st[8U] = { 0U };
  KRML_MAYBE_FOR8(i,
    0U,
    8U,
    1U,
    uint64_t *os = st;
    uint64_t x = Hacl_Hash_SHA2_h384[i];
    os[i] = x;);
  uint64_t *s = st;
  uint8_t *dst1 = ipad;
  if (data_len == 0U)
  {
    Hacl_Hash_SHA2_sha384_update_last(FStar_UInt128_add(FStar_UInt128_uint64_to_uint128(0ULL),
        FStar_UInt128_uint64_to_uint128((uint64_t)128U)),
      128U,
      ipad,
      s);
  }
  else
  {
    uint32_t block_len = 128U;
    uint32_t n_blocks0 = data_len / block_len;
    uint32_t rem0 = data_len % block_len;
    K___uint32_t_uint32_t scrut;
    if (n_blocks0 > 0U && rem0 == 0U)
    {
      uint32_t n_blocks_ = n_blocks0 - 1U;
      scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks_, .snd = data_len - n_blocks_ * block_len });
    }
    else
    {
      scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks0, .snd = rem0 });
    }
    uint32_t n_blocks = scrut.fst;
    uint32_t rem_len = scrut.snd;
    uint32_t full_blocks_len = n_blocks * block_len;
    uint8_t *full_blocks = data;
    uint8_t *rem = data + full_blocks_len;
    Hacl_Hash_SHA2_sha384_update_nblocks(128U, ipad, s);
    Hacl_Hash_SHA2_sha384_update_nblocks(n_blocks * 128U, full_blocks, s);
    Hacl_Hash_SHA2_sha384_update_last(FStar_UInt128_add(FStar_UInt128_add(FStar_UInt128_uint64_to_uint128((uint64_t)128U),
          FStar_UInt128_uint64_to_uint128((uint64_t)full_blocks_len)),
        FStar_UInt128_uint64_to_uint128((uint64_t)rem_len)),
      rem_len,
      rem,
      s);
  }
  Hacl_Hash_SHA2_sha384_finish(s, dst1);
  uint8_t *hash1 = ipad;
  Hacl_Hash_SHA2_sha384_init(s);
  uint32_t block_len = 128U;
  uint32_t n_blocks0 = 48U / block_len;
  uint32_t rem0 = 48U % block_len;
  K___uint32_t_uint32_t scrut;
  if (n_blocks0 > 0U && rem0 == 0U)
  {
    uint32_t n_blocks_ = n_blocks0 - 1U;
    scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks_, .snd = 48U - n_blocks_ * block_len });
  }
  else
  {
    scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks0, .snd = rem0 });
  }
  uint32_t n_blocks = scrut.fst;
  uint32_t rem_len = scrut.snd;
  uint32_t full_blocks_len = n_blocks * block_len;
  uint8_t *full_blocks = hash1;
  uint8_t *rem = hash1 + full_blocks_len;
  Hacl_Hash_SHA2_sha384_update_nblocks(128U, opad, s);
  Hacl_Hash_SHA2_sha384_update_nblocks(n_blocks * 128U, full_blocks, s);
  Hacl_Hash_SHA2_sha384_update_last(FStar_UInt128_add(FStar_UInt128_add(FStar_UInt128_uint64_to_uint128((uint64_t)128U),
        FStar_UInt128_uint64_to_uint128((uint64_t)full_blocks_len)),
      FStar_UInt128_uint64_to_uint128((uint64_t)rem_len)),
    rem_len,
    rem,
    s);
  Hacl_Hash_SHA2_sha384_finish(s, dst);
}

/**
Write the HMAC-SHA-2-512 MAC of a message (`data`) by using a key (`key`) into `dst`.

The key can be any length and will be hashed if it is longer and padded if it is shorter than 128 bytes.
`dst` must point to 64 bytes of memory.
*/
void
Hacl_HMAC_compute_sha2_512(
  uint8_t *dst,
  uint8_t *key,
  uint32_t key_len,
  uint8_t *data,
  uint32_t data_len
)
{
  uint32_t l = 128U;
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t key_block[l];
  memset(key_block, 0U, l * sizeof (uint8_t));
  uint8_t *nkey = key_block;
  uint32_t ite;
  if (key_len <= 128U)
  {
    ite = key_len;
  }
  else
  {
    ite = 64U;
  }
  uint8_t *zeroes = key_block + ite;
  KRML_MAYBE_UNUSED_VAR(zeroes);
  if (key_len <= 128U)
  {
    memcpy(nkey, key, key_len * sizeof (uint8_t));
  }
  else
  {
    Hacl_Hash_SHA2_hash_512(nkey, key, key_len);
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t ipad[l];
  memset(ipad, 0x36U, l * sizeof (uint8_t));
  for (uint32_t i = 0U; i < l; i++)
  {
    uint8_t xi = ipad[i];
    uint8_t yi = key_block[i];
    ipad[i] = (uint32_t)xi ^ (uint32_t)yi;
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t opad[l];
  memset(opad, 0x5cU, l * sizeof (uint8_t));
  for (uint32_t i = 0U; i < l; i++)
  {
    uint8_t xi = opad[i];
    uint8_t yi = key_block[i];
    opad[i] = (uint32_t)xi ^ (uint32_t)yi;
  }
  uint64_t st[8U] = { 0U };
  KRML_MAYBE_FOR8(i,
    0U,
    8U,
    1U,
    uint64_t *os = st;
    uint64_t x = Hacl_Hash_SHA2_h512[i];
    os[i] = x;);
  uint64_t *s = st;
  uint8_t *dst1 = ipad;
  if (data_len == 0U)
  {
    Hacl_Hash_SHA2_sha512_update_last(FStar_UInt128_add(FStar_UInt128_uint64_to_uint128(0ULL),
        FStar_UInt128_uint64_to_uint128((uint64_t)128U)),
      128U,
      ipad,
      s);
  }
  else
  {
    uint32_t block_len = 128U;
    uint32_t n_blocks0 = data_len / block_len;
    uint32_t rem0 = data_len % block_len;
    K___uint32_t_uint32_t scrut;
    if (n_blocks0 > 0U && rem0 == 0U)
    {
      uint32_t n_blocks_ = n_blocks0 - 1U;
      scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks_, .snd = data_len - n_blocks_ * block_len });
    }
    else
    {
      scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks0, .snd = rem0 });
    }
    uint32_t n_blocks = scrut.fst;
    uint32_t rem_len = scrut.snd;
    uint32_t full_blocks_len = n_blocks * block_len;
    uint8_t *full_blocks = data;
    uint8_t *rem = data + full_blocks_len;
    Hacl_Hash_SHA2_sha512_update_nblocks(128U, ipad, s);
    Hacl_Hash_SHA2_sha512_update_nblocks(n_blocks * 128U, full_blocks, s);
    Hacl_Hash_SHA2_sha512_update_last(FStar_UInt128_add(FStar_UInt128_add(FStar_UInt128_uint64_to_uint128((uint64_t)128U),
          FStar_UInt128_uint64_to_uint128((uint64_t)full_blocks_len)),
        FStar_UInt128_uint64_to_uint128((uint64_t)rem_len)),
      rem_len,
      rem,
      s);
  }
  Hacl_Hash_SHA2_sha512_finish(s, dst1);
  uint8_t *hash1 = ipad;
  Hacl_Hash_SHA2_sha512_init(s);
  uint32_t block_len = 128U;
  uint32_t n_blocks0 = 64U / block_len;
  uint32_t rem0 = 64U % block_len;
  K___uint32_t_uint32_t scrut;
  if (n_blocks0 > 0U && rem0 == 0U)
  {
    uint32_t n_blocks_ = n_blocks0 - 1U;
    scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks_, .snd = 64U - n_blocks_ * block_len });
  }
  else
  {
    scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks0, .snd = rem0 });
  }
  uint32_t n_blocks = scrut.fst;
  uint32_t rem_len = scrut.snd;
  uint32_t full_blocks_len = n_blocks * block_len;
  uint8_t *full_blocks = hash1;
  uint8_t *rem = hash1 + full_blocks_len;
  Hacl_Hash_SHA2_sha512_update_nblocks(128U, opad, s);
  Hacl_Hash_SHA2_sha512_update_nblocks(n_blocks * 128U, full_blocks, s);
  Hacl_Hash_SHA2_sha512_update_last(FStar_UInt128_add(FStar_UInt128_add(FStar_UInt128_uint64_to_uint128((uint64_t)128U),
        FStar_UInt128_uint64_to_uint128((uint64_t)full_blocks_len)),
      FStar_UInt128_uint64_to_uint128((uint64_t)rem_len)),
    rem_len,
    rem,
    s);
  Hacl_Hash_SHA2_sha512_finish(s, dst);
}

/**
Write the HMAC-BLAKE2s MAC of a message (`data`) by using a key (`key`) into `dst`.

The key can be any length and will be hashed if it is longer and padded if it is shorter than 64 bytes.
`dst` must point to 32 bytes of memory.
*/
void
Hacl_HMAC_compute_blake2s_32(
  uint8_t *dst,
  uint8_t *key,
  uint32_t key_len,
  uint8_t *data,
  uint32_t data_len
)
{
  uint32_t l = 64U;
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t key_block[l];
  memset(key_block, 0U, l * sizeof (uint8_t));
  uint8_t *nkey = key_block;
  uint32_t ite;
  if (key_len <= 64U)
  {
    ite = key_len;
  }
  else
  {
    ite = 32U;
  }
  uint8_t *zeroes = key_block + ite;
  KRML_MAYBE_UNUSED_VAR(zeroes);
  if (key_len <= 64U)
  {
    memcpy(nkey, key, key_len * sizeof (uint8_t));
  }
  else
  {
    Hacl_Hash_Blake2s_hash_with_key(nkey, 32U, key, key_len, NULL, 0U);
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t ipad[l];
  memset(ipad, 0x36U, l * sizeof (uint8_t));
  for (uint32_t i = 0U; i < l; i++)
  {
    uint8_t xi = ipad[i];
    uint8_t yi = key_block[i];
    ipad[i] = (uint32_t)xi ^ (uint32_t)yi;
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t opad[l];
  memset(opad, 0x5cU, l * sizeof (uint8_t));
  for (uint32_t i = 0U; i < l; i++)
  {
    uint8_t xi = opad[i];
    uint8_t yi = key_block[i];
    opad[i] = (uint32_t)xi ^ (uint32_t)yi;
  }
  uint32_t s[16U] = { 0U };
  Hacl_Hash_Blake2s_init(s, 0U, 32U);
  uint32_t *s0 = s;
  uint8_t *dst1 = ipad;
  if (data_len == 0U)
  {
    uint32_t wv[16U] = { 0U };
    Hacl_Hash_Blake2s_update_last(64U, wv, s0, 0ULL, 64U, ipad);
  }
  else
  {
    uint32_t block_len = 64U;
    uint32_t n_blocks0 = data_len / block_len;
    uint32_t rem0 = data_len % block_len;
    K___uint32_t_uint32_t scrut;
    if (n_blocks0 > 0U && rem0 == 0U)
    {
      uint32_t n_blocks_ = n_blocks0 - 1U;
      scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks_, .snd = data_len - n_blocks_ * block_len });
    }
    else
    {
      scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks0, .snd = rem0 });
    }
    uint32_t n_blocks = scrut.fst;
    uint32_t rem_len = scrut.snd;
    uint32_t full_blocks_len = n_blocks * block_len;
    uint8_t *full_blocks = data;
    uint8_t *rem = data + full_blocks_len;
    uint32_t wv[16U] = { 0U };
    Hacl_Hash_Blake2s_update_multi(64U, wv, s0, 0ULL, ipad, 1U);
    uint32_t wv0[16U] = { 0U };
    Hacl_Hash_Blake2s_update_multi(n_blocks * 64U,
      wv0,
      s0,
      (uint64_t)block_len,
      full_blocks,
      n_blocks);
    uint32_t wv1[16U] = { 0U };
    Hacl_Hash_Blake2s_update_last(rem_len,
      wv1,
      s0,
      (uint64_t)64U + (uint64_t)full_blocks_len,
      rem_len,
      rem);
  }
  Hacl_Hash_Blake2s_finish(32U, dst1, s0);
  uint8_t *hash1 = ipad;
  Hacl_Hash_Blake2s_init(s0, 0U, 32U);
  uint32_t block_len = 64U;
  uint32_t n_blocks0 = 32U / block_len;
  uint32_t rem0 = 32U % block_len;
  K___uint32_t_uint32_t scrut;
  if (n_blocks0 > 0U && rem0 == 0U)
  {
    uint32_t n_blocks_ = n_blocks0 - 1U;
    scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks_, .snd = 32U - n_blocks_ * block_len });
  }
  else
  {
    scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks0, .snd = rem0 });
  }
  uint32_t n_blocks = scrut.fst;
  uint32_t rem_len = scrut.snd;
  uint32_t full_blocks_len = n_blocks * block_len;
  uint8_t *full_blocks = hash1;
  uint8_t *rem = hash1 + full_blocks_len;
  uint32_t wv[16U] = { 0U };
  Hacl_Hash_Blake2s_update_multi(64U, wv, s0, 0ULL, opad, 1U);
  uint32_t wv0[16U] = { 0U };
  Hacl_Hash_Blake2s_update_multi(n_blocks * 64U,
    wv0,
    s0,
    (uint64_t)block_len,
    full_blocks,
    n_blocks);
  uint32_t wv1[16U] = { 0U };
  Hacl_Hash_Blake2s_update_last(rem_len,
    wv1,
    s0,
    (uint64_t)64U + (uint64_t)full_blocks_len,
    rem_len,
    rem);
  Hacl_Hash_Blake2s_finish(32U, dst, s0);
}

/**
Write the HMAC-BLAKE2b MAC of a message (`data`) by using a key (`key`) into `dst`.

The key can be any length and will be hashed if it is longer and padded if it is shorter than 128 bytes.
`dst` must point to 64 bytes of memory.
*/
void
Hacl_HMAC_compute_blake2b_32(
  uint8_t *dst,
  uint8_t *key,
  uint32_t key_len,
  uint8_t *data,
  uint32_t data_len
)
{
  uint32_t l = 128U;
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t key_block[l];
  memset(key_block, 0U, l * sizeof (uint8_t));
  uint8_t *nkey = key_block;
  uint32_t ite;
  if (key_len <= 128U)
  {
    ite = key_len;
  }
  else
  {
    ite = 64U;
  }
  uint8_t *zeroes = key_block + ite;
  KRML_MAYBE_UNUSED_VAR(zeroes);
  if (key_len <= 128U)
  {
    memcpy(nkey, key, key_len * sizeof (uint8_t));
  }
  else
  {
    Hacl_Hash_Blake2b_hash_with_key(nkey, 64U, key, key_len, NULL, 0U);
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t ipad[l];
  memset(ipad, 0x36U, l * sizeof (uint8_t));
  for (uint32_t i = 0U; i < l; i++)
  {
    uint8_t xi = ipad[i];
    uint8_t yi = key_block[i];
    ipad[i] = (uint32_t)xi ^ (uint32_t)yi;
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t opad[l];
  memset(opad, 0x5cU, l * sizeof (uint8_t));
  for (uint32_t i = 0U; i < l; i++)
  {
    uint8_t xi = opad[i];
    uint8_t yi = key_block[i];
    opad[i] = (uint32_t)xi ^ (uint32_t)yi;
  }
  uint64_t s[16U] = { 0U };
  Hacl_Hash_Blake2b_init(s, 0U, 64U);
  uint64_t *s0 = s;
  uint8_t *dst1 = ipad;
  if (data_len == 0U)
  {
    uint64_t wv[16U] = { 0U };
    Hacl_Hash_Blake2b_update_last(128U, wv, s0, FStar_UInt128_uint64_to_uint128(0ULL), 128U, ipad);
  }
  else
  {
    uint32_t block_len = 128U;
    uint32_t n_blocks0 = data_len / block_len;
    uint32_t rem0 = data_len % block_len;
    K___uint32_t_uint32_t scrut;
    if (n_blocks0 > 0U && rem0 == 0U)
    {
      uint32_t n_blocks_ = n_blocks0 - 1U;
      scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks_, .snd = data_len - n_blocks_ * block_len });
    }
    else
    {
      scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks0, .snd = rem0 });
    }
    uint32_t n_blocks = scrut.fst;
    uint32_t rem_len = scrut.snd;
    uint32_t full_blocks_len = n_blocks * block_len;
    uint8_t *full_blocks = data;
    uint8_t *rem = data + full_blocks_len;
    uint64_t wv[16U] = { 0U };
    Hacl_Hash_Blake2b_update_multi(128U, wv, s0, FStar_UInt128_uint64_to_uint128(0ULL), ipad, 1U);
    uint64_t wv0[16U] = { 0U };
    Hacl_Hash_Blake2b_update_multi(n_blocks * 128U,
      wv0,
      s0,
      FStar_UInt128_uint64_to_uint128((uint64_t)block_len),
      full_blocks,
      n_blocks);
    uint64_t wv1[16U] = { 0U };
    Hacl_Hash_Blake2b_update_last(rem_len,
      wv1,
      s0,
      FStar_UInt128_add(FStar_UInt128_uint64_to_uint128((uint64_t)128U),
        FStar_UInt128_uint64_to_uint128((uint64_t)full_blocks_len)),
      rem_len,
      rem);
  }
  Hacl_Hash_Blake2b_finish(64U, dst1, s0);
  uint8_t *hash1 = ipad;
  Hacl_Hash_Blake2b_init(s0, 0U, 64U);
  uint32_t block_len = 128U;
  uint32_t n_blocks0 = 64U / block_len;
  uint32_t rem0 = 64U % block_len;
  K___uint32_t_uint32_t scrut;
  if (n_blocks0 > 0U && rem0 == 0U)
  {
    uint32_t n_blocks_ = n_blocks0 - 1U;
    scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks_, .snd = 64U - n_blocks_ * block_len });
  }
  else
  {
    scrut = ((K___uint32_t_uint32_t){ .fst = n_blocks0, .snd = rem0 });
  }
  uint32_t n_blocks = scrut.fst;
  uint32_t rem_len = scrut.snd;
  uint32_t full_blocks_len = n_blocks * block_len;
  uint8_t *full_blocks = hash1;
  uint8_t *rem = hash1 + full_blocks_len;
  uint64_t wv[16U] = { 0U };
  Hacl_Hash_Blake2b_update_multi(128U, wv, s0, FStar_UInt128_uint64_to_uint128(0ULL), opad, 1U);
  uint64_t wv0[16U] = { 0U };
  Hacl_Hash_Blake2b_update_multi(n_blocks * 128U,
    wv0,
    s0,
    FStar_UInt128_uint64_to_uint128((uint64_t)block_len),
    full_blocks,
    n_blocks);
  uint64_t wv1[16U] = { 0U };
  Hacl_Hash_Blake2b_update_last(rem_len,
    wv1,
    s0,
    FStar_UInt128_add(FStar_UInt128_uint64_to_uint128((uint64_t)128U),
      FStar_UInt128_uint64_to_uint128((uint64_t)full_blocks_len)),
    rem_len,
    rem);
  Hacl_Hash_Blake2b_finish(64U, dst, s0);
}


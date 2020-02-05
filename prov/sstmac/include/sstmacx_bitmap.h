/**
Copyright 2009-2020 National Technology and Engineering Solutions of Sandia, 
LLC (NTESS).  Under the terms of Contract DE-NA-0003525, the U.S.  Government 
retains certain rights in this software.

Sandia National Laboratories is a multimission laboratory managed and operated
by National Technology and Engineering Solutions of Sandia, LLC., a wholly 
owned subsidiary of Honeywell International, Inc., for the U.S. Department of 
Energy's National Nuclear Security Administration under contract DE-NA0003525.

Copyright (c) 2009-2020, NTESS

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

    * Neither the name of the copyright holder nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Questions? Contact sst-macro-help@sandia.gov
*/
/*
 * Copyright (c) 2015,2017 Cray Inc. All rights reserved.
 *
 *  Created on: Apr 16, 2015
 *      Author: jswaro
 */

#ifndef BITMAP_H_
#define BITMAP_H_

#include <stdint.h>
#include <pthread.h>
#include <ofi.h>
#include <rdma/fi_errno.h>

#define SSTMACX_BITMAP_BUCKET_BITS 6
#define SSTMACX_BITMAP_BUCKET_LENGTH (1ULL << SSTMACX_BITMAP_BUCKET_BITS)
#define SSTMACX_BUCKET_INDEX(index) ((index) >> SSTMACX_BITMAP_BUCKET_BITS)
#define SSTMACX_BIT_INDEX(index) ((index) % SSTMACX_BITMAP_BUCKET_LENGTH)
#define SSTMACX_BIT_VALUE(index) (1ULL << SSTMACX_BIT_INDEX(index))

#define __PARTIAL_BLOCKS(nbits) (((nbits) % SSTMACX_BITMAP_BUCKET_LENGTH) ? 1 : 0)
#define __FULL_BLOCKS(nbits) ((nbits) >> SSTMACX_BITMAP_BUCKET_BITS)
#define SSTMACX_BITMAP_BLOCKS(nbits) \
	(__FULL_BLOCKS(nbits) + __PARTIAL_BLOCKS(nbits))

typedef uint64_t sstmacx_bitmap_value_t;

#ifdef HAVE_ATOMICS
#include <stdatomic.h>

typedef atomic_uint_fast64_t sstmacx_bitmap_block_t;
#else
typedef struct atomic_uint64_t {
	fastlock_t lock;
	sstmacx_bitmap_value_t val;
} sstmacx_bitmap_block_t;
#endif

typedef enum sstmacx_bitmap_state {
	SSTMACX_BITMAP_STATE_UNINITIALIZED = 0,
	SSTMACX_BITMAP_STATE_READY,
	SSTMACX_BITMAP_STATE_FREE,
} sstmacx_bitmap_state_e;

/**
 * @brief sstmacx bitmap structure
 *
 * @var state    state of the bitmap
 * @var length   length of bitmap in bits
 * @var arr      bitmap array
 * @var internal_buffer_allocation   flag to denote use of an externally
 *                                   allocated buffer
 */
typedef struct sstmacx_bitmap {
	sstmacx_bitmap_state_e state;
	uint32_t length;
	sstmacx_bitmap_block_t *arr;
	int internal_buffer_allocation;
} sstmacx_bitmap_t;

/**
 * Tests to see if a bit has been set in the bit.
 *
 * @param   bitmap  a sstmacx_bitmap pointer to the bitmap struct
 * @param   index   index of the bit in the map to test
 * @return  0 if the bit is not set, 1 if the bit is set
 */
int _sstmacx_test_bit(sstmacx_bitmap_t *bitmap, uint32_t index);

/**
 * Sets a bit in the bitmap
 *
 * @param   bitmap  a sstmacx_bitmap pointer to the bitmap struct
 * @param   index   index of the bit in the map to set
 */
void _sstmacx_set_bit(sstmacx_bitmap_t *bitmap, uint32_t index);

/**
 * Clears a bit in the bitmap
 *
 * @param   bitmap  a sstmacx_bitmap pointer to the bitmap struct
 * @param   index   index of the bit in the map to clear
 */
void _sstmacx_clear_bit(sstmacx_bitmap_t *bitmap, uint32_t index);

/**
 * Tests to see if a bit is set, then sets the bit in the bitmap
 *
 * @param   bitmap  a sstmacx_bitmap pointer to the bitmap struct
 * @param   index   index of the bit in the map to test and set
 * @return  0 if the bit was not set, 1 if the bit was already set
 */
int _sstmacx_test_and_set_bit(sstmacx_bitmap_t *bitmap, uint32_t index);

/**
 * Tests to see if a bit is set, the clears the bit in the bitmap
 *
 * @param   bitmap  a sstmacx_bitmap pointer to the bitmap struct
 * @param   index   index of the bit in the map to test and set
 * @return  0 if the bit was not set, 1 if the bit was already set
 */
int _sstmacx_test_and_clear_bit(sstmacx_bitmap_t *bitmap, uint32_t index);

/**
 * Takes a sstmacx_bitmap and allocates the internal structures and performs
 *   generic setup based on the number of bits requested
 *
 * @param   bitmap  a sstmacx_bitmap pointer to the bitmap struct
 * @param   nbits   number of bits to request space for
 * @param   addr    if provided, external memory allocation used for internal
					array
 * @return  0       on success
 * @return  -FI_EINVAL if bitmap is already initialized, or 0 is given
 *          as nbits
 * @return  -FI_ENOMEM if there isn't sufficient memory available to
 *          create bitmap
 * @note    If addr parameter is provided, realloc_bitmap will not work
 */
int _sstmacx_alloc_bitmap(sstmacx_bitmap_t *bitmap, uint32_t nbits, void *addr);

/**
 * Takes a sstmacx_bitmap and reallocates the internal structures to the requested
 *   size given in bits
 *
 * @note    On return of a ENOMEM error code, the bitmap will not be
 *          resized and will still be a valid and operable bitmap.
 *          The ENOMEM error only serves to indication that resources
 *          are	limited.
 *
 * @param   bitmap  a sstmacx_bitmap pointer to the bitmap struct
 * @param   nbits   number of bits to resize the bitmap to
 * @return  0       on success
 * @return  -FI_EINVAL if the bitmap hasn't been allocated yet or nbits == 0
 * @return  -FI_ENOMEM if there wasn't sufficient memory to expand the bitmap.
 */
int _sstmacx_realloc_bitmap(sstmacx_bitmap_t *bitmap, uint32_t nbits);

/**
 * Frees the internal structures of sstmacx_bitmap
 *
 * @param   bitmap  a sstmacx_bitmap pointer to the bitmap struct
 * @return  0       on success
 * @return  -FI_EINVAL if the internal resources are uninitialized or already free
 */
int _sstmacx_free_bitmap(sstmacx_bitmap_t *bitmap);

/**
 * Sets every bit in the bitmap with (value != 0)
 *
 * @param   bitmap  a sstmacx_bitmap pointer to the bitmap struct
 * @param   value   an integer value to be compared with 0 to set bits to
 */
void _sstmacx_fill_bitmap(sstmacx_bitmap_t *bitmap, uint64_t value);

/**
 * Finds the bit index of the first zero bit in the bitmap
 *
 * @param   bitmap	a sstmacx_bitmap pointer to the bitmap struct
 * @return  index	on success, returns an index s.t.
 *                    0 <= index < bitmap->length
 * @return  -FI_EAGAIN on failure to find a zero bit
 */
int _sstmacx_find_first_zero_bit(sstmacx_bitmap_t *bitmap);

/**
 * Finds the bit index of the first set bit in the bitmap
 *
 * @param   bitmap  a sstmacx_bitmap pointer to the bitmap struct
 * @return  index   on success, returns a index s.t.
 *                    0 <= index < bitmap->length
 * @return  -FI_EAGAIN on failure to find a set bit
 */
int _sstmacx_find_first_set_bit(sstmacx_bitmap_t *bitmap);

/**
 * Tests to verify that the bitmap is full
 *
 * @param   bitmap  a sstmacx_bitmap pointer to the bitmap struct
 * @return  0 if the bitmap has cleared bits, 1 if the bitmap is fully set
 */
int _sstmacx_bitmap_full(sstmacx_bitmap_t *bitmap);

/**
 * Tests to verify that the bitmap is empty
 *
 * @param   bitmap  a sstmacx_bitmap pointer to the bitmap struct
 * @return  0 if the bitmap has set bits, 1 if the bitmap is fully cleared
 */
int _sstmacx_bitmap_empty(sstmacx_bitmap_t *bitmap);

/**
 * Helper function for determining the size of array needed to support
 * 'x' number of bits for an externally provided buffer address 
 * @param   nbits  number of bits requested for the bitmap
 */
__attribute__((unused))
static inline uint32_t _sstmacx_bitmap_get_buffer_size(int nbits)
{
	return SSTMACX_BITMAP_BLOCKS(nbits) * sizeof(sstmacx_bitmap_block_t);
}

#endif /* BITMAP_H_ */

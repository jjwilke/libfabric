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

#include <stdlib.h>
#include <rdma/fi_errno.h>

#include "sstmacx_bitmap.h"

#ifdef HAVE_ATOMICS

#define __sstmacx_init_block(block) atomic_init(block, 0)
#define __sstmacx_set_block(bitmap, index, value) \
	atomic_store(&(bitmap)->arr[(index)], (value))
#define __sstmacx_load_block(bitmap, index) atomic_load(&(bitmap->arr[(index)]))
#define __sstmacx_set_bit(bitmap, bit) \
	atomic_fetch_or(&(bitmap)->arr[SSTMACX_BUCKET_INDEX(bit)], \
			SSTMACX_BIT_VALUE(bit))
#define __sstmacx_clear_bit(bitmap, bit) \
	atomic_fetch_and(&(bitmap)->arr[SSTMACX_BUCKET_INDEX(bit)], \
			~SSTMACX_BIT_VALUE(bit))
#define __sstmacx_test_bit(bitmap, bit) \
	((atomic_load(&(bitmap)->arr[SSTMACX_BUCKET_INDEX(bit)]) \
			& SSTMACX_BIT_VALUE(bit)) != 0)
#else

static inline void __sstmacx_init_block(sstmacx_bitmap_block_t *block)
{
	fastlock_init(&block->lock);
	block->val = 0llu;
}

static inline void __sstmacx_set_block(sstmacx_bitmap_t *bitmap, int index,
		uint64_t value)
{
	sstmacx_bitmap_block_t *block = &bitmap->arr[index];

	fastlock_acquire(&block->lock);
	block->val = value;
	fastlock_release(&block->lock);
}

static inline uint64_t __sstmacx_load_block(sstmacx_bitmap_t *bitmap, int index)
{
	sstmacx_bitmap_block_t *block = &bitmap->arr[index];
	uint64_t ret;

	fastlock_acquire(&block->lock);
	ret = block->val;
	fastlock_release(&block->lock);

	return ret;
}

static inline uint64_t __sstmacx_set_bit(sstmacx_bitmap_t *bitmap, int bit)
{
	sstmacx_bitmap_block_t *block = &bitmap->arr[SSTMACX_BUCKET_INDEX(bit)];
	uint64_t ret;

	fastlock_acquire(&block->lock);
	ret = block->val;
	block->val |= SSTMACX_BIT_VALUE(bit);
	fastlock_release(&block->lock);

	return ret;
}

static inline uint64_t __sstmacx_clear_bit(sstmacx_bitmap_t *bitmap, int bit)
{
	sstmacx_bitmap_block_t *block = &bitmap->arr[SSTMACX_BUCKET_INDEX(bit)];
	uint64_t ret;

	fastlock_acquire(&block->lock);
	ret = block->val;
	block->val &= ~SSTMACX_BIT_VALUE(bit);
	fastlock_release(&block->lock);

	return ret;
}

static inline int __sstmacx_test_bit(sstmacx_bitmap_t *bitmap, int bit)
{
	sstmacx_bitmap_block_t *block = &bitmap->arr[SSTMACX_BUCKET_INDEX(bit)];
	int ret;

	fastlock_acquire(&block->lock);
	ret = (block->val & SSTMACX_BIT_VALUE(bit)) != 0;
	fastlock_release(&block->lock);

	return ret;
}
#endif

extern "C" int _sstmacx_test_bit(sstmacx_bitmap_t *bitmap, uint32_t index)
{
	return __sstmacx_test_bit(bitmap, index);
}

void _sstmacx_set_bit(sstmacx_bitmap_t *bitmap, uint32_t index)
{
	__sstmacx_set_bit(bitmap, index);
}

void _sstmacx_clear_bit(sstmacx_bitmap_t *bitmap, uint32_t index)
{
	__sstmacx_clear_bit(bitmap, index);
}

extern "C" int _sstmacx_test_and_set_bit(sstmacx_bitmap_t *bitmap, uint32_t index)
{
	return (__sstmacx_set_bit(bitmap, index) & SSTMACX_BIT_VALUE(index)) != 0;
}

extern "C" int _sstmacx_test_and_clear_bit(sstmacx_bitmap_t *bitmap, uint32_t index)
{
	return (__sstmacx_clear_bit(bitmap, index) & SSTMACX_BIT_VALUE(index)) != 0;
}

extern "C" int _sstmacx_bitmap_full(sstmacx_bitmap_t *bitmap)
{
	return _sstmacx_find_first_zero_bit(bitmap) == -EAGAIN;
}

extern "C" int _sstmacx_bitmap_empty(sstmacx_bitmap_t *bitmap)
{
	return _sstmacx_find_first_set_bit(bitmap) == -FI_EAGAIN;
}

extern "C" int _sstmacx_find_first_zero_bit(sstmacx_bitmap_t *bitmap)
{
	int i, pos;
	sstmacx_bitmap_value_t value;

	for (i = 0, pos = 0;
			i < SSTMACX_BITMAP_BLOCKS(bitmap->length);
			++i, pos += SSTMACX_BITMAP_BUCKET_LENGTH) {
		/* invert the bits to check for first zero bit */
		value = ~(__sstmacx_load_block(bitmap, i));

		if (value != 0) {
			/* no need to check for errors because we have
			   established there is an unset bit */
			pos += ffsll(value) - 1;

			if (pos < bitmap->length)
				return pos;
			else
				return -FI_EAGAIN;
		}
	}

	return -FI_EAGAIN;
}

extern "C" int _sstmacx_find_first_set_bit(sstmacx_bitmap_t *bitmap)
{
	int i, pos;
	sstmacx_bitmap_value_t value;

	for (i = 0, pos = 0;
			i < SSTMACX_BITMAP_BLOCKS(bitmap->length);
			++i, pos += SSTMACX_BITMAP_BUCKET_LENGTH) {
		value = __sstmacx_load_block(bitmap, i);

		if (value != 0) {
			/* no need to check for errors because we have
			   established there is a set bit */
			pos += ffsll(value) - 1;

			if (pos < bitmap->length)
				return pos;
			else
				return -FI_EAGAIN;		}
	}

	return -FI_EAGAIN;
}

void _sstmacx_fill_bitmap(sstmacx_bitmap_t *bitmap, uint64_t value)
{
	int i;
	sstmacx_bitmap_value_t fill_value = (value != 0) ? ~0 : 0;

	for (i = 0; i < SSTMACX_BITMAP_BLOCKS(bitmap->length); ++i) {
		__sstmacx_set_block(bitmap, i, fill_value);
	}
}

extern "C" int _sstmacx_alloc_bitmap(sstmacx_bitmap_t *bitmap, uint32_t nbits, void *addr)
{
	int i;

	if (bitmap->state == SSTMACX_BITMAP_STATE_READY)
		return -FI_EINVAL;

	if (bitmap->length != 0 || nbits == 0)
		return -FI_EINVAL;

	if (!addr) {
		bitmap->arr = calloc(SSTMACX_BITMAP_BLOCKS(nbits),
				sizeof(sstmacx_bitmap_block_t));
		bitmap->internal_buffer_allocation = 1;
	} else {
		bitmap->arr = addr;
		bitmap->internal_buffer_allocation = 0;
	}

	if (!bitmap->arr)
		return -FI_ENOMEM;

	bitmap->length = nbits;

	for (i = 0; i < SSTMACX_BITMAP_BLOCKS(bitmap->length); ++i)
		__sstmacx_init_block(&bitmap->arr[i]);

	bitmap->state = SSTMACX_BITMAP_STATE_READY;

	return 0;
}

extern "C" int _sstmacx_realloc_bitmap(sstmacx_bitmap_t *bitmap, uint32_t nbits)
{
	sstmacx_bitmap_block_t *new_allocation;
	int blocks_to_allocate = SSTMACX_BITMAP_BLOCKS(nbits);
	int i;

	if (bitmap->state != SSTMACX_BITMAP_STATE_READY)
		return -FI_EINVAL;

	if (nbits == 0 || bitmap->arr == NULL)
		return -FI_EINVAL;

	if (!bitmap->internal_buffer_allocation)
		return -FI_EINVAL;

	new_allocation = realloc(bitmap->arr,
			(blocks_to_allocate *
					sizeof(sstmacx_bitmap_block_t)));

	if (!new_allocation)
		return -FI_ENOMEM;

	bitmap->arr = new_allocation;

	/* Did we increase the size of the bitmap?
	 * If so, initialize new blocks */
	if (blocks_to_allocate > SSTMACX_BITMAP_BLOCKS(bitmap->length)) {
		for (i = SSTMACX_BITMAP_BLOCKS(bitmap->length);
				i < blocks_to_allocate;
				++i) {
			__sstmacx_init_block(&bitmap->arr[i]);
		}
	}

	bitmap->length = nbits;

	return 0;
}

extern "C" int _sstmacx_free_bitmap(sstmacx_bitmap_t *bitmap)
{
	if (bitmap->state != SSTMACX_BITMAP_STATE_READY)
		return -FI_EINVAL;

	bitmap->length = 0;
	if (bitmap->arr && bitmap->internal_buffer_allocation) {
		free(bitmap->arr);
		bitmap->arr = NULL;
	}

	bitmap->state = SSTMACX_BITMAP_STATE_FREE;

	return 0;
}

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
 * Copyright (c) 2015-2016 Los Alamos National Security, LLC.
 *                         All rights reserved.
 * Copyright (c) 2016 Cray Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef SSTMACX_VECTOR_H_
#define SSTMACX_VECTOR_H_

#include "sstmacx.h"
#include "sstmacx_util.h"

#include "stdlib.h"
#include "string.h"

/*******************************************************************************
 * DATASTRUCTS
 ******************************************************************************/
typedef enum sstmacx_vec_state {
	SSTMACX_VEC_STATE_READY = 0xdeadbeef,
	SSTMACX_VEC_STATE_DEAD,
} sstmacx_vec_state_e;

typedef enum sstmacx_vec_increase {
	SSTMACX_VEC_INCREASE_ADD,
	SSTMACX_VEC_INCREASE_MULT,
} sstmacx_vec_increase_e;

typedef enum sstmacx_vec_lock {
	SSTMACX_VEC_UNLOCKED,
	SSTMACX_VEC_LOCKED,
} sstmacx_vec_lock_e;

typedef uint32_t sstmacx_vec_index_t;
typedef void * sstmacx_vec_entry_t;

/**
 * Set of attributes that MUST be initialized and passed to _sstmacx_vec_init.
 *
 * @var vec_initial_size	Initial size of the vector
 * @var vec_maximum_size	Maximum size of the vector
 * @var vec_increase_step	Type of step to increase vector by, ADD or MULT
 * @var vec_internal_locking	SSTMACX_VEC_UNLOCKED for unlocked, otherwise locked
 * @var creator			fn required to properly alloc the vector element
 */
typedef struct sstmacx_vec_attr {
	uint32_t vec_initial_size;
	uint32_t cur_size;
	uint32_t vec_maximum_size;

	uint32_t vec_increase_step;

	sstmacx_vec_increase_e vec_increase_type;

	sstmacx_vec_lock_e vec_internal_locking;
} sstmacx_vec_attr_t;

struct sstmacx_vector;

struct sstmacx_vector_iter {
	struct sstmacx_vector *vec;
	uint32_t cur_idx;
};

#define SSTMACX_VECTOR_ITERATOR(_vec, _iter)	\
	struct sstmacx_vector_iter _iter = {	\
		.vec = (_vec),			\
		.cur_idx = 0,			\
	}

/* Returns the current index of the iterator */
#define SSTMACX_VECTOR_ITERATOR_IDX(_iter)	((_iter).cur_idx - 1)

/**
 * Vector operations
 *
 * @var insert_last	Insert an entry into the last index of the vector.
 * @var insert_at	Insert an entry into the vector at the given index.
 *
 * @var remove_last	Removes the last element from the vector.
 * @var remove_at	Removes the element at index from the vector.
 *
 * @var last		Return the last element of the vector.
 * @var at		Return the element at the specified index.
 *
 * @var iter_next	Return the element at the current index and move them
 *			index to the next element.
 */
typedef struct sstmacx_vector_ops {
	int (*resize)(struct sstmacx_vector *, uint32_t);

	int (*insert_last)(struct sstmacx_vector *, sstmacx_vec_entry_t *);
	int (*insert_at)(struct sstmacx_vector *, sstmacx_vec_entry_t *,
			 sstmacx_vec_index_t);

	int (*remove_last)(struct sstmacx_vector *);
	int (*remove_at)(struct sstmacx_vector *, sstmacx_vec_index_t);

	int (*last)(struct sstmacx_vector *, void **);
	int (*at)(struct sstmacx_vector *, void **, sstmacx_vec_index_t);

	sstmacx_vec_entry_t *(*iter_next)(struct sstmacx_vector_iter *);
} sstmacx_vector_ops_t;

/**
 * Vector handle
 *
 * @var state	The current state of the vector instance.
 * @var attr	The attributes of this vector.
 * @var ops	The supported operations on this vector.
 * @var vector	The begging address of the vector.
 * @var size	The current size of the vector.
 * @var lock	A read/write lock for the vector.
 */
typedef struct sstmacx_vector {
	sstmacx_vec_state_e state;
	sstmacx_vec_attr_t attr;
	sstmacx_vector_ops_t *ops;
	sstmacx_vec_entry_t *vector;
	rwlock_t lock;
} sstmacx_vector_t;


/*******************************************************************************
 * API Prototypes
 ******************************************************************************/
/**
 * Create the initial vector.  The user is responsible for initializing the
 * "attr" parameter prior to calling this function.
 *
 * @param[in] vec	the vector to initialize
 * @param[in] attr	the vector attributes
 *
 * @return FI_SUCCESS	Upon successfully creating the vector
 * @return -FI_EINVAL	Upon receiving an invalid parameter
 * @return -FI_ENOMEM	Upon insufficient memory to create the vector
 */
int _sstmacx_vec_init(struct sstmacx_vector *vec, sstmacx_vec_attr_t *attr);

/**
 * Close the vector elements and then the vector.
 *
 * @param[in] vec       the vector to close
 *
 * @return FI_SUCCESS	Upon successfully closing the vector
 * @return -FI_EINVAL	Upon a uninitialized or dead vector
 */
int _sstmacx_vec_close(sstmacx_vector_t *vec);

/*******************************************************************************
 * INLINE OPS FNS
 ******************************************************************************/
/**
 * Resize the vector to size.
 *
 * @param[in] vec	the vector to resize
 * @param[in] size	the new size of the vector
 *
 * @return FI_SUCCESS	Upon successfully resizing the vector
 * @return -FI_EINVAL	Upon passing a uninitialized or dead vector, a size
 * 			less than the minimum vector size, or a size greater
 *			than the maximum vector size
 * @return -FI_ENOMEM	Upon running out of memory
 */
static inline int _sstmacx_vec_resize(sstmacx_vector_t *vec, uint32_t size)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (OFI_UNLIKELY(!vec)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "Invalid parameter to "
			  "_sstmacx_vec_resize.\n");
		return -FI_EINVAL;
	} else {
		return vec->ops->resize(vec, size);
	}
}

/**
 * Get the element at index in the vector.
 *
 * @param[in]	  vec 	  The vector to return an element from
 * @param[in/out] element The element at the specified index in the vector
 * @param[in]	  index   The index of the desired element
 *
 * @return FI_SUCCESS	Upon successfully returning the element
 * @return -FI_EINVAL	Upon passing a NULL or dead vector
 * @return -FI_ECANCLED Upon attempting to get an empty element
 */
static inline int _sstmacx_vec_at(sstmacx_vector_t *vec, void **element,
			       sstmacx_vec_index_t index)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (OFI_UNLIKELY(!vec || !element)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "Invalid parameter to "
			  "_sstmacx_vec_at\n");
		return -FI_EINVAL;
	} else {
		return vec->ops->at(vec, element, index);
	}
}

/**
 * Get the first element in the vector.
 *
 * @param[in]	  vec The vector to return an element from
 * @param[in/out] element the first element in the vector
 *
 * @return FI_SUCCESS	Upon successfully returning the element
 * @return -FI_EINVAL	Upon passing a NULL or dead vector
 * @return -FI_ECANCLED Upon attempting to get an empty element
 */
static inline int _sstmacx_vec_last(sstmacx_vector_t *vec, void **element)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (OFI_UNLIKELY(!vec || !element)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "Invalid parameter to "
			  "_sstmacx_vec_last\n");
		return -FI_EINVAL;
	} else {
		return vec->ops->last(vec, element);
	}
}

/**
 * Get the first element in the vector.
 *
 * @param[in]	  vec The vector to return an element from
 * @param[in/out] element the first element in the vector
 *
 * @return FI_SUCCESS	Upon successfully returning the element
 * @return -FI_EINVAL	Upon passing a NULL or dead vector
 * @return -FI_ECANCLED Upon attempting to get an empty element
 */
static inline int _sstmacx_vec_first(sstmacx_vector_t *vec, void **element)
{
	return _sstmacx_vec_at(vec, element, 0);
}

/**
 * Removes the element at index from the vector.  Note that
 * the user is responsible for properly disconnecting and/or destroying
 * this vector element.
 *
 * @param[in] vec	the vector to remove an entry from
 * @param[in] index	the index of the entry to remove
 *
 * @return FI_SUCCESS	 Upon successfully removing the entry
 * @return -FI_EINVAL	 Upon passing a dead vector
 * @return -FI_ECANCELED Upon attempting to remove an empty entry
 */
static inline int _sstmacx_vec_remove_at(sstmacx_vector_t *vec,
				      sstmacx_vec_index_t index)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (OFI_UNLIKELY(!vec)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "Invalid parameter to "
			  "_sstmacx_vec_remove_at\n");
		return -FI_EINVAL;
	} else {
		return vec->ops->remove_at(vec, index);
	}
}

/**
 * Removes the last element from the vector.  Note that
 * the user is responsible for properly disconnecting and/or destroying
 * this vector element.
 *
 * @param[in] vec	the vector to remove an entry from
 *
 * @return FI_SUCCESS	 Upon successfully removing and destroying the entry
 * @return -FI_EINVAL	 Upon passing a dead entry
 * @return -FI_ECANCELED Upon attempting to remove an empty entry
 */
static inline int _sstmacx_vec_remove_last(sstmacx_vector_t *vec)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (OFI_UNLIKELY(!vec)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "Invalid parameter to "
			  "_sstmacx_vec_remove_at\n");
		return -FI_EINVAL;
	} else {
		return vec->ops->remove_last(vec);
	}
}

/**
 * Removes the first element from the vector.  Note that
 * the user is responsible for properly disconnecting and/or destroying
 * this vector element.
 *
 * @param[in] vec	the vector to remove an entry from
 *
 * @return FI_SUCCESS	 Upon successfully removing and destroying the entry
 * @return -FI_EINVAL	 Upon passing a dead entry
 * @return -FI_ECANCELED Upon attempting to remove an empty entry
 */
static inline int _sstmacx_vec_remove_first(sstmacx_vector_t *vec)
{
	return _sstmacx_vec_remove_at(vec, 0);
}

/**
 * Inserts an entry into the vector at the given index. If the current size
 * of the vector is not large enough to satisfy the insertion then the vector
 * will be grown up to the maximum size. If the entry at index is not empty
 * the insertion will be canceled.
 *
 * @param[in] vec	the vector to insert entry into
 * @param[in] entry	the item to insert into the vector
 * @param[in] index	the index to insert the item at
 *
 * @return FI_SUCCESS	 Upon successfully inserting the entry into the vector
 * @return -FI_ENOMEM	 Upon exceeding the available memory
 * @return -FI_EINVAL	 Upon passing a dead or null vector, or an index passed
 *			 the maximum size.
 * @return -FI_ECANCELED Upon an existing non-empty entry being found at index
 * 			 or reaching the maximum vector size.
 */
static inline int _sstmacx_vec_insert_at(sstmacx_vector_t *vec,
				      sstmacx_vec_entry_t *entry,
				      sstmacx_vec_index_t index)
{
	if (OFI_UNLIKELY(!vec || !entry)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "Invalid parameter to "
			  "_sstmacx_vec_insert_at\n");
		return -FI_EINVAL;
	} else {
		return vec->ops->insert_at(vec, entry, index);
	}
}

/**
 * Inserts an entry into the last index of the vector. If the entry at the
 * last index is not empty the insertion will be canceled.
 *
 * @param[in] vec	the vector to insert entry into
 * @param[in] entry	the item to insert into the vector
 *
 * @return FI_SUCCESS	 Upon successfully inserting the entry into the vector
 * @return -FI_EINVAL	 Upon passing a dead vector, or a null
 * 			 entry
 * @return -FI_ECANCELED Upon an existing non-empty entry being found at the
 *			 last index
 */
static inline int _sstmacx_vec_insert_last(sstmacx_vector_t *vec,
					sstmacx_vec_entry_t *entry)
{
	if (OFI_UNLIKELY(!vec || !entry)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "Invalid parameter to "
			  "_sstmacx_vec_insert_last\n");
		return -FI_EINVAL;
	} else {
		return vec->ops->insert_last(vec, entry);
	}
}

/**
 * Inserts an entry into the first index of the vector. If the entry at the
 * first index is not empty the insertion will be canceled.
 *
 * @param[in] vec	the vector to insert entry into
 * @param[in] entry	the item to insert into the vector
 *
 * @return FI_SUCCESS	 Upon successfully inserting the entry into the vector
 * @return -FI_EINVAL	 Upon passing a dead vector, or a null
 * 			 entry
 * @return -FI_ECANCELED Upon an existing non-empty entry being found at index 0
 */
static inline int _sstmacx_vec_insert_first(sstmacx_vector_t *vec,
					 sstmacx_vec_entry_t *entry)
{
	return _sstmacx_vec_insert_at(vec, entry, 0);
}

/**
 * Return the current element in the vector iterator and move
 * the iterator to the next element.
 *
 * @param iter    pointer to the vector iterator
 * @return        pointer to current element in the vector
 */
static inline
sstmacx_vec_entry_t *_sstmacx_vec_iterator_next(struct sstmacx_vector_iter *iter)
{
	if (iter == NULL) {
		SSTMACX_WARN(FI_LOG_EP_DATA, "Invalid parameter to"
			  "_sstmacx_vec_iterator_next\n");
		return NULL;
	} else {
		return iter->vec->ops->iter_next(iter);
	}
}

#endif /* SSTMACX_VECTOR_H_ */

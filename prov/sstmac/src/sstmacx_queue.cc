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
 * Copyright (c) 2015 Los Alamos National Security, LLC. All rights reserved.
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

#include <stdlib.h>
#include "sstmacx.h"
#include "sstmacx_queue.h"

extern "C" int _sstmacx_queue_create(struct sstmacx_queue **queue, alloc_func alloc_item,
		       free_func free_item, size_t entry_size,
		       size_t entry_count)
{
	struct sstmacx_queue *q;
	struct slist_entry *temp;
	int ret = FI_SUCCESS;

	if (!alloc_item || !free_item) {
		ret = -FI_EINVAL;
		goto err;
	}

	q = calloc(1, sizeof(*q));
	if (!q) {
		ret = -FI_ENOMEM;
		goto err;
	}

	q->alloc_item = alloc_item;
	q->free_item = free_item;

	q->entry_size = entry_size;

	slist_init(&q->item_list);
	slist_init(&q->free_list);

	for (size_t count = 0; count < entry_count; count++) {
		temp = q->alloc_item(entry_size);
		if (!temp) {
			ret = -FI_ENOMEM;
			goto err1;
		}

		_sstmacx_queue_enqueue_free(q, temp);
	}

	*queue = q;

	return ret;

err1:
	_sstmacx_queue_destroy(q);
	*queue = NULL;
err:
	return ret;
}

void _sstmacx_queue_destroy(struct sstmacx_queue *queue)
{
	struct slist_entry *temp;

	while ((temp = _sstmacx_queue_dequeue(queue)))
		queue->free_item(temp);

	while ((temp = _sstmacx_queue_dequeue_free(queue)))
		queue->free_item(temp);

	free(queue);
}

struct slist_entry *_sstmacx_queue_peek(struct sstmacx_queue *queue)
{
	return queue->item_list.head;
}

struct slist_entry *_sstmacx_queue_get_free(struct sstmacx_queue *queue)
{
	struct slist_entry *ret;

	ret = _sstmacx_queue_dequeue_free(queue);
	if (!ret)
		ret = queue->alloc_item(queue->entry_size);

	return ret;
}

struct slist_entry *_sstmacx_queue_dequeue(struct sstmacx_queue *queue)
{
	return slist_remove_head(&queue->item_list);
}

struct slist_entry *_sstmacx_queue_dequeue_free(struct sstmacx_queue *queue)
{
	return slist_remove_head(&queue->free_list);
}

void _sstmacx_queue_enqueue(struct sstmacx_queue *queue, struct slist_entry *item)
{
	sstmacx_slist_insert_tail(item, &queue->item_list);
}

void _sstmacx_queue_enqueue_free(struct sstmacx_queue *queue,
			      struct slist_entry *item)
{
	slist_insert_head(item, &queue->free_list);
}

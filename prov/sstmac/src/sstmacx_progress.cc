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
 * Copyright (c) 2017 Cray Inc. All rights reserved.
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

/*
 * Progress common code
 */

#include <stdlib.h>

#include "sstmacx_progress.h"

struct sstmacx_prog_obj {
	struct dlist_entry list;
	int ref_cnt;
	void *obj;
	int (*prog_fn)(void *data);
};


extern "C" int _sstmacx_prog_progress(struct sstmacx_prog_set *set)
{
	struct sstmacx_prog_obj *pobj, *tmp;
	int rc;

	COND_READ_ACQUIRE(set->requires_lock, &set->lock);

	dlist_for_each_safe(&set->prog_objs, pobj, tmp, list) {
		rc = pobj->prog_fn(pobj->obj);
		if (rc) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "Obj(%p) prog function failed: %d\n",
				  pobj, rc);
		}
	}

	COND_RW_RELEASE(set->requires_lock, &set->lock);

	return FI_SUCCESS;
}

extern "C" int _sstmacx_prog_obj_add(struct sstmacx_prog_set *set, void *obj,
		       int (*prog_fn)(void *data))
{
	struct sstmacx_prog_obj *pobj, *tmp;

	COND_WRITE_ACQUIRE(set->requires_lock, &set->lock);

	dlist_for_each_safe(&set->prog_objs, pobj, tmp, list) {
		if (obj == pobj->obj && prog_fn == pobj->prog_fn) {
			pobj->ref_cnt++;
			COND_RW_RELEASE(set->requires_lock, &set->lock);
			return FI_SUCCESS;
		}
	}

	pobj = malloc(sizeof(struct sstmacx_prog_obj));
	if (!pobj) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "Failed to add OBJ to prog set.\n");
		COND_RW_RELEASE(set->requires_lock, &set->lock);
		return -FI_ENOMEM;
	}

	pobj->obj = obj;
	pobj->prog_fn = prog_fn;
	pobj->ref_cnt = 1;
	dlist_init(&pobj->list);
	dlist_insert_tail(&pobj->list, &set->prog_objs);

	COND_RW_RELEASE(set->requires_lock, &set->lock);

	SSTMACX_INFO(FI_LOG_EP_CTRL, "Added obj(%p) to set(%p)\n",
		  obj, set);

	return FI_SUCCESS;
}

extern "C" int _sstmacx_prog_obj_rem(struct sstmacx_prog_set *set, void *obj,
		       int (*prog_fn)(void *data))
{
	struct sstmacx_prog_obj *pobj, *tmp;

	COND_WRITE_ACQUIRE(set->requires_lock, &set->lock);

	dlist_for_each_safe(&set->prog_objs, pobj, tmp, list) {
		if (obj == pobj->obj && prog_fn == pobj->prog_fn) {
			if (!--pobj->ref_cnt) {
				dlist_remove(&pobj->list);
				free(pobj);
				SSTMACX_INFO(FI_LOG_EP_CTRL,
					  "Removed obj(%p) from set(%p)\n",
					  obj, set);
			}
			COND_RW_RELEASE(set->requires_lock, &set->lock);
			return FI_SUCCESS;
		}
	}

	COND_RW_RELEASE(set->requires_lock, &set->lock);

	SSTMACX_WARN(FI_LOG_EP_CTRL, "Object not found on prog set.\n");
	return -FI_EINVAL;
}

extern "C" int _sstmacx_prog_init(struct sstmacx_prog_set *set)
{
	dlist_init(&set->prog_objs);
	rwlock_init(&set->lock);
	set->requires_lock = 1;

	return FI_SUCCESS;
}

extern "C" int _sstmacx_prog_fini(struct sstmacx_prog_set *set)
{
	struct sstmacx_prog_obj *pobj, *tmp;

	COND_WRITE_ACQUIRE(set->requires_lock, &set->lock);

	dlist_for_each_safe(&set->prog_objs, pobj, tmp, list) {
		dlist_remove(&pobj->list);
		free(pobj);
	}

	COND_RW_RELEASE(set->requires_lock, &set->lock);

	rwlock_destroy(&set->lock);

	return FI_SUCCESS;
}


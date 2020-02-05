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

#include "sstmacx_util.h"
#include "sstmacx_smrn.h"

static struct sstmacx_smrn global_smrn;

extern "C" int _sstmacx_smrn_init(void)
{
	int ret;

	fastlock_init(&global_smrn.lock);
	global_smrn.references = 0;
	dlist_init(&global_smrn.rq_head);

	ret = _sstmacx_notifier_init();

	return ret;
}

extern "C" int _sstmacx_smrn_open(struct sstmacx_smrn **smrn)
{
	struct sstmacx_smrn *tmp = &global_smrn;
	int ret = FI_SUCCESS;

	fastlock_acquire(&tmp->lock);
	if (tmp->references == 0)
		ret = _sstmacx_notifier_open(&tmp->notifier);

	if (!ret)
		tmp->references += 1;
	fastlock_release(&tmp->lock);

	if (!ret)
		*smrn = tmp;

	return ret;
}

extern "C" int _sstmacx_smrn_close(struct sstmacx_smrn *smrn)
{
	int ret = FI_SUCCESS;

	fastlock_acquire(&smrn->lock);
	if (smrn->references == 0)
		ret = -FI_EINVAL;

	if (smrn->references == 1)
		ret = _sstmacx_notifier_close(smrn->notifier);

	if (!ret)
		smrn->references -= 1;
	fastlock_release(&smrn->lock);

	return ret;
}

extern "C" int _sstmacx_smrn_monitor(struct sstmacx_smrn *smrn,
	struct sstmacx_smrn_rq *rq,
	void *addr,
	uint64_t len,
	uint64_t cookie,
	struct sstmacx_smrn_context *context)
{
	int ret;

	if (!context || !rq || !smrn)
		return -FI_EINVAL;

	context->rq = rq;
	context->cookie = cookie;

	ret = _sstmacx_notifier_monitor(smrn->notifier, addr,
				len, (uint64_t) context);
	if (ret == FI_SUCCESS)
		SSTMACX_DEBUG(FI_LOG_FABRIC,
				"monitoring addr=%p len=%d cookie=%p "
				"context=%p rq=%p notifier=%p\n",
				addr, len, context->cookie,
				context, rq, smrn->notifier);
	return ret;
}

extern "C" int _sstmacx_smrn_unmonitor(struct sstmacx_smrn *smrn,
	uint64_t cookie,
	struct sstmacx_smrn_context *context)
{
	if (!smrn)
		return -FI_EINVAL;

	if (cookie != context->cookie)
		return -FI_EINVAL;

	return _sstmacx_notifier_unmonitor(smrn->notifier, (uint64_t) context);
}

static void __sstmacx_smrn_read_events(struct sstmacx_smrn *smrn)
{
	int ret;
	struct sstmacx_smrn_context *context;
	struct sstmacx_smrn_rq *rq;
	int len = sizeof(uint64_t);

	do {
		ret = _sstmacx_notifier_get_event(smrn->notifier,
			(void *) &context, len);
		if (ret != len) {
			SSTMACX_DEBUG(FI_LOG_FABRIC,
				"no more events to be read\n");
			break;
		}

		SSTMACX_DEBUG(FI_LOG_FABRIC,
			"found event, context=%p rq=%p cookie=%lx\n",
			context, context->rq, context->cookie);

		rq = context->rq;
		fastlock_acquire(&rq->lock);
		dlist_insert_tail(&context->entry, &rq->list);
		fastlock_release(&rq->lock);
	} while (ret == len);
}

extern "C" int _sstmacx_smrn_get_event(struct sstmacx_smrn *smrn,
	struct sstmacx_smrn_rq *rq,
	struct sstmacx_smrn_context **context)
{
	int ret;

	if (!smrn || !context)
		return -FI_EINVAL;

	__sstmacx_smrn_read_events(smrn);

	fastlock_acquire(&rq->lock);
	if (!dlist_empty(&rq->list)) {
		dlist_pop_front(&rq->list, struct sstmacx_smrn_context,
			*context, entry);
		ret = FI_SUCCESS;
	} else
		ret = -FI_EAGAIN;
	fastlock_release(&rq->lock);

	return ret;
}


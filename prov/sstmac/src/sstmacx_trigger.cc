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
 * Copyright (c) 2016 Cray Inc. All rights reserved.
 * Copyright (c) 2016 Los Alamos National Security, LLC. All rights reserved.
 *
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
 * Triggered operations handling.
 */

#include "sstmacx_trigger.h"
#include "sstmacx_vc.h"
#include "sstmacx.h"

extern "C" int _sstmacx_trigger_queue_req(struct sstmacx_fab_req *req)
{
	struct fi_triggered_context *trigger_context;
	struct fi_trigger_threshold *threshold;
	struct sstmacx_fid_cntr *cntr;
	struct sstmacx_fab_req *r;
	size_t req_thresh;

	trigger_context = (struct fi_triggered_context *)
				req->user_context;
	threshold = &trigger_context->trigger.threshold;
	cntr = container_of(threshold->cntr, struct sstmacx_fid_cntr, cntr_fid);

	if (ofi_atomic_get32(&cntr->cnt) >= threshold->threshold) {
		SSTMACX_INFO(FI_LOG_EP_DATA,
			  "Trigger condition met: %p\n",
			  req);

		/* Trigger condition has already been met. */
		return 1;
	}

	SSTMACX_INFO(FI_LOG_EP_DATA,
		  "Queueing triggered op: %p\n",
		  req);

	fastlock_acquire(&cntr->trigger_lock);
	if (dlist_empty(&cntr->trigger_list)) {
		dlist_init(&req->dlist);
		dlist_insert_head(&req->dlist, &cntr->trigger_list);
	} else {
		req_thresh = threshold->threshold;

		dlist_for_each(&cntr->trigger_list, r, dlist) {
			trigger_context = (struct fi_triggered_context *)
						r->user_context;
			threshold = &trigger_context->trigger.threshold;

			/* Insert new req. after those with equal threshold and
			 * before those with greater threshold. */
			if (req_thresh < threshold->threshold) {
				break;
			}
		}

		dlist_init(&req->dlist);
		dlist_insert_before(&req->dlist, &r->dlist);
	}
	fastlock_release(&cntr->trigger_lock);

	return FI_SUCCESS;
}

void _sstmacx_trigger_check_cntr(struct sstmacx_fid_cntr *cntr)
{
	struct fi_triggered_context *trigger_context;
	struct fi_trigger_threshold *threshold;
	struct sstmacx_fab_req *req, *req2;
	size_t count;

	if (OFI_LIKELY(dlist_empty(&cntr->trigger_list))) {
		return;
	}

	 count = ofi_atomic_get32(&cntr->cnt);

	fastlock_acquire(&cntr->trigger_lock);
	dlist_for_each_safe(&cntr->trigger_list, req, req2, dlist) {
		trigger_context = (struct fi_triggered_context *)
					req->user_context;
		threshold = &trigger_context->trigger.threshold;

		if (count >= threshold->threshold) {
			SSTMACX_INFO(FI_LOG_EP_DATA,
				  "Trigger condition met: %p\n",
				  req);

			dlist_remove_init(&req->dlist);
			req->flags &= ~FI_TRIGGER;
			_sstmacx_vc_queue_tx_req(req);
		} else {
			break;
		}
	}
	fastlock_release(&cntr->trigger_lock);
}

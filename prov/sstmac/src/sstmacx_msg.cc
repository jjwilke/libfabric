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
 * Copyright (c) 2015-2019 Cray Inc. All rights reserved.
 * Copyright (c) 2015-2018 Los Alamos National Security, LLC.
 *                         All rights reserved.
 * Copyright (c) 2019 Triad National Security, LLC. All rights reserved.
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
#include <string.h>
#include <assert.h>

#include "sstmacx.h"
#include "sstmacx_cm_nic.h"
#include "sstmacx_nic.h"
#include "sstmacx_util.h"
#include "sstmacx_ep.h"
#include "sstmacx_hashtable.h"
#include "sstmacx_vc.h"
#include "sstmacx_cntr.h"
#include "sstmacx_av.h"
#include "sstmacx_rma.h"
#include "sstmacx_atomic.h"
#include "sstmacx_cm.h"

#define INVALID_PEEK_FORMAT(fmt) \
	((fmt) == FI_CQ_FORMAT_CONTEXT || (fmt) == FI_CQ_FORMAT_MSG)

#define SSTMACX_TAGGED_PCD_COMPLETION_FLAGS	(FI_MSG | FI_RECV | FI_TAGGED)

smsg_completer_fn_t sstmacx_ep_smsg_completers[];

/*******************************************************************************
 * helper functions
 ******************************************************************************/
/**
 * This function return the receiver's address given that we are at offset cur_len
 * within the send_iov.
 *
 * @param req     the fabric request
 * @param cur_len the current offset at which we found an unaligned head or tail
 * within the sender's iov entries.
 */
static inline uint8_t *__sstmacx_msg_iov_unaligned_recv_addr(struct sstmacx_fab_req *req,
							  size_t cur_len)
{
	int i;

	/* Find the recv_address for the given head data */
	for (i = 0; i < req->msg.recv_iov_cnt; i++) {
		if ((int64_t) cur_len - (int64_t) req->msg.recv_info[i].recv_len < 0) {
			return (uint8_t *) (req->msg.recv_info[i].recv_addr + cur_len);
		} else {
			cur_len -= req->msg.recv_info[i].recv_len;
		}
	}

	return NULL;
}

static inline void __sstmacx_msg_send_alignment(struct sstmacx_fab_req *req)
{
	int i;

	/* Ensure all head and tail fields are initialized properly */
	for (i = 0; i < req->msg.send_iov_cnt; i++) {
		/* Check head for four byte alignment, if not aligned store
		 * the unaligned bytes (<=3) in head */
		if (req->msg.send_info[i].send_addr & SSTMAC_READ_ALIGN_MASK) {
			req->msg.send_info[i].head =
				*(uint32_t *)(req->msg.send_info[i].send_addr &
					      ~SSTMAC_READ_ALIGN_MASK);

			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "Sending %d unaligned head bytes (%x)\n",
				  SSTMAC_READ_ALIGN -
				  (req->msg.send_info[i].send_addr &
				   SSTMAC_READ_ALIGN_MASK),
				  req->msg.send_info[i].head);
		}

		/* Check tail for four byte alignment. */
		if ((req->msg.send_info[i].send_addr +
		     req->msg.send_info[i].send_len) &
		    SSTMAC_READ_ALIGN_MASK) {
			req->msg.send_info[i].tail =
				*(uint32_t *)((req->msg.send_info[i].send_addr +
					       req->msg.send_info[i].send_len) &
					      ~SSTMAC_READ_ALIGN_MASK);

			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "Sending %d unaligned tail bytes (%x)\n",
				  (req->msg.send_info[i].send_addr +
				   req->msg.send_info[i].send_len) &
				  SSTMAC_READ_ALIGN_MASK,
				  req->msg.send_info[i].tail);
		}
	}
}
static inline void __sstmacx_msg_free_rma_txd(struct sstmacx_fab_req *req,
					   struct sstmacx_tx_descriptor *txd)
{
	sstmac_ct_get_post_descriptor_t *cur_ct, *nxt_ct;

	if (txd->sstmac_desc.type & SSTMAC_POST_FMA_GET) {
		for (cur_ct = txd->sstmac_desc.next_descr;
		     cur_ct != NULL;
		     cur_ct = nxt_ct) {
			nxt_ct = cur_ct->next_descr;
			free(cur_ct);
		}
	}
	_sstmacx_nic_tx_free(req->sstmacx_ep->nic, txd);
}

static inline void __sstmacx_msg_free_iov_txds(struct sstmacx_fab_req *req,
					    size_t txd_cnt)
{
	int i;

	for (i = 0; i < txd_cnt; i++) {
		__sstmacx_msg_free_rma_txd(req, req->iov_txds[i]);
	}
}

static void __sstmacx_msg_unpack_data_into_iov(const struct recv_info_t *dest,
					    size_t dest_cnt,
					    uint64_t src, size_t src_len)
{
	static int i;
	static size_t cum_len;
	static size_t offset;
	size_t bwrite;

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "Unpacking data for recvv count (%lu)"
		   " src = %p, dest = %p,"
		   " i = %d, cum_len = %lu, offset = %lu\n",
		   dest_cnt, src, dest, i, cum_len, offset);

	/* Pull out each iov len and base field into the iov */
	while (i < dest_cnt) {
		bwrite = dest[i].recv_len - offset < src_len - cum_len ?
			dest[i].recv_len - offset : src_len - cum_len;

		memcpy((uint8_t *) dest[i].recv_addr + offset,
		       (void *) (src + cum_len), bwrite);

		cum_len += bwrite;

		/* Src exhausted */
		if (cum_len == src_len) {
			offset = dest[i].recv_len - bwrite;
			cum_len = 0;

			/* dest exhausted too, reset the counters */
			if (!offset) {
				i = cum_len = 0;
			}

			return;
		}

		i++;
	}
}

static void __sstmacx_msg_pack_data_from_iov(uint64_t dest, size_t dest_len,
					  const struct iovec *src,
					  size_t src_cnt)
{
	int i;
	size_t cum_len = 0;

	SSTMACX_DEBUG(FI_LOG_EP_CTRL, "Packing data for sendv count (%d)\n",
		   src_cnt);

	/* Pull out each iov len and base field into the dest buffer */
	for (i = 0; i < src_cnt && cum_len < dest_len; i++) {
		memcpy((void *) (dest + cum_len), src[i].iov_base,
		       src[i].iov_len < dest_len - cum_len ?
		       src[i].iov_len : dest_len - cum_len);
		cum_len += src[i].iov_len;
	}
}


/*
 * TODO: this can eventually be used in more places in this
 * but the msg component of the fab request structure would
 * need to be refactored.
 */
static inline int __sstmacx_msg_register_iov(struct sstmacx_fid_ep *ep,
					  const struct iovec *iov,
					  size_t count,
					  struct sstmacx_fid_mem_desc **md_vec)
{
	int i, ret = FI_SUCCESS;
	struct fid_mr *auto_mr = NULL;
	struct sstmacx_fid_domain *dom = ep->domain;

	for (i = 0; i < count; i++) {

		ret = _sstmacx_mr_reg(&dom->domain_fid.fid,
				  iov[i].iov_base,
				  iov[i].iov_len,
				  FI_READ | FI_WRITE, 0,
				  0, 0, &auto_mr, NULL,
				  ep->auth_key, SSTMACX_PROV_REG);

		if (ret != FI_SUCCESS) {
			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				   "Failed to "
				   "auto-register"
				   " local buffer: %s\n",
				   fi_strerror(-ret));

			for (i--; i >= 0; i--) {
				ret = fi_close(&md_vec[i]->mr_fid.fid);
				if (ret != FI_SUCCESS) {
					SSTMACX_FATAL(FI_LOG_DOMAIN,
						"failed to release auto-registered region, "
						"rc=%d\n", ret);
				}
			}

			goto fn_exit;
		}

		md_vec[i] = container_of((void *) auto_mr,
					struct sstmacx_fid_mem_desc,
					mr_fid);
	}

fn_exit:
	return ret;
}

static void __sstmacx_msg_copy_data_to_recv_addr(struct sstmacx_fab_req *req,
					      void *data)
{
	size_t	len;

	SSTMACX_DBG_TRACE(FI_LOG_EP_DATA, "\n");

	len = MIN(req->msg.cum_send_len, req->msg.cum_recv_len);

	switch(req->type) {
	case SSTMACX_FAB_RQ_RECV:
		memcpy((void *)req->msg.recv_info[0].recv_addr, data, len);
		break;

	case SSTMACX_FAB_RQ_RECVV:
	case SSTMACX_FAB_RQ_TRECVV:
		__sstmacx_msg_unpack_data_into_iov(req->msg.recv_info,
						req->msg.recv_iov_cnt,
						(uint64_t) data, len);
		break;

	default:
		SSTMACX_FATAL(FI_LOG_EP_DATA, "Invalid request type: %d", req->type);
		return;
	}
}

static void __sstmacx_msg_queues(struct sstmacx_fid_ep *ep,
			      int tagged,
			      struct sstmacx_tag_storage **posted_queue,
			      struct sstmacx_tag_storage **unexp_queue)
{
	if (tagged) {
		*posted_queue = &ep->tagged_posted_recv_queue;
		*unexp_queue = &ep->tagged_unexp_recv_queue;
	} else {
		*posted_queue = &ep->posted_recv_queue;
		*unexp_queue = &ep->unexp_recv_queue;
	}
}

static void __sstmacx_msg_send_fr_complete(struct sstmacx_fab_req *req,
					struct sstmacx_tx_descriptor *txd)
{
	struct sstmacx_vc *vc = req->vc;

	ofi_atomic_dec32(&vc->outstanding_tx_reqs);
	_sstmacx_nic_tx_free(req->sstmacx_ep->nic, txd);

	_sstmacx_fr_free(req->sstmacx_ep, req);

	/* Schedule VC TX queue in case the VC is 'fenced'. */
	_sstmacx_vc_tx_schedule(vc);
}

static int __recv_err(struct sstmacx_fid_ep *ep, void *context, uint64_t flags,
		      size_t len, void *addr, uint64_t data, uint64_t tag,
		      size_t olen, int err, int prov_errno, void *err_data,
		      size_t err_data_size)
{
	int rc;

	if (ep->recv_cq) {
		rc = _sstmacx_cq_add_error(ep->recv_cq, context, flags, len,
					addr, data, tag, olen, err,
					prov_errno, err_data, err_data_size);
		if (rc != FI_SUCCESS)  {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_cq_add_error returned %d\n",
				  rc);
		}
	}

	if (ep->recv_cntr) {
		rc = _sstmacx_cntr_inc_err(ep->recv_cntr);
		if (rc != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_cntr_inc_err() failed: %d\n",
				  rc);
	}

	return FI_SUCCESS;
}

static int __sstmacx_msg_recv_err(struct sstmacx_fid_ep *ep, struct sstmacx_fab_req *req)
{
	uint64_t flags = FI_RECV | FI_MSG;

	flags |= req->msg.send_flags & FI_TAGGED;

	return __recv_err(ep, req->user_context, flags, req->msg.cum_recv_len,
			  (void *)req->msg.recv_info[0].recv_addr, req->msg.imm,
			  req->msg.tag, 0, FI_ECANCELED,
			  sstmacxu_to_fi_errno(SSTMAC_RC_TRANSACTION_ERROR), NULL, 0);
}

static int __recv_completion(
		struct sstmacx_fid_ep *ep,
		struct sstmacx_fab_req *req,
		uint64_t flags,
		size_t len,
		void *addr)
{
	ssize_t rc;

	if ((req->msg.recv_flags & FI_COMPLETION) && ep->recv_cq) {
		rc = _sstmacx_cq_add_event(ep->recv_cq,
					ep,
					req->user_context,
					flags,
					len,
					addr,
					req->msg.imm,
					req->msg.tag,
					FI_ADDR_NOTAVAIL);
		if (rc != FI_SUCCESS)  {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				"_sstmacx_cq_add_event returned %d\n",
				rc);
		}
	}

	if (ep->recv_cntr) {
		rc = _sstmacx_cntr_inc(ep->recv_cntr);
		if (rc != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_cntr_inc() failed: %d\n",
				  rc);
	}

	return FI_SUCCESS;
}

static int __recv_completion_src(
		struct sstmacx_fid_ep *ep,
		struct sstmacx_fab_req *req,
		uint64_t flags,
		size_t len,
		void *addr,
		fi_addr_t src_addr)
{
	ssize_t rc;
	char *buffer;
	size_t buf_len;

	SSTMACX_DBG_TRACE(FI_LOG_TRACE, "\n");

	if ((req->msg.recv_flags & FI_COMPLETION) && ep->recv_cq) {
		if ((src_addr == FI_ADDR_NOTAVAIL) &&
                    (ep->caps & FI_SOURCE_ERR) != 0) {
			if (ep->domain->addr_format == FI_ADDR_STR) {
				buffer = malloc(SSTMACX_FI_ADDR_STR_LEN);
				rc = _sstmacx_ep_name_to_str(req->vc->sstmacx_ep_name, (char **)&buffer);
				assert(rc == FI_SUCCESS);
				buf_len = SSTMACX_FI_ADDR_STR_LEN;
			} else {
				buffer = malloc(SSTMACX_CQ_MAX_ERR_DATA_SIZE);
				assert(buffer != NULL);
				memcpy(buffer, req->vc->sstmacx_ep_name,
					sizeof(struct sstmacx_ep_name));
				buf_len = sizeof(struct sstmacx_ep_name);
			}
			rc = _sstmacx_cq_add_error(ep->recv_cq,
						req->user_context,
						flags,
						len,
						addr,
						req->msg.imm,
						req->msg.tag,
						0,
						FI_EADDRNOTAVAIL,
						0,
						buffer,
						buf_len);
		} else {
			rc = _sstmacx_cq_add_event(ep->recv_cq,
						ep,
						req->user_context,
						flags,
						len,
						addr,
						req->msg.imm,
						req->msg.tag,
						src_addr);
		}
		if (rc != FI_SUCCESS)  {
			SSTMACX_WARN(FI_LOG_EP_DATA,
					"_sstmacx_cq_add_event returned %d\n",
					rc);
		}
	}

	if (ep->recv_cntr) {
		rc = _sstmacx_cntr_inc(ep->recv_cntr);
		if (rc != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_cntr_inc() failed: %d\n",
				  rc);
	}

	return FI_SUCCESS;
}

/*
 * SSTMAC provider generates a separate CQE to indicate
 * its releasing a FI_MULTI_RECV receive buffer back to
 * the application.
 */
static void __sstmacx_msg_mrecv_completion(void *obj)
{
	int ret;
	struct sstmacx_fab_req *req = (struct sstmacx_fab_req *)obj;

	if (req->msg.recv_flags & FI_LOCAL_MR) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "freeing auto-reg MR: %p\n",
			req->msg.recv_md[0]);
		ret = fi_close(&req->msg.recv_md[0]->mr_fid.fid);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_DOMAIN,
				"failed to close auto-registered region, "
			"ret %s\n", fi_strerror(-ret));
		}
	}

	ret = __recv_completion(req->sstmacx_ep,
				req,
				FI_MULTI_RECV,
				0UL,
				NULL);
	if (ret != FI_SUCCESS) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA,
			  "__recv_completion failed for multi recv"
			  " complete: %d\n",
				  ret);
	}

	_sstmacx_fr_free(req->sstmacx_ep, req);
}

static inline int __sstmacx_msg_recv_completion(struct sstmacx_fid_ep *ep,
					     struct sstmacx_fab_req *req)
{
	int ret;
	uint64_t flags = FI_RECV | FI_MSG;
	size_t len;
	void *recv_addr = NULL;
	fi_addr_t src_addr;

	flags |= req->msg.send_flags & (FI_TAGGED | FI_REMOTE_CQ_DATA);
	flags |= req->msg.recv_flags & (FI_PEEK | FI_CLAIM | FI_DISCARD);

	len = MIN(req->msg.cum_send_len, req->msg.cum_recv_len);


	if (OFI_UNLIKELY(req->msg.recv_flags & FI_MULTI_RECV))
		recv_addr = (void *)req->msg.recv_info[0].recv_addr;

	/*
	 * Deal with possible truncation
	 */
	if (OFI_LIKELY(req->msg.cum_send_len <= req->msg.cum_recv_len)) {

		if (OFI_LIKELY(!(ep->caps & FI_SOURCE))) {
			ret = __recv_completion(ep,
						 req,
						 flags,
						 len,
						 recv_addr);
		} else {
			src_addr = _sstmacx_vc_peer_fi_addr(req->vc);
			ret = __recv_completion_src(ep,
						     req,
						     flags,
						     len,
						     recv_addr,
						     src_addr);
		}

	} else {

		ret = __recv_err(ep,
				 req->user_context,
				 flags,
				 len,
				 recv_addr,
				 req->msg.imm,
				 req->msg.tag,
				 req->msg.cum_send_len - req->msg.cum_recv_len,
				 FI_ETRUNC,
				 FI_ETRUNC, NULL, 0);
	};

	/*
	 * if i'm child of a FI_MULTI_RECV request, decrement
	 * ref count
	 */

	if (req->msg.parent != NULL) {
		_sstmacx_ref_put(req->msg.parent);
	}
	return ret;
}

static int __sstmacx_msg_send_err(struct sstmacx_fid_ep *ep, struct sstmacx_fab_req *req)
{
	uint64_t flags = FI_SEND | FI_MSG;
	int rc;

	flags |= req->msg.send_flags & FI_TAGGED;

	if (ep->send_cq) {
		rc = _sstmacx_cq_add_error(ep->send_cq, req->user_context,
					flags, 0, 0, 0, 0, 0, FI_ECANCELED,
					sstmacxu_to_fi_errno(SSTMAC_RC_TRANSACTION_ERROR),
					NULL, 0);
		if (rc != FI_SUCCESS)  {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				   "_sstmacx_cq_add_error() returned %d\n",
				   rc);
		}
	}

	if (ep->send_cntr) {
		rc = _sstmacx_cntr_inc_err(ep->send_cntr);
		if (rc != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_cntr_inc() failed: %d\n",
				  rc);
	}

	return FI_SUCCESS;
}

static int __sstmacx_msg_send_completion(struct sstmacx_fid_ep *ep,
				      struct sstmacx_fab_req *req)
{
	uint64_t flags = FI_SEND | FI_MSG;
	int rc;

	flags |= req->msg.send_flags & FI_TAGGED;

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "send_cq = %p\n", ep->send_cq);

	if ((req->msg.send_flags & FI_COMPLETION) && ep->send_cq) {
		rc = _sstmacx_cq_add_event(ep->send_cq, ep, req->user_context,
					flags, 0, 0, 0, 0, FI_ADDR_NOTAVAIL);
		if (rc != FI_SUCCESS)  {
			SSTMACX_WARN(FI_LOG_EP_DATA,
					"_sstmacx_cq_add_event returned %d\n",
					rc);
		}
	}

	if (ep->send_cntr) {
		rc = _sstmacx_cntr_inc(ep->send_cntr);
		if (rc != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_cntr_inc() failed: %d\n",
				  rc);
	}

	return FI_SUCCESS;
}

static int __sstmacx_rndzv_req_send_fin(void *arg)
{
	struct sstmacx_fab_req *req = (struct sstmacx_fab_req *)arg;
	struct sstmacx_nic *nic;
	struct sstmacx_fid_ep *ep;
	struct sstmacx_tx_descriptor *txd;
	sstmac_return_t status;
	int rc;

	SSTMACX_DBG_TRACE(FI_LOG_EP_DATA, "\n");

	ep = req->sstmacx_ep;
	assert(ep != NULL);

	nic = ep->nic;
	assert(nic != NULL);

	rc = _sstmacx_nic_tx_alloc(nic, &txd);
	if (rc) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA,
				"_sstmacx_nic_tx_alloc() failed: %d\n",
				rc);
		return -FI_ENOSPC;
	}

	txd->rndzv_fin_hdr.req_addr = req->msg.rma_id;
	txd->rndzv_fin_hdr.status = req->msg.status;

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "req_addr = %p\n",
		   (void *) txd->rndzv_fin_hdr.req_addr);

	txd->req = req;

	txd->completer_fn = sstmacx_ep_smsg_completers[SSTMACX_SMSG_T_RNDZV_FIN];

	COND_ACQUIRE(nic->requires_lock, &nic->lock);
	status = SSTMAC_SmsgSendWTag(req->vc->sstmac_ep,
			&txd->rndzv_fin_hdr, sizeof(txd->rndzv_fin_hdr),
			NULL, 0, txd->id, SSTMACX_SMSG_T_RNDZV_FIN);
	if ((status == SSTMAC_RC_SUCCESS) &&
		(ep->domain->data_progress == FI_PROGRESS_AUTO))
		_sstmacx_rma_post_irq(req->vc);

	COND_RELEASE(nic->requires_lock, &nic->lock);

	if (status == SSTMAC_RC_NOT_DONE) {
		_sstmacx_nic_tx_free(nic, txd);
		SSTMACX_DEBUG(FI_LOG_EP_DATA,
			  "SSTMAC_SmsgSendWTag returned %s\n",
			  sstmac_err_str[status]);
	} else if (status != SSTMAC_RC_SUCCESS) {
		_sstmacx_nic_tx_free(nic, txd);
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "SSTMAC_SmsgSendWTag returned %s\n",
			  sstmac_err_str[status]);
	}

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "Initiated RNDZV_FIN, req: %p\n", req);

	return sstmacxu_to_fi_errno(status);
}

static void __sstmacx_msg_copy_unaligned_get_data(struct sstmacx_fab_req *req)
{
	int head_off, head_len, tail_len;
	void *addr;

	head_off = req->msg.send_info[0].send_addr & SSTMAC_READ_ALIGN_MASK;
	head_len = head_off ? SSTMAC_READ_ALIGN - head_off : 0;
	tail_len = (req->msg.send_info[0].send_addr + req->msg.send_info[0].send_len) &
		SSTMAC_READ_ALIGN_MASK;

	if (head_off) {
		addr = (uint8_t *)&req->msg.send_info[0].head + head_off;

		SSTMACX_DEBUG(FI_LOG_EP_DATA,
			  "writing %d bytes to head (%p, %hxx)\n",
			  head_len, req->msg.recv_info[0].recv_addr,
			  *(uint32_t *)addr);
		memcpy((void *)req->msg.recv_info[0].recv_addr, addr, head_len);
	}

	if (tail_len) {
		addr = (void *)(req->msg.recv_info[0].recv_addr +
				req->msg.send_info[0].send_len -
				tail_len);

		SSTMACX_DEBUG(FI_LOG_EP_DATA,
			  "writing %d bytes to tail (%p, %hxx)\n",
			  tail_len, addr, req->msg.send_info[0].tail);
		memcpy((void *)addr, &req->msg.send_info[0].tail, tail_len);
	}
}

static inline void __sstmacx_msg_iov_cpy_unaligned_head_tail_data(struct sstmacx_fab_req *req)
{
	int i, head_off, head_len, tail_len;
	void *addr, *recv_addr;
	size_t cur_len = 0;

#if ENABLE_DEBUG
	for (i = 0; i < req->msg.send_iov_cnt; i++) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "req->msg.send_info[%d].head = 0x%x\n"
			   "req->msg.send_info[%d].tail = 0x%x\n", i,
			   req->msg.send_info[i].head, i, req->msg.send_info[i].tail);
	}
#endif

	/* Copy out the original head/tail data sent across in the control message */
	for (i = 0; i < req->msg.send_iov_cnt; i++) {
		head_off = req->msg.send_info[i].send_addr & SSTMAC_READ_ALIGN_MASK;
		head_len = head_off ? SSTMAC_READ_ALIGN - head_off : 0;

		if (head_off) {
			recv_addr = __sstmacx_msg_iov_unaligned_recv_addr(req, cur_len);

			if (recv_addr) {
				addr = (uint8_t *)&req->msg.send_info[i].head + head_off;

				SSTMACX_DEBUG(FI_LOG_EP_DATA,
					  "writing %d bytes to head (%p, 0x%x) for i = %d\n",
					  head_len, recv_addr,
					  *(uint32_t *)addr, i);
				memcpy(recv_addr, addr, head_len);
			}
		}

		tail_len = (req->msg.send_info[i].send_addr + req->msg.send_info[i].send_len) &
			SSTMAC_READ_ALIGN_MASK;

		if (tail_len) {
			recv_addr = __sstmacx_msg_iov_unaligned_recv_addr(req,
								       cur_len +
								       req->msg.send_info[i].send_len - tail_len);

			if (recv_addr) {
				SSTMACX_DEBUG(FI_LOG_EP_DATA,
					  "writing %d bytes to tail (%p, 0x%x)\n",
					  tail_len, recv_addr, req->msg.send_info[i].tail);
				memcpy((void *)recv_addr, &req->msg.send_info[i].tail, tail_len);
			}
		}

		cur_len += req->msg.send_info[i].send_len;
	}

#if ENABLE_DEBUG
	for (i = 0; i < req->msg.recv_iov_cnt; i++) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "req->msg.recv_info[%d].tail_len = %d\n"
			   "req->msg.recv_info[%d].head_len = %d\n",
			   i, req->msg.recv_info[i].tail_len,
			   i, req->msg.recv_info[i].head_len);
	}
#endif

	/* Copy out the "middle" head and tail data found when building the iov request */
	for (i = 0; i < req->msg.recv_iov_cnt; i++) {
		if (req->msg.recv_info[i].tail_len) {
			addr = (void *) ((uint8_t *) req->int_tx_buf +
			       (SSTMAC_READ_ALIGN * i));

			recv_addr = (void *) (req->msg.recv_info[i].recv_addr +
					      req->msg.recv_info[i].recv_len -
					      req->msg.recv_info[i].tail_len);

			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "writing %d bytes to mid-tail (%p, 0x%x)\n",
				  req->msg.recv_info[i].tail_len,
				  recv_addr, *(uint32_t *)addr);

			memcpy(recv_addr, addr, req->msg.recv_info[i].tail_len);
		}

		if (req->msg.recv_info[i].head_len) {
			/* Since we move the remote addr backwards to a four
			 * byte address and read four bytes, ensure that
			 * what we read from the int_tx_buf is just the actual
			 * head data we are interested in.
			 */
			addr = (void *) ((uint8_t *) req->int_tx_buf +
			     (SSTMAC_READ_ALIGN * (i + SSTMACX_MAX_MSG_IOV_LIMIT)) +
			     SSTMAC_READ_ALIGN - req->msg.recv_info[i].head_len);
			recv_addr = (void *) req->msg.recv_info[i].recv_addr;

			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "writing %d bytes to mid-head (%p, 0x%x)\n",
				  req->msg.recv_info[i].head_len,
				  recv_addr, *(uint32_t *)addr);

			memcpy(recv_addr, addr, req->msg.recv_info[i].head_len);
		}
	}
}

static int __sstmacx_rndzv_req_complete(void *arg, sstmac_return_t tx_status)
{
	struct sstmacx_tx_descriptor *txd = (struct sstmacx_tx_descriptor *)arg;
	struct sstmacx_fab_req *req = txd->req;
	int ret, rc;

	if (req->msg.recv_flags & SSTMACX_MSG_GET_TAIL) {
		/* There are two TXDs involved with this request, an RDMA
		 * transfer to move the middle block and an FMA transfer to
		 * move unaligned tail data.  If this is the FMA TXD, store the
		 * unaligned bytes.  Bytes are copied from the request to the
		 * user buffer once both TXDs arrive. */
		if (txd->sstmac_desc.type == SSTMAC_POST_FMA_GET)
			req->msg.send_info[0].tail =
				*(uint32_t *)req->int_tx_buf;

		/* Remember any failure.  Retransmit both TXDs once both are
		 * complete. */
		req->msg.status |= tx_status;

		if (ofi_atomic_dec32(&req->msg.outstanding_txds) == 1) {
			_sstmacx_nic_tx_free(req->sstmacx_ep->nic, txd);
			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "Received first RDMA chain TXD, req: %p\n",
				  req);
			return FI_SUCCESS;
		}

		tx_status = req->msg.status;
	}

	_sstmacx_nic_tx_free(req->sstmacx_ep->nic, txd);

	if (tx_status != SSTMAC_RC_SUCCESS) {
		if (SSTMACX_EP_RDM(req->sstmacx_ep->type) &&
			_sstmacx_req_replayable(req)) {
			req->tx_failures++;
			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "Requeueing failed request: %p\n", req);
			return _sstmacx_vc_requeue_work_req(req);
		}

		if (!SSTMACX_EP_DGM(req->sstmacx_ep->type)) {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "Dropping failed request: %p\n", req);
			ret = __sstmacx_msg_recv_err(req->sstmacx_ep,
						  req);
			if (ret != FI_SUCCESS)
				SSTMACX_WARN(FI_LOG_EP_DATA,
					  "__sstmacx_msg_send_err() failed: %s\n",
					  fi_strerror(-ret));
			__sstmacx_msg_send_fr_complete(req, txd);
			return ret;
		}

		req->msg.status = tx_status;
		req->work_fn = __sstmacx_rndzv_req_send_fin;
		return _sstmacx_vc_requeue_work_req(req);
	}

	__sstmacx_msg_copy_unaligned_get_data(req);

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "Completed RNDZV GET, req: %p\n", req);

	if ((req->msg.recv_flags & FI_LOCAL_MR) &&
		(req->msg.parent == NULL)) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "freeing auto-reg MR: %p\n",
			  req->msg.recv_md[0]);
		rc = fi_close(&req->msg.recv_md[0]->mr_fid.fid);
		if (rc != FI_SUCCESS) {
			SSTMACX_FATAL(FI_LOG_DOMAIN,
				"failed to close auto-registered region, "
				"rc=%d\n", rc);
		}
	}

	req->work_fn = __sstmacx_rndzv_req_send_fin;
	return _sstmacx_vc_requeue_work_req(req);
}

/*
 * As the completer fn is called in the nic's progress loop, the remote
 * side's fabric request will keep track of the state of this rndzv iov
 * transaction, once the outstanding_txds reaches zero for this fabric
 * request, we are either ready to generate CQEs and send the fin msg
 * back to the sender or rebuild and retransmit the iov txds.
 */
static int __sstmacx_rndzv_iov_req_build(void *arg);
static int __sstmacx_rndzv_iov_req_complete(void *arg, sstmac_return_t tx_status)
{
	struct sstmacx_tx_descriptor *txd = (struct sstmacx_tx_descriptor *)arg;
	struct sstmacx_fab_req *req = txd->req;
	int i, ret = FI_SUCCESS;
	struct sstmacx_auth_key *info __attribute__ ((unused));
	int rc;

	SSTMACX_DBG_TRACE(FI_LOG_EP_DATA, "\n");

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "req->msg.outstanding_txds = %d\n",
		   ofi_atomic_get32(&req->msg.outstanding_txds));

	req->msg.status |= tx_status;

	__sstmacx_msg_free_rma_txd(req, txd);

	if (ofi_atomic_dec32(&req->msg.outstanding_txds) == 0) {

		/* All the txd's are complete, we just need our unaligned heads
		 * and tails now
		 */
		__sstmacx_msg_iov_cpy_unaligned_head_tail_data(req);
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "req->msg.recv_flags == FI_LOCAL_MR "
			   "is %s, req->msg.recv_iov_cnt = %lu\n",
			   req->msg.recv_flags & FI_LOCAL_MR ? "true" : "false",
			   req->msg.recv_iov_cnt);

		if (req->msg.status != FI_SUCCESS) {

			if (SSTMACX_EP_RDM(req->sstmacx_ep->type) &&
				_sstmacx_req_replayable(req)) {
				req->tx_failures++;
				/* Build and re-tx the entire iov request if the
				 * ep type is "reliable datagram" */
				req->work_fn = __sstmacx_rndzv_iov_req_build;
				return _sstmacx_vc_requeue_work_req(req);
			}

			if (!SSTMACX_EP_DGM(req->sstmacx_ep->type)) {
				SSTMACX_WARN(FI_LOG_EP_DATA,
					  "Dropping failed request: %p\n", req);
				ret = __sstmacx_msg_send_err(req->sstmacx_ep,
						    req);
				if (ret != FI_SUCCESS)
					SSTMACX_WARN(FI_LOG_EP_DATA,
						  "__sstmacx_msg_send_err() failed: %s\n",
						  fi_strerror(-ret));
				__sstmacx_msg_send_fr_complete(req, txd);
				return ret;
			}
		} else {
			if (req->msg.recv_flags & FI_LOCAL_MR) {

				if (req->sstmacx_ep->domain->using_vmdh) {
					info = req->sstmacx_ep->auth_key;
					assert(info);
				}

				for (i = 0; i < req->msg.recv_iov_cnt; i++) {
					SSTMACX_DEBUG(FI_LOG_EP_DATA, "freeing auto"
						  "-reg MR: %p\n",
						  req->msg.recv_md[i]);
					rc = fi_close(&req->msg.recv_md[i]->mr_fid.fid);
					if (rc != FI_SUCCESS) {
						SSTMACX_FATAL(FI_LOG_DOMAIN,
							"failed to close auto-registration, "
							"rc=%d\n", rc);
					}
				}
			}
		}

		/* Generate remote CQE and send fin msg back to sender */
		req->work_fn = __sstmacx_rndzv_req_send_fin;
		return _sstmacx_vc_requeue_work_req(req);
	}

	/*
	 * Successful tx, continue until the txd counter reaches zero
	 * or we can't recover from the error.
	 */
	return ret;
}

static int __sstmacx_rndzv_req_xpmem(struct sstmacx_fab_req *req)
{
	int ret = FI_SUCCESS, send_idx = 0, recv_idx = 0, i;
	size_t cpy_len, recv_len;
	uint64_t recv_ptr = 0UL;
	struct sstmacx_xpmem_access_handle *access_hndl;

	recv_len = req->msg.recv_info[0].recv_len;
	recv_ptr = req->msg.recv_info[0].recv_addr;

	/* to avoid small xpmem cross maps first get/release
	 * xpmem handles for all of the send_iov_cnt bufs
	 */

	for (i = 0; i < req->msg.send_iov_cnt; i++) {
		ret = _sstmacx_xpmem_access_hndl_get(req->sstmacx_ep->xpmem_hndl,
						  req->vc->peer_apid,
						  req->msg.send_info[i].send_addr,
						  req->msg.send_info[i].send_len,
						  &access_hndl);
		ret = _sstmacx_xpmem_access_hndl_put(access_hndl);
	}

	/* Copy data from/to (>=1) iovec entries */
	while (send_idx < req->msg.send_iov_cnt) {
		cpy_len = MIN(recv_len, req->msg.send_info[send_idx].send_len);

		/*
		 * look up mapping from other EP
		 */
		ret = _sstmacx_xpmem_access_hndl_get(req->sstmacx_ep->xpmem_hndl,
						  req->vc->peer_apid,
						  req->msg.send_info[send_idx].send_addr,
						  cpy_len,
						  &access_hndl);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_DATA, "_sstmacx_xpmem_access_hndl_get failed %s\n",
				  fi_strerror(-ret));
			req->msg.status = SSTMAC_RC_TRANSACTION_ERROR;
			return ret;
		}

		/*
		 * pull the data from the other process' address space
		 */
		ret = _sstmacx_xpmem_copy(access_hndl,
				       (void *)recv_ptr,
				       (void *)req->msg.send_info[send_idx].send_addr,
				       cpy_len);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_DATA, "_sstmacx_xpmem_vaddr_copy failed %s\n",
				  fi_strerror(-ret));
			req->msg.status = SSTMAC_RC_TRANSACTION_ERROR;
			_sstmacx_xpmem_access_hndl_put(access_hndl);
			return ret;
		}

		ret = _sstmacx_xpmem_access_hndl_put(access_hndl);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_DATA, "_sstmacx_xpmem_access_hndl_put failed %s\n",
				  fi_strerror(-ret));
		}

		/* Update the local and remote addresses */
		recv_len -= cpy_len;

		/* We have exhausted the current recv (and possibly send)
		 * buffer */
		if (recv_len == 0) {
			recv_idx++;

			/* We cannot receive any more. */
			if (recv_idx == req->msg.recv_iov_cnt)
				break;

			recv_ptr = req->msg.recv_info[recv_idx].recv_addr;
			recv_len = req->msg.recv_info[recv_idx].recv_len;

			/* Also exhausted send buffer */
			if (cpy_len == req->msg.send_info[send_idx].send_len) {
				send_idx++;
			} else {
				req->msg.send_info[send_idx].send_addr += cpy_len;
				req->msg.send_info[send_idx].send_len -= cpy_len;
			}
		} else {	/* Just exhausted current send buffer. */
			send_idx++;
			recv_ptr += cpy_len;
		}
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "send_idx = %d, recv_idx = %d\n",
				send_idx, recv_idx);
	}

	/*
	 * set the req send fin and reschedule req
	 */

	req->msg.status = SSTMAC_RC_SUCCESS;  /* hmph */
	req->work_fn = __sstmacx_rndzv_req_send_fin;
	return _sstmacx_vc_queue_work_req(req);
}

static int __sstmacx_rndzv_req(void *arg)
{
	struct sstmacx_fab_req *req = (struct sstmacx_fab_req *)arg;
	struct sstmacx_fid_ep *ep = req->sstmacx_ep;
	struct sstmacx_nic *nic = ep->nic;
	struct sstmacx_tx_descriptor *txd, *tail_txd = NULL;
	sstmac_return_t status;
	int rc;
	int use_tx_cq_blk = 0;
	struct fid_mr *auto_mr = NULL;
	int inject_err = _sstmacx_req_inject_err(req);
	int head_off, head_len, tail_len;
	void *tail_data = NULL;

	SSTMACX_DBG_TRACE(FI_LOG_EP_DATA, "\n");

	if (req->vc->modes & SSTMACX_VC_MODE_XPMEM)
		return  __sstmacx_rndzv_req_xpmem(req);

	if (!req->msg.recv_md[0]) {
		rc = _sstmacx_mr_reg(&ep->domain->domain_fid.fid,
				  (void *)req->msg.recv_info[0].recv_addr,
				  req->msg.recv_info[0].recv_len,
				  FI_READ | FI_WRITE, 0, 0, 0,
				  &auto_mr, NULL, ep->auth_key, SSTMACX_PROV_REG);
		if (rc != FI_SUCCESS) {
			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "Failed to auto-register local buffer: %d\n",
				  rc);

			return -FI_EAGAIN;
		}
		req->msg.recv_flags |= FI_LOCAL_MR;
		req->msg.recv_md[0] = container_of(auto_mr,
						   struct sstmacx_fid_mem_desc,
						   mr_fid);
		req->msg.recv_info[0].mem_hndl = req->msg.recv_md[0]->mem_hndl;
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "auto-reg MR: %p\n", auto_mr);
	}

	rc = _sstmacx_nic_tx_alloc(nic, &txd);
	if (rc) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "_sstmacx_nic_tx_alloc() failed: %d\n",
			  rc);
		return -FI_ENOSPC;
	}

	txd->completer_fn = __sstmacx_rndzv_req_complete;
	txd->req = req;


	use_tx_cq_blk = (ep->domain->data_progress == FI_PROGRESS_AUTO) ? 1 : 0;

	txd->sstmac_desc.type = SSTMAC_POST_RDMA_GET;
	txd->sstmac_desc.cq_mode = SSTMAC_CQMODE_GLOBAL_EVENT;
	txd->sstmac_desc.dlvr_mode = SSTMAC_DLVMODE_PERFORMANCE;
	txd->sstmac_desc.local_mem_hndl = req->msg.recv_info[0].mem_hndl;
	txd->sstmac_desc.remote_mem_hndl = req->msg.rma_mdh;
	txd->sstmac_desc.rdma_mode = 0;
	txd->sstmac_desc.src_cq_hndl = (use_tx_cq_blk) ?
					nic->tx_cq_blk : nic->tx_cq;

	head_off = req->msg.send_info[0].send_addr & SSTMAC_READ_ALIGN_MASK;
	head_len = head_off ? SSTMAC_READ_ALIGN - head_off : 0;
	tail_len = (req->msg.send_info[0].send_addr + req->msg.send_info[0].send_len) &
			SSTMAC_READ_ALIGN_MASK;

	txd->sstmac_desc.local_addr = (uint64_t)req->msg.recv_info[0].recv_addr + head_len;
	txd->sstmac_desc.remote_addr = (uint64_t)req->msg.send_info[0].send_addr + head_len;
	txd->sstmac_desc.length = req->msg.send_info[0].send_len - head_len - tail_len;

	if (req->msg.recv_flags & SSTMACX_MSG_GET_TAIL) {
		/* The user ended up with a send matching a receive with a
		 * buffer that is too short and unaligned... what a way to
		 * behave.  We could not have forseen which unaligned data to
		 * send across with the rndzv_start request, so we do an extra
		 * TX here to pull the random unaligned bytes. */
		rc = _sstmacx_nic_tx_alloc(nic, &tail_txd);
		if (rc) {
			_sstmacx_nic_tx_free(nic, txd);
			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "_sstmacx_nic_tx_alloc() failed (tail): %d\n",
				  rc);
			return -FI_ENOSPC;
		}

		if (req->int_tx_buf_e == NULL) {
			req->int_tx_buf_e = _sstmacx_ep_get_int_tx_buf(ep);
			if (req->int_tx_buf_e == NULL) {
				SSTMACX_FATAL(FI_LOG_EP_DATA,
					  "RAN OUT OF INT_TX_BUFS");
				/* TODO return error */
			}
		}

		req->int_tx_buf = ((struct sstmacx_int_tx_buf *)
				   req->int_tx_buf_e)->buf;
		req->int_tx_mdh = _sstmacx_ep_get_int_tx_mdh(req->int_tx_buf_e);

		tail_txd->completer_fn = __sstmacx_rndzv_req_complete;
		tail_txd->req = req;

		tail_data = (void *)((req->msg.send_info[0].send_addr +
				      req->msg.send_info[0].send_len) &
				      ~SSTMAC_READ_ALIGN_MASK);

		tail_txd->sstmac_desc.type = SSTMAC_POST_FMA_GET;
		tail_txd->sstmac_desc.cq_mode = SSTMAC_CQMODE_GLOBAL_EVENT;
		tail_txd->sstmac_desc.dlvr_mode = SSTMAC_DLVMODE_PERFORMANCE;
		tail_txd->sstmac_desc.local_mem_hndl = req->int_tx_mdh;
		tail_txd->sstmac_desc.remote_mem_hndl = req->msg.rma_mdh;
		tail_txd->sstmac_desc.rdma_mode = 0;
		tail_txd->sstmac_desc.src_cq_hndl = nic->tx_cq;
		tail_txd->sstmac_desc.local_addr = (uint64_t)req->int_tx_buf;
		tail_txd->sstmac_desc.remote_addr = (uint64_t)tail_data;
		tail_txd->sstmac_desc.length = SSTMAC_READ_ALIGN;

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "Using two GETs\n");
	}

	COND_ACQUIRE(nic->requires_lock, &nic->lock);

	if (inject_err) {
		_sstmacx_nic_txd_err_inject(nic, txd);
		status = SSTMAC_RC_SUCCESS;
	} else {
		status = SSTMAC_PostRdma(req->vc->sstmac_ep, &txd->sstmac_desc);
	}

	if (status != SSTMAC_RC_SUCCESS) {
		COND_RELEASE(nic->requires_lock, &nic->lock);
		if (tail_txd)
			_sstmacx_nic_tx_free(nic, tail_txd);
		_sstmacx_nic_tx_free(nic, txd);
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "SSTMAC_PostRdma failed: %s\n",
			  sstmac_err_str[status]);

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "\n");
		return sstmacxu_to_fi_errno(status);
	}

	if (req->msg.recv_flags & SSTMACX_MSG_GET_TAIL) {
		if (OFI_UNLIKELY(inject_err)) {
			_sstmacx_nic_txd_err_inject(nic, tail_txd);
			status = SSTMAC_RC_SUCCESS;
		} else {
			status = SSTMAC_PostFma(req->vc->sstmac_ep,
					     &tail_txd->sstmac_desc);
		}

		if (status != SSTMAC_RC_SUCCESS) {
			COND_RELEASE(nic->requires_lock, &nic->lock);
			_sstmacx_nic_tx_free(nic, tail_txd);

			/* Wait for the first TX to complete, then retransmit
			 * the entire thing. */
			ofi_atomic_set32(&req->msg.outstanding_txds, 1);
			req->msg.status = SSTMAC_RC_TRANSACTION_ERROR;

			SSTMACX_DEBUG(FI_LOG_EP_DATA, "SSTMAC_PostFma() failed: %s\n",
				  sstmac_err_str[status]);
			return FI_SUCCESS;
		}

		/* Wait for both TXs to complete, then process the request. */
		ofi_atomic_set32(&req->msg.outstanding_txds, 2);
		req->msg.status = SSTMAC_RC_SUCCESS;

	}

	COND_RELEASE(nic->requires_lock, &nic->lock);

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "Initiated RNDZV GET, req: %p\n", req);

	return sstmacxu_to_fi_errno(status);
}

/* Attempt to post the iov txds */
static int __sstmacx_rndzv_iov_req_post(void *arg)
{
	struct sstmacx_fab_req *req = (struct sstmacx_fab_req *)arg;
	struct sstmacx_tx_descriptor *txd;
	sstmac_return_t status;
	struct sstmacx_nic *nic = req->sstmacx_ep->nic;
	int i, iov_txd_cnt = ofi_atomic_get32(&req->msg.outstanding_txds);

	assert(nic != NULL);

	SSTMACX_DBG_TRACE(FI_LOG_EP_DATA, "\n");

	if (OFI_UNLIKELY(iov_txd_cnt == 0))
		return -FI_EAGAIN;

	COND_ACQUIRE(nic->requires_lock, &nic->lock);

	for (i = 0, txd = req->iov_txds[0];
	     i < iov_txd_cnt;
	     txd = req->iov_txds[++i]) {
		if (txd->sstmac_desc.type & SSTMAC_POST_RDMA_GET) {
			status = SSTMAC_PostRdma(req->vc->sstmac_ep,
					      &txd->sstmac_desc);
		} else {
			status = SSTMAC_CtPostFma(req->vc->sstmac_ep,
					       &txd->sstmac_desc);
		}

		if (status != SSTMAC_RC_SUCCESS) {
			COND_RELEASE(nic->requires_lock, &nic->lock);

			SSTMACX_WARN(FI_LOG_EP_DATA, "%s failed on txd %p: with "
				  "%s\n",
				  txd->sstmac_desc.type & SSTMAC_POST_RDMA_GET ?
				  "SSTMAC_PostRdma" : "SSTMAC_CtPostFma", txd,
				  sstmac_err_str[status]);

			return sstmacxu_to_fi_errno(status);
		}
	}

	COND_RELEASE(nic->requires_lock, &nic->lock);

	return FI_SUCCESS;
}

/*
 * Dequeued a iov work req on the remote endpoint, initiate the pull of data.
 */
static int __sstmacx_rndzv_iov_req_build(void *arg)
{
	int ret = FI_SUCCESS, send_idx, recv_idx, use_tx_cq_blk;
	struct sstmacx_fab_req *req = (struct sstmacx_fab_req *)arg;
	struct sstmacx_fid_ep *ep = req->sstmacx_ep;
	struct sstmacx_nic *nic = ep->nic;
	sstmac_ep_handle_t sstmac_ep = req->vc->sstmac_ep;
	struct sstmacx_tx_descriptor *txd = NULL, *ct_txd = NULL;
	size_t recv_len, send_len, get_len, send_cnt, recv_cnt, txd_cnt, ht_len;
	uint64_t recv_ptr = 0UL, send_ptr = 0UL;
	/* TODO: Should this be the sender's rndzv thresh instead? */
	size_t rndzv_thresh = ep->domain->params.msg_rendezvous_thresh;
	sstmac_ct_get_post_descriptor_t *cur_ct = NULL;
	void **next_ct = NULL;
	int head_off, head_len, tail_len;

	SSTMACX_DBG_TRACE(FI_LOG_EP_DATA, "\n");

	if (req->vc->modes & SSTMACX_VC_MODE_XPMEM)
		return  __sstmacx_rndzv_req_xpmem(req);

	txd_cnt = 0;
	send_cnt = req->msg.send_iov_cnt;

	recv_ptr = req->msg.recv_info[0].recv_addr;
	recv_len = req->msg.recv_info[0].recv_len;
	recv_cnt = req->msg.recv_iov_cnt;

	send_ptr = req->msg.send_info[0].send_addr;
	send_len = req->msg.send_info[0].send_len;

	use_tx_cq_blk = (ep->domain->data_progress == FI_PROGRESS_AUTO);

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "send_cnt = %lu, recv_cnt = %lu\n",
		   send_cnt, recv_cnt);

	/* Ensure the user's recv buffer is registered for recv/recvv */
	if (!req->msg.recv_md[0]) {
		struct fid_mr *auto_mr;

		for (recv_idx = 0; recv_idx < recv_cnt; recv_idx++) {
			auto_mr = NULL;

			ret = _sstmacx_mr_reg(&ep->domain->domain_fid.fid,
					  (void *)
					  req->msg.recv_info[recv_idx].recv_addr,
					  req->msg.recv_info[recv_idx].recv_len,
					  FI_READ | FI_WRITE, 0, 0, 0,
					  &auto_mr, NULL, ep->auth_key, SSTMACX_PROV_REG);

			if (ret != FI_SUCCESS) {
				SSTMACX_DEBUG(FI_LOG_EP_DATA,
					   "Failed to auto-register"
					   " local buffer: %s\n",
					   fi_strerror(-ret));

				for (recv_idx--; recv_idx >= 0; recv_idx--)
					fi_close(&req->msg.recv_md[recv_idx]->mr_fid.fid);

				return ret;
			}

			req->msg.recv_md[recv_idx] = container_of(
				(void *) auto_mr,
				struct sstmacx_fid_mem_desc,
				mr_fid);

			req->msg.recv_info[recv_idx].mem_hndl =
				req->msg.recv_md[recv_idx]->mem_hndl;

			SSTMACX_DEBUG(FI_LOG_EP_DATA, "auto-reg MR: %p\n",
				   req->msg.recv_md[recv_idx]);

		}
		req->msg.recv_flags |= FI_LOCAL_MR;
	}

	recv_idx = send_idx = 0;

	/* Iterate through the buffers and build the Fma and Rdma requests! */
	while (send_idx < send_cnt) {
		get_len = MIN(recv_len, send_len);

		/* Begin alignment checks
		 *
		 * Each "mid-head" and "mid-tail" (resulting from the send pointer
		 * and length being adjusted to match the smaller posted recv buf in
		 * this loop) will be added to one or more chained transactions
		 * below.
		 *
		 * The original heads and tails (sent across in the control
		 * message) must be accounted for below in order to GET the
		 * correct, now four byte aligned, "body" section of the
		 * message.
		 */
		if (send_ptr & SSTMAC_READ_ALIGN_MASK ||
		    (send_ptr + get_len) & SSTMAC_READ_ALIGN_MASK) {
			if (req->int_tx_buf_e == NULL) {
				req->int_tx_buf_e = _sstmacx_ep_get_int_tx_buf(ep);

				/* There are no available int_tx bufs */
				if (req->int_tx_buf_e == NULL) {
					ofi_atomic_set32(&req->msg.outstanding_txds, 0);
					req->work_fn = __sstmacx_rndzv_iov_req_post;
					return _sstmacx_vc_queue_work_req(req);
				}

				req->int_tx_buf = ((struct sstmacx_int_tx_buf *)
						req->int_tx_buf_e)->buf;
				req->int_tx_mdh = _sstmacx_ep_get_int_tx_mdh(
						req->int_tx_buf_e);
				SSTMACX_DEBUG(FI_LOG_EP_DATA,
				    "req->int_tx_buf = %p\n", req->int_tx_buf);
			}

			head_off = send_ptr & SSTMAC_READ_ALIGN_MASK;
			head_len = head_off ? SSTMAC_READ_ALIGN - head_off : 0;
			tail_len = (send_ptr + get_len) & SSTMAC_READ_ALIGN_MASK;

			ht_len = (size_t) (head_len + tail_len);

			/* TODO: handle this. */
			if (ht_len > recv_len) {
				SSTMACX_FATAL(FI_LOG_EP_DATA, "The head tail data "
					   "length exceeds the matching receive"
					   "buffer length.\n");
			}

			/* found a mid-head? (see "Begin alignment" comment block) */
			req->msg.recv_info[recv_idx].head_len = (send_ptr != req->msg.send_info[send_idx].send_addr) ?
				head_len : 0;

			/* found a mid-tail? (see "Begin alignment" comment block) */
			req->msg.recv_info[recv_idx].tail_len = (send_len > recv_len) ?
				tail_len : 0;

			/* Update the local and remote addresses */
			get_len -= ht_len;
			send_len -= ht_len;
			recv_len -= ht_len;

			send_ptr += head_len;
			recv_ptr += head_len;

			/* Add to existing ct */
			if (ct_txd) {
				if (req->msg.recv_info[recv_idx].tail_len) {
					cur_ct = *next_ct = malloc(sizeof(sstmac_ct_get_post_descriptor_t));

					if (cur_ct == NULL) {
						SSTMACX_DEBUG(FI_LOG_EP_DATA,
							   "Failed to allocate "
							   "sstmac FMA get chained "
							   "descriptor.");

						/* +1 to ensure we free the
						 * current chained txd */
						__sstmacx_msg_free_iov_txds(req, txd_cnt + 1);
						return -FI_ENOSPC;
					}

					cur_ct->ep_hndl = sstmac_ep;
					cur_ct->remote_mem_hndl = req->msg.send_info[send_idx].mem_hndl;
					cur_ct->local_mem_hndl = req->int_tx_mdh;
					cur_ct->length = SSTMAC_READ_ALIGN;
					cur_ct->remote_addr = (send_ptr + get_len + tail_len) & ~SSTMAC_READ_ALIGN_MASK;
					cur_ct->local_addr = (uint64_t) (((uint8_t *) req->int_tx_buf) + (SSTMAC_READ_ALIGN * recv_idx));
					next_ct = &cur_ct->next_descr;
				}

				if (req->msg.recv_info[recv_idx].head_len) {
					cur_ct = *next_ct = malloc(sizeof(sstmac_ct_get_post_descriptor_t));

					if (cur_ct == NULL) {
						SSTMACX_DEBUG(FI_LOG_EP_DATA,
							   "Failed to allocate "
							   "sstmac FMA get chained "
							   "descriptor.");

						/* +1 to ensure we free the
						 * current chained txd */
						__sstmacx_msg_free_iov_txds(req, txd_cnt + 1);
						return -FI_ENOSPC;
					}

					cur_ct->ep_hndl = sstmac_ep;
					cur_ct->remote_mem_hndl = req->msg.send_info[send_idx].mem_hndl;
					cur_ct->local_mem_hndl = req->int_tx_mdh;
					cur_ct->length = SSTMAC_READ_ALIGN;
					cur_ct->remote_addr = send_ptr - SSTMAC_READ_ALIGN;
					cur_ct->local_addr = (uint64_t) (((uint8_t *) req->int_tx_buf) +
						(SSTMAC_READ_ALIGN * (recv_idx + SSTMACX_MAX_MSG_IOV_LIMIT)));
					next_ct = &cur_ct->next_descr;
				}
			} else { 	/* Start a new ct */
				if (req->msg.recv_info[recv_idx].tail_len) {
					SSTMACX_DEBUG(FI_LOG_EP_DATA, "New FMA"
						   " CT\n");
					ret = _sstmacx_nic_tx_alloc(nic, &ct_txd);

					if (ret != FI_SUCCESS) {
						/* We'll try again. */
						SSTMACX_DEBUG(FI_LOG_EP_DATA,
							  "_sstmacx_nic_tx_alloc()"
							  " returned %s\n",
							  fi_strerror(-ret));

						__sstmacx_msg_free_iov_txds(req, txd_cnt);
						return -FI_ENOSPC;
					}

					ct_txd->completer_fn = __sstmacx_rndzv_iov_req_complete;
					ct_txd->req = req;

					ct_txd->sstmac_desc.type = SSTMAC_POST_FMA_GET;
					ct_txd->sstmac_desc.cq_mode = SSTMAC_CQMODE_GLOBAL_EVENT;
					ct_txd->sstmac_desc.dlvr_mode = SSTMAC_DLVMODE_PERFORMANCE;
					ct_txd->sstmac_desc.rdma_mode = 0;
					ct_txd->sstmac_desc.src_cq_hndl = (use_tx_cq_blk) ? nic->tx_cq_blk : nic->tx_cq;

					ct_txd->sstmac_desc.remote_addr = (send_ptr + get_len + tail_len) & ~SSTMAC_READ_ALIGN_MASK;
					ct_txd->sstmac_desc.remote_mem_hndl = req->msg.send_info[send_idx].mem_hndl;

					ct_txd->sstmac_desc.local_addr = (uint64_t) ((uint8_t *) req->int_tx_buf + (SSTMAC_READ_ALIGN * recv_idx));
					ct_txd->sstmac_desc.local_mem_hndl = req->int_tx_mdh;

					ct_txd->sstmac_desc.length = SSTMAC_READ_ALIGN;

					next_ct = &ct_txd->sstmac_desc.next_descr;
				}

				if (req->msg.recv_info[recv_idx].head_len) {
					if (req->msg.recv_info[recv_idx].tail_len) { /* Existing FMA CT */
						cur_ct = *next_ct = malloc(sizeof(sstmac_ct_get_post_descriptor_t));
						if (cur_ct == NULL) {
							SSTMACX_DEBUG(FI_LOG_EP_DATA,
								   "Failed to allocate "
								   "sstmac FMA get chained "
								   "descriptor.");

							/* +1 to ensure we free the
							 * current chained txd */
							__sstmacx_msg_free_iov_txds(req, txd_cnt + 1);
							return -FI_ENOSPC;
						}

						cur_ct->ep_hndl = sstmac_ep;
						cur_ct->remote_mem_hndl = req->msg.send_info[send_idx].mem_hndl;
						cur_ct->local_mem_hndl = req->int_tx_mdh;
						cur_ct->length = SSTMAC_READ_ALIGN;
						cur_ct->remote_addr = send_ptr - SSTMAC_READ_ALIGN;
						cur_ct->local_addr = (uint64_t) (((uint8_t *) req->int_tx_buf) +
								(SSTMAC_READ_ALIGN * (recv_idx + SSTMACX_MAX_MSG_IOV_LIMIT)));
						next_ct = &cur_ct->next_descr;
					} else { /* New FMA ct */
						SSTMACX_DEBUG(FI_LOG_EP_DATA, "New FMA"
							   " CT\n");
						ret = _sstmacx_nic_tx_alloc(nic, &ct_txd);

						if (ret != FI_SUCCESS) {
							/* We'll try again. */
							SSTMACX_DEBUG(FI_LOG_EP_DATA,
								  "_sstmacx_nic_tx_alloc()"
								  " returned %s\n",
								  fi_strerror(-ret));

							__sstmacx_msg_free_iov_txds(req, txd_cnt);
							return -FI_ENOSPC;
						}

						ct_txd->completer_fn = __sstmacx_rndzv_iov_req_complete;
						ct_txd->req = req;

						ct_txd->sstmac_desc.type = SSTMAC_POST_FMA_GET;
						ct_txd->sstmac_desc.cq_mode = SSTMAC_CQMODE_GLOBAL_EVENT;
						ct_txd->sstmac_desc.dlvr_mode = SSTMAC_DLVMODE_PERFORMANCE;
						ct_txd->sstmac_desc.rdma_mode = 0;
						ct_txd->sstmac_desc.src_cq_hndl = (use_tx_cq_blk) ? nic->tx_cq_blk : nic->tx_cq;

						ct_txd->sstmac_desc.remote_addr = send_ptr - SSTMAC_READ_ALIGN;
						ct_txd->sstmac_desc.remote_mem_hndl = req->msg.send_info[send_idx].mem_hndl;

						ct_txd->sstmac_desc.local_addr = (uint64_t) ((uint8_t *) req->int_tx_buf +
								(SSTMAC_READ_ALIGN * (recv_idx + SSTMACX_MAX_MSG_IOV_LIMIT)));
						ct_txd->sstmac_desc.local_mem_hndl = req->int_tx_mdh;

						ct_txd->sstmac_desc.length = SSTMAC_READ_ALIGN;

						next_ct = &ct_txd->sstmac_desc.next_descr;
					}
				}
			}
		} else { 	/* no head/tail found */
			head_len = tail_len = 0;
			req->msg.recv_info[recv_idx].head_len = req->msg.recv_info[recv_idx].tail_len = 0;
		}
		/* End alignment checks */

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "send_info[%d].send_len = %lu,"
			   " recv_len = %lu, get_len = %lu, head_len = %d,"
			   " tail_len = %d, req->msg.recv_info[%d].tail_len = %u\n"
			   "req->msg.recv_info[%d].head_len = %u, "
			   "recv_ptr(head) = %p, recv_ptr(tail) = %p\n", send_idx,
			   send_len, recv_len, get_len, head_len, tail_len, recv_idx,
			   req->msg.recv_info[recv_idx].tail_len, recv_idx,
			   req->msg.recv_info[recv_idx].head_len, (void *) (recv_ptr - head_len),
			   (void *) (recv_ptr + get_len));

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "txd = %p, send_ptr = %p, "
			   "send_ptr + get_len = %p, recv_ptr = %p\n",
			   txd, (void *) send_ptr, (void *)(send_ptr + get_len),
			   recv_ptr);

		if (get_len >= rndzv_thresh) { /* Build the rdma txd */
			ret = _sstmacx_nic_tx_alloc(nic, &txd);

			if (ret != FI_SUCCESS) {
				/* We'll try again. */
				SSTMACX_DEBUG(FI_LOG_EP_DATA, "_sstmacx_nic_tx_alloc()"
					  " returned %s\n",
					  fi_strerror(-ret));

				__sstmacx_msg_free_iov_txds(req, txd_cnt);
				return -FI_ENOSPC;
			}

			txd->completer_fn = __sstmacx_rndzv_iov_req_complete;
			txd->req = req;

			txd->sstmac_desc.type = SSTMAC_POST_RDMA_GET;
			txd->sstmac_desc.cq_mode = SSTMAC_CQMODE_GLOBAL_EVENT;
			txd->sstmac_desc.dlvr_mode = SSTMAC_DLVMODE_PERFORMANCE;
			txd->sstmac_desc.local_mem_hndl = req->msg.recv_info[recv_idx].mem_hndl;
			txd->sstmac_desc.remote_mem_hndl = req->msg.send_info[send_idx].mem_hndl;
			txd->sstmac_desc.rdma_mode = 0;
			txd->sstmac_desc.src_cq_hndl = (use_tx_cq_blk) ? nic->tx_cq_blk : nic->tx_cq;

			txd->sstmac_desc.local_addr = recv_ptr;
			txd->sstmac_desc.remote_addr = send_ptr;
			txd->sstmac_desc.length = get_len;

			req->iov_txds[txd_cnt++] = txd;
			txd = NULL;
		} else if (get_len) {		       /* Build the Ct txd */
			if (!ct_txd) {
				SSTMACX_DEBUG(FI_LOG_EP_DATA, "New FMA"
					   " CT\n");
				ret = _sstmacx_nic_tx_alloc(nic, &ct_txd);
				if (ret != FI_SUCCESS) {
					/* We'll try again. */
					SSTMACX_DEBUG(FI_LOG_EP_DATA,
						  "_sstmacx_nic_tx_alloc()"
						  " returned %s\n",
						  fi_strerror(-ret));

					__sstmacx_msg_free_iov_txds(req, txd_cnt);
					return -FI_ENOSPC;
				}

				ct_txd->completer_fn = __sstmacx_rndzv_iov_req_complete;
				ct_txd->req = req;

				ct_txd->sstmac_desc.type = SSTMAC_POST_FMA_GET;
				ct_txd->sstmac_desc.cq_mode = SSTMAC_CQMODE_GLOBAL_EVENT;
				ct_txd->sstmac_desc.dlvr_mode = SSTMAC_DLVMODE_PERFORMANCE;
				ct_txd->sstmac_desc.local_mem_hndl = req->msg.recv_info[recv_idx]. mem_hndl;

				ct_txd->sstmac_desc.remote_mem_hndl = req->msg.send_info[send_idx].mem_hndl;
				ct_txd->sstmac_desc.rdma_mode = 0;
				ct_txd->sstmac_desc.src_cq_hndl = (use_tx_cq_blk) ? nic->tx_cq_blk : nic->tx_cq;

				ct_txd->sstmac_desc.local_addr = recv_ptr;
				ct_txd->sstmac_desc.remote_addr = send_ptr;
				ct_txd->sstmac_desc.length = get_len;

				next_ct = &ct_txd->sstmac_desc.next_descr;
			} else {
				cur_ct = *next_ct = malloc(sizeof(sstmac_ct_get_post_descriptor_t));

				if (cur_ct == NULL) {
					SSTMACX_DEBUG(FI_LOG_EP_DATA,
						   "Failed to allocate "
						   "sstmac FMA get chained "
						   "descriptor.");

					/* +1 to ensure we free the
					 * current chained txd */
					__sstmacx_msg_free_iov_txds(req, txd_cnt + 1);
					return -FI_ENOSPC;
				}

				cur_ct->ep_hndl = sstmac_ep;
				cur_ct->length = get_len;
				cur_ct->remote_addr = send_ptr;
				cur_ct->remote_mem_hndl = req->msg.send_info[send_idx].mem_hndl;
				cur_ct->local_addr = (uint64_t) recv_ptr;
				cur_ct->local_mem_hndl = req->msg.recv_info[recv_idx].mem_hndl;

				next_ct = &cur_ct->next_descr;
			}
		}

		/* Update the recv len */
		recv_len -= get_len;

		/* We have exhausted the current recv (and possibly send)
		 * buffer */
		if (recv_len == 0) {
			recv_idx++;

			/* We cannot receive any more. */
			if (recv_idx == recv_cnt)
				break;

			recv_ptr = req->msg.recv_info[recv_idx].recv_addr;
			recv_len = req->msg.recv_info[recv_idx].recv_len;

			/* Also exhausted send buffer */
			if (get_len == send_len) {
				send_idx++;
				send_ptr = req->msg.send_info[send_idx].send_addr;
				send_len = req->msg.send_info[send_idx].send_len;
			} else {
				send_ptr += (get_len + tail_len);
				send_len -= get_len;
			}
		} else {	/* Just exhausted current send buffer. */
			send_idx++;
			send_ptr = req->msg.send_info[send_idx].send_addr;
			send_len = req->msg.send_info[send_idx].send_len;
			recv_ptr += (get_len + tail_len);
		}
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "send_idx = %d, recv_idx = %d\n",
			   send_idx, recv_idx);
	}

	/*
	 * If we ran out of buffer space on the sender's/receiver's side in the
	 * middle of building the ct, we must terminate and add that ct to the
	 * queue. Note that if the last txd built was a rdma txd then the txd
	 * will have been queued and txd will have a NULL value.
	 */
	if (ct_txd) {
		*next_ct = NULL;
		req->iov_txds[txd_cnt++] = ct_txd;
	}

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "txd_cnt = %lu\n", txd_cnt);
	ofi_atomic_set32(&req->msg.outstanding_txds, txd_cnt);

	/* All the txd's are built, update the work_fn */
	req->work_fn = __sstmacx_rndzv_iov_req_post;

	/* Put this request back on work Q.
	 * TODO: Should we put it at the beginning of the work Q? */
	ret = _sstmacx_vc_queue_work_req(req);
	return ret;
}

/*******************************************************************************
 * SSTMAC SMSG callbacks invoked upon completion of an SMSG message at the sender.
 ******************************************************************************/

static int __comp_eager_msg_w_data(void *data, sstmac_return_t tx_status)
{
	struct sstmacx_tx_descriptor *tdesc = (struct sstmacx_tx_descriptor *)data;
	struct sstmacx_fab_req *req = tdesc->req;
	int ret = FI_SUCCESS;

	if (tx_status != SSTMAC_RC_SUCCESS) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "Failed transaction: %p\n", req);
		ret = __sstmacx_msg_send_err(req->sstmacx_ep, req);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "__sstmacx_msg_send_err() failed: %s\n",
				  fi_strerror(-ret));
	} else {
		/* Successful delivery.  Generate completions. */
		ret = __sstmacx_msg_send_completion(req->sstmacx_ep, req);

		/*
		 * For fi_sendv we must free the temporary buf used to flatten
		 * the user's iovec.
		 */
		if (req->type == SSTMACX_FAB_RQ_SENDV ||
		    req->type == SSTMACX_FAB_RQ_TSENDV) {
			free((void *) req->msg.send_info[0].send_addr);
		}

		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "__sstmacx_msg_send_completion() failed: %d\n",
				  ret);
	}

	__sstmacx_msg_send_fr_complete(req, tdesc);

	return FI_SUCCESS;
}

static int __comp_eager_msg_w_data_ack(void *data, sstmac_return_t tx_status)
{
	return -FI_ENOSYS;
}

static int __comp_eager_msg_data_at_src(void *data, sstmac_return_t tx_status)
{
	return -FI_ENOSYS;
}

static int __comp_eager_msg_data_at_src_ack(void *data, sstmac_return_t tx_status)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_rts(void *data, sstmac_return_t tx_status)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_rtr(void *data, sstmac_return_t tx_status)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_cookie(void *data, sstmac_return_t tx_status)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_send_done(void *data, sstmac_return_t tx_status)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_recv_done(void *data, sstmac_return_t tx_status)
{
	return -FI_ENOSYS;
}

/* Completed request to start rendezvous send. */
static int __comp_rndzv_start(void *data, sstmac_return_t tx_status)
{
	struct sstmacx_tx_descriptor *txd = (struct sstmacx_tx_descriptor *)data;
	struct sstmacx_fab_req *req = txd->req;
	int ret;

	if (tx_status != SSTMAC_RC_SUCCESS) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "Failed transaction: %p\n", txd->req);
		ret = __sstmacx_msg_send_err(req->sstmacx_ep, req);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "__sstmacx_msg_send_err() failed: %s\n",
				  fi_strerror(-ret));
		__sstmacx_msg_send_fr_complete(req, txd);
	} else {
		/* Just free the TX descriptor for now.  The request remains
		 * active until the remote peer notifies us that they're done
		 * with the send buffer. */
		_sstmacx_nic_tx_free(txd->req->sstmacx_ep->nic, txd);

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "Completed RNDZV_START, req: %p\n",
			  txd->req);
	}

	return FI_SUCCESS;
}

/* Notified sender that rendezvous data has been moved.  Rendezvous send
 * complete.  Generate Completions. */
static int __comp_rndzv_fin(void *data, sstmac_return_t tx_status)
{
	int ret = FI_SUCCESS;
	struct sstmacx_tx_descriptor *tdesc = (struct sstmacx_tx_descriptor *)data;
	struct sstmacx_fab_req *req = tdesc->req;

	if (tx_status != SSTMAC_RC_SUCCESS || req->msg.status != SSTMAC_RC_SUCCESS) {
		/* TODO should this be fatal? A request will sit waiting at the
		 * peer. */
		SSTMACX_WARN(FI_LOG_EP_DATA, "Failed transaction: %p\n", req);
		ret = __sstmacx_msg_recv_err(req->sstmacx_ep, req);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
					"__sstmacx_msg_recv_err() failed: %d\n",
					ret);
	} else {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "Completed RNDZV_FIN, req: %p\n",
			  req);

		ret = __sstmacx_msg_recv_completion(req->sstmacx_ep, req);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "__sstmacx_msg_recv_completion() failed: %d\n",
				  ret);
	}

	_sstmacx_nic_tx_free(req->sstmacx_ep->nic, tdesc);
	_sstmacx_fr_free(req->sstmacx_ep, req);

	return FI_SUCCESS;
}

smsg_completer_fn_t sstmacx_ep_smsg_completers[] = {
	[SSTMACX_SMSG_T_EGR_W_DATA] = __comp_eager_msg_w_data,
	[SSTMACX_SMSG_T_EGR_W_DATA_ACK] = __comp_eager_msg_w_data_ack,
	[SSTMACX_SMSG_T_EGR_GET] = __comp_eager_msg_data_at_src,
	[SSTMACX_SMSG_T_EGR_GET_ACK] = __comp_eager_msg_data_at_src_ack,
	[SSTMACX_SMSG_T_RNDZV_RTS] = __comp_rndzv_msg_rts,
	[SSTMACX_SMSG_T_RNDZV_RTR] = __comp_rndzv_msg_rtr,
	[SSTMACX_SMSG_T_RNDZV_COOKIE] = __comp_rndzv_msg_cookie,
	[SSTMACX_SMSG_T_RNDZV_SDONE] = __comp_rndzv_msg_send_done,
	[SSTMACX_SMSG_T_RNDZV_RDONE] = __comp_rndzv_msg_recv_done,
	[SSTMACX_SMSG_T_RNDZV_START] = __comp_rndzv_start,
	[SSTMACX_SMSG_T_RNDZV_FIN] = __comp_rndzv_fin,
	[SSTMACX_SMSG_T_RNDZV_IOV_START] = __comp_rndzv_start
};


/*******************************************************************************
 * SSTMAC SMSG callbacks invoked upon receipt of an SMSG message.
 * These callback functions are invoked with the lock for the nic
 * associated with the vc already held.
 ******************************************************************************/
/*
 * Handle SMSG message with tag SSTMACX_SMSG_T_EGR_W_DATA
 */

static inline struct sstmacx_fab_req *
		__handle_mrecv_req(struct sstmacx_fab_req *mrecv_req,
				   struct sstmacx_fid_ep *ep,
				   uint64_t len,
				   struct sstmacx_tag_storage *queue)
{
	struct sstmacx_fab_req *req = NULL;

	req = _sstmacx_fr_alloc(ep);
	if (req == NULL) {
		return NULL;
	}

	/*
	 * set recv related fields in request,
	 * and adjust mrecv buffer pointer and
	 * space remaining
	 */

	req->type = SSTMACX_FAB_RQ_RECV;
	ofi_atomic_initialize32(&req->msg.outstanding_txds, 0);
	req->msg.recv_flags = mrecv_req->msg.recv_flags;
	req->msg.recv_flags |= FI_MULTI_RECV;
	req->msg.recv_info[0].recv_addr =
			mrecv_req->msg.mrecv_buf_addr;
	req->msg.recv_info[0].recv_len =
			mrecv_req->msg.mrecv_space_left;
	req->msg.recv_md[0] = mrecv_req->msg.recv_md[0];
	req->msg.recv_info[0].mem_hndl = mrecv_req->msg.recv_info[0].mem_hndl;
	req->user_context = mrecv_req->user_context;
	req->msg.cum_recv_len = mrecv_req->msg.mrecv_space_left;

	req->msg.parent = mrecv_req;
	if (req->msg.parent)
		_sstmacx_ref_get(req->msg.parent);

	mrecv_req->msg.mrecv_space_left -= len;
	mrecv_req->msg.mrecv_buf_addr += len;

	if ((int64_t)mrecv_req->msg.mrecv_space_left  <
			ep->min_multi_recv) {
		_sstmacx_remove_tag(queue, mrecv_req);
		_sstmacx_ref_put(mrecv_req);
	} else {
		SSTMACX_DEBUG(FI_LOG_EP_DATA,
			"Re-using multi-recv req: %p\n", mrecv_req);
	}

	return req;
}

static int __smsg_eager_msg_w_data(void *data, void *msg)
{
	int ret = FI_SUCCESS;
	sstmac_return_t status;
	struct sstmacx_vc *vc = (struct sstmacx_vc *)data;
	struct sstmacx_smsg_eager_hdr *hdr = (struct sstmacx_smsg_eager_hdr *)msg;
	struct sstmacx_fid_ep *ep;
	struct sstmacx_fab_req *req = NULL;
	void *data_ptr;
	struct sstmacx_tag_storage *unexp_queue;
	struct sstmacx_tag_storage *posted_queue;
	int tagged;

	SSTMACX_DBG_TRACE(FI_LOG_EP_DATA, "\n");

	ep = vc->ep;
	assert(ep);

	data_ptr = (void *)((char *)msg + sizeof(*hdr));

	tagged = !!(hdr->flags & FI_TAGGED);
	__sstmacx_msg_queues(ep, tagged, &posted_queue, &unexp_queue);

	/* Lookup a matching posted request. */
	req = _sstmacx_match_tag(posted_queue, hdr->msg_tag, 0, FI_PEEK, NULL,
			      &vc->peer_addr);
	if (req) {
		if (req->type == SSTMACX_FAB_RQ_MRECV) {
			req = __handle_mrecv_req(req, ep, hdr->len, posted_queue);
			if (req == NULL) {
				return -FI_ENOMEM;
			}
		}

		req->addr = vc->peer_addr;
		req->sstmacx_ep = ep;
		req->vc = vc;

		req->msg.cum_send_len = hdr->len;
		req->msg.send_flags = hdr->flags;
		req->msg.send_iov_cnt = 1;
		req->msg.tag = hdr->msg_tag;
		req->msg.imm = hdr->imm;

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "Matched req: %p (%p, %u)\n",
			   req, req->msg.recv_info[0].recv_addr,
			   req->msg.cum_send_len);

		__sstmacx_msg_copy_data_to_recv_addr(req, data_ptr);

		__sstmacx_msg_recv_completion(ep, req);

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "Freeing req: %p\n", req);

		/*
		 * Dequeue and free the request.
		 */
		_sstmacx_remove_tag(posted_queue, req);
		_sstmacx_fr_free(ep, req);
	} else {
		/* Add new unexpected receive request. */
		req = _sstmacx_fr_alloc(ep);
		if (req == NULL) {
			return -FI_ENOMEM;
		}

		/* TODO: Buddy alloc */
		req->msg.send_info[0].send_addr = (uint64_t)malloc(hdr->len);
		if (OFI_UNLIKELY(req->msg.send_info[0].send_addr == 0ULL)) {
			_sstmacx_fr_free(ep, req);
			return -FI_ENOMEM;
		}

		req->type = SSTMACX_FAB_RQ_RECV;
		req->addr = vc->peer_addr;
		req->sstmacx_ep = ep;
		req->vc = vc;

		req->msg.cum_send_len = hdr->len;
		req->msg.send_info[0].send_len = hdr->len;
		req->msg.send_iov_cnt = 1;
		req->msg.send_flags = hdr->flags;
		req->msg.tag = hdr->msg_tag;
		req->msg.imm = hdr->imm;
		req->msg.parent = NULL;

		memcpy((void *)req->msg.send_info[0].send_addr, data_ptr, hdr->len);
		req->addr = vc->peer_addr;

		_sstmacx_insert_tag(unexp_queue, req->msg.tag, req, ~0);

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "New req: %p (%u)\n",
			  req, req->msg.cum_send_len);
	}

	status = SSTMAC_SmsgRelease(vc->sstmac_ep);
	if (OFI_UNLIKELY(status != SSTMAC_RC_SUCCESS)) {
		SSTMACX_WARN(FI_LOG_EP_DATA,
				"SSTMAC_SmsgRelease returned %s\n",
				sstmac_err_str[status]);
		ret = sstmacxu_to_fi_errno(status);
	}

	return ret;
}

/*
 * this function will probably not be used unless we need
 * some kind of explicit flow control to handle unexpected
 * receives
 */

static int __smsg_eager_msg_w_data_ack(void *data, void *msg)
{
	return -FI_ENOSYS;
}

/*
 * Handle SMSG message with tag SSTMACX_SMSG_T_EGR_GET
 */
static int __smsg_eager_msg_data_at_src(void *data, void *msg)
{
	return -FI_ENOSYS;
}

/*
 * Handle SMSG message with tag SSTMACX_SMSG_T_EGR_GET_ACK
 */
static int  __smsg_eager_msg_data_at_src_ack(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_rts(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_rtr(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_cookie(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_send_done(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_recv_done(void *data, void *msg)
{
	return -FI_ENOSYS;
}

/* Received SMSG rendezvous start message.  Try to match a posted receive and
 * start pulling data. */
static int __smsg_rndzv_start(void *data, void *msg)
{
	int ret = FI_SUCCESS;
	sstmac_return_t status;
	struct sstmacx_vc *vc = (struct sstmacx_vc *)data;
	struct sstmacx_smsg_rndzv_start_hdr *hdr =
			(struct sstmacx_smsg_rndzv_start_hdr *)msg;
	struct sstmacx_fid_ep *ep;
	struct sstmacx_fab_req *req = NULL;
	struct sstmacx_tag_storage *unexp_queue;
	struct sstmacx_tag_storage *posted_queue;
	int tagged;

	SSTMACX_DBG_TRACE(FI_LOG_EP_DATA, "\n");

	ep = vc->ep;
	assert(ep);

	tagged = !!(hdr->flags & FI_TAGGED);
	__sstmacx_msg_queues(ep, tagged, &posted_queue, &unexp_queue);

	req = _sstmacx_match_tag(posted_queue, hdr->msg_tag, 0, FI_PEEK, NULL,
			      &vc->peer_addr);

	if (req) {
		if (req->type == SSTMACX_FAB_RQ_MRECV) {
			req = __handle_mrecv_req(req, ep, hdr->len,
						 posted_queue);
			if (req == NULL) {
				return -FI_ENOMEM;
			}
		}

		req->addr = vc->peer_addr;
		req->sstmacx_ep = ep;
		req->vc = vc;
		req->tx_failures = 0;

		/* Check if a second GET for unaligned data is needed. */
		if (hdr->len > req->msg.recv_info[0].recv_len &&
		    ((hdr->addr + req->msg.recv_info[0].recv_len) & SSTMAC_READ_ALIGN_MASK)) {
			req->msg.recv_flags |= SSTMACX_MSG_GET_TAIL;
		}

		req->msg.send_info[0].send_addr = hdr->addr;
		req->msg.send_info[0].send_len =
			MIN(hdr->len, req->msg.cum_recv_len);
		req->msg.send_info[0].mem_hndl = hdr->mdh;
		req->msg.cum_send_len = hdr->len;
		req->msg.send_iov_cnt = 1;
		req->msg.send_flags = hdr->flags;
		req->msg.tag = hdr->msg_tag;
		req->msg.imm = hdr->imm;
		req->msg.rma_mdh = hdr->mdh;
		req->msg.rma_id = hdr->req_addr;
		req->msg.send_info[0].head = hdr->head;
		req->msg.send_info[0].tail = hdr->tail;

		if (req->type == SSTMACX_FAB_RQ_RECV) {
			/* fi_send is rndzv with recv */

			SSTMACX_DEBUG(FI_LOG_EP_DATA, "recv rndzv start - POSTED,"
				   " req = %p\n", req);
			req->work_fn = __sstmacx_rndzv_req;
		} else if (req->type == SSTMACX_FAB_RQ_RECVV ||
			   req->type == SSTMACX_FAB_RQ_TRECVV) {
			/* fi_send is rndzv with recvv */

			SSTMACX_DEBUG(FI_LOG_EP_DATA, "recvv rndzv start - POSTED,"
				   " req = %p\n", req);

			req->work_fn = __sstmacx_rndzv_iov_req_build;
		}

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "Matched req: %p (%p, %u)\n",
			  req, req->msg.recv_info[0].recv_addr,
			  req->msg.send_info[0].send_len);

		_sstmacx_remove_tag(posted_queue, req);

		/* Queue request to initiate pull of source data. */
		ret = _sstmacx_vc_queue_work_req(req);

		SSTMACX_DEBUG(FI_LOG_EP_DATA,
			   "_sstmacx_vc_queue_work_req returned %s\n",
			   fi_strerror(-ret));
	} else {
		/* Add new unexpected receive request. */
		req = _sstmacx_fr_alloc(ep);
		if (req == NULL) {
			return -FI_ENOMEM;
		}

		req->type = SSTMACX_FAB_RQ_RECV;
		req->addr = vc->peer_addr;
		req->sstmacx_ep = ep;
		req->vc = vc;

		req->msg.send_info[0].send_addr = hdr->addr;
		req->msg.send_info[0].send_len = hdr->len;
		req->msg.send_info[0].mem_hndl = hdr->mdh;
		req->msg.send_iov_cnt = 1;
		req->msg.cum_send_len = req->msg.send_info[0].send_len;
		req->msg.send_flags = hdr->flags;
		req->msg.tag = hdr->msg_tag;
		req->msg.imm = hdr->imm;
		req->msg.rma_mdh = hdr->mdh;
		req->msg.rma_id = hdr->req_addr;
		req->msg.send_info[0].head = hdr->head;
		req->msg.send_info[0].tail = hdr->tail;
		ofi_atomic_initialize32(&req->msg.outstanding_txds, 0);
		req->msg.parent = NULL;

		_sstmacx_insert_tag(unexp_queue, req->msg.tag, req, ~0);

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "New req: %p (%u)\n",
			  req, req->msg.send_info[0].send_len);
	}

	status = SSTMAC_SmsgRelease(vc->sstmac_ep);
	if (OFI_UNLIKELY(status != SSTMAC_RC_SUCCESS)) {
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "SSTMAC_SmsgRelease returned %s\n",
			  sstmac_err_str[status]);
		ret = sstmacxu_to_fi_errno(status);
	}

	return ret;
}

static int __smsg_rndzv_iov_start(void *data, void *msg)
{
	int ret = FI_SUCCESS;
	sstmac_return_t status;
	struct sstmacx_vc *vc = (struct sstmacx_vc *) data;
	struct sstmacx_smsg_rndzv_iov_start_hdr *hdr = msg;
	void *data_ptr = (void *) ((uint8_t *) msg + sizeof(*hdr));
	struct sstmacx_fid_ep *ep;
	struct sstmacx_fab_req *req = NULL;
	struct sstmacx_tag_storage *unexp_queue;
	struct sstmacx_tag_storage *posted_queue;
	char is_req_posted = 0;

	SSTMACX_DBG_TRACE(FI_LOG_EP_DATA, "\n");

#if ENABLE_DEBUG
	int i;

	for (i = 0; i < hdr->iov_cnt; i++) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "send_addr[%d] = %p, send_len[%d] = %lu\n", i,
			   ((struct send_info_t *)data_ptr)[i].send_addr, i,
			   ((struct send_info_t *)data_ptr)[i].send_len);
	}
#endif
	ep = vc->ep;
	assert(ep != NULL);

	__sstmacx_msg_queues(ep, hdr->flags & FI_TAGGED,
			  &posted_queue, &unexp_queue);

	req = _sstmacx_match_tag(posted_queue, hdr->msg_tag, 0, FI_PEEK, NULL,
			      &vc->peer_addr);

	if (req) {		/* Found a request in the posted queue */
		is_req_posted = 1;
		req->tx_failures = 0;
		req->msg.cum_send_len = hdr->send_len;

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "Matched req: %p (%p, %u)\n",
			  req, req->msg.recv_info[0].recv_addr, hdr->send_len);
		_sstmacx_remove_tag(posted_queue, req);
	} else {		/* Unexpected receive, enqueue it */
		req = _sstmacx_fr_alloc(ep);
		if (req == NULL) {
			return -FI_ENOMEM;
		}

		ofi_atomic_initialize32(&req->msg.outstanding_txds, 0);

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "New req: %p (%u)\n",
			  req, hdr->send_len);

		req->msg.cum_send_len = hdr->send_len;
	}

	req->addr = vc->peer_addr;
	req->sstmacx_ep = ep;
	req->vc = vc;
	req->work_fn = __sstmacx_rndzv_iov_req_build;

	req->msg.send_flags = hdr->flags;
	req->msg.imm = hdr->imm;
	req->msg.tag = hdr->msg_tag;
	req->msg.send_iov_cnt = hdr->iov_cnt;
	req->msg.rma_id = hdr->req_addr;
	req->msg.parent = NULL;
	memcpy(req->msg.send_info, data_ptr,
	       sizeof(struct send_info_t) * hdr->iov_cnt);

	if (is_req_posted)
		ret = _sstmacx_vc_queue_work_req(req);
	else
		_sstmacx_insert_tag(unexp_queue, req->msg.tag, req, ~0);

	/*
	 * Release the message buffer on the nic, need to copy the data
	 * section out before this.
	 */
	status = SSTMAC_SmsgRelease(vc->sstmac_ep);

	if (OFI_UNLIKELY(status != SSTMAC_RC_SUCCESS)) {
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "SSTMAC_SmsgRelease returned %s\n",
			  sstmac_err_str[status]);
		ret = sstmacxu_to_fi_errno(status);
	}

	return ret;
}

static int __sstmacx_rndzv_fin_cleanup(void *arg)
{
	int i;
	struct sstmacx_fab_req *req = (struct sstmacx_fab_req *)arg;
	int rc;

	SSTMACX_DBG_TRACE(FI_LOG_EP_DATA, "\n");

	for (i = 0; i < req->msg.send_iov_cnt; i++) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "freeing auto-reg MR: %p\n",
			  req->msg.send_md[i]);

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "req->msg.send_md[%d] ="
			   " %p\n", i, req->msg.send_md[i]);

		rc = fi_close(&req->msg.send_md[i]->mr_fid.fid);
		if (rc != FI_SUCCESS) {
			SSTMACX_FATAL(FI_LOG_DOMAIN,
				"failed to release internal memory registration, "
				"rc=%d\n", rc);
		}

		req->flags &= ~FI_LOCAL_MR;
	}

	_sstmacx_fr_free(req->sstmacx_ep, req);

	return FI_SUCCESS;
}

/* Received SMSG rendezvous fin message.  The peer has finished pulling send
 * data.  Free the send request and generate completions. */
static int __smsg_rndzv_fin(void *data, void *msg)
{
	int ret = FI_SUCCESS;
	sstmac_return_t status;
	struct sstmacx_vc *vc = (struct sstmacx_vc *)data;
	struct sstmacx_smsg_rndzv_fin_hdr *hdr =
			(struct sstmacx_smsg_rndzv_fin_hdr *)msg;
	struct sstmacx_fab_req *req;
	struct sstmacx_fid_ep *ep;

	SSTMACX_DBG_TRACE(FI_LOG_EP_DATA, "\n");

	req = (struct sstmacx_fab_req *)hdr->req_addr;
	assert(req);

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "Received RNDZV_FIN, req: %p\n", req);

	ep = req->sstmacx_ep;
	assert(ep != NULL);

	if (hdr->status == SSTMAC_RC_SUCCESS) {
		__sstmacx_msg_send_completion(ep, req);
	} else {
		ret = __sstmacx_msg_send_err(ep, req);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "__sstmacx_msg_send_err() failed: %s\n",
				  fi_strerror(-ret));
		}
	}

	ofi_atomic_dec32(&req->vc->outstanding_tx_reqs);

	/* Schedule VC TX queue in case the VC is 'fenced'. */
	_sstmacx_vc_tx_schedule(req->vc);

	if (req->msg.send_flags & FI_LOCAL_MR) {
		/* Defer freeing the MR and request. */
		req->work_fn = __sstmacx_rndzv_fin_cleanup;
		ret = _sstmacx_vc_queue_work_req(req);
	} else {
		_sstmacx_fr_free(ep, req);
	}

	status = SSTMAC_SmsgRelease(vc->sstmac_ep);
	if (OFI_UNLIKELY(status != SSTMAC_RC_SUCCESS)) {
		SSTMACX_WARN(FI_LOG_EP_DATA,
				"SSTMAC_SmsgRelease returned %s\n",
				sstmac_err_str[status]);
		ret = sstmacxu_to_fi_errno(status);
	}

	return ret;
}

smsg_callback_fn_t sstmacx_ep_smsg_callbacks[] = {
	[SSTMACX_SMSG_T_EGR_W_DATA] = __smsg_eager_msg_w_data,
	[SSTMACX_SMSG_T_EGR_W_DATA_ACK] = __smsg_eager_msg_w_data_ack,
	[SSTMACX_SMSG_T_EGR_GET] = __smsg_eager_msg_data_at_src,
	[SSTMACX_SMSG_T_EGR_GET_ACK] = __smsg_eager_msg_data_at_src_ack,
	[SSTMACX_SMSG_T_RNDZV_RTS] = __smsg_rndzv_msg_rts,
	[SSTMACX_SMSG_T_RNDZV_RTR] = __smsg_rndzv_msg_rtr,
	[SSTMACX_SMSG_T_RNDZV_COOKIE] = __smsg_rndzv_msg_cookie,
	[SSTMACX_SMSG_T_RNDZV_SDONE] = __smsg_rndzv_msg_send_done,
	[SSTMACX_SMSG_T_RNDZV_RDONE] = __smsg_rndzv_msg_recv_done,
	[SSTMACX_SMSG_T_RNDZV_START] = __smsg_rndzv_start,
	[SSTMACX_SMSG_T_RNDZV_FIN] = __smsg_rndzv_fin,
	[SSTMACX_SMSG_T_RMA_DATA] = __smsg_rma_data, /* defined in sstmacx_rma.c */
	[SSTMACX_SMSG_T_AMO_CNTR] = __smsg_amo_cntr, /* defined in sstmacx_amo.c */
	[SSTMACX_SMSG_T_RNDZV_IOV_START] = __smsg_rndzv_iov_start
};

static int __sstmacx_peek_request(struct sstmacx_fab_req *req)
{
	struct sstmacx_fid_cq *recv_cq = req->sstmacx_ep->recv_cq;
	int rendezvous = !!(req->msg.send_flags & SSTMACX_MSG_RENDEZVOUS);
	int ret, send_idx, recv_idx, copy_len;
	uint64_t send_ptr, recv_ptr, send_len, recv_len;

	/* All claim work is performed by the tag storage, so nothing special
	 * here.  If no CQ, no data is to be returned.  Just inform the user
	 * that a message is present. */
	SSTMACX_DEBUG(FI_LOG_EP_DATA, "peeking req=%p\n", req);
	if (!recv_cq)
		return FI_SUCCESS;

	/* Rendezvous messages on the unexpected queue won't have data.
	 * Additionally, if the CQ format doesn't support passing a buffer
	 * location and length, then data will not be copied. */
	if (!rendezvous && req->msg.recv_info[0].recv_addr &&
	    !INVALID_PEEK_FORMAT(recv_cq->attr.format)) {
		send_len = req->msg.send_info[0].send_len;
		send_ptr = req->msg.send_info[0].send_addr;
		recv_len = req->msg.recv_info[0].recv_len;
		recv_ptr = req->msg.recv_info[0].recv_addr;
		send_idx = recv_idx = 0;

		while (1) {
			copy_len = MIN(send_len, recv_len);
			memcpy((void *)recv_ptr, (void *)send_ptr, copy_len);

			/* Update lengths/addresses */
			send_len -= copy_len;
			recv_len -= copy_len;

			if (send_len == 0) {
				send_idx++;

				if (send_idx == req->msg.send_iov_cnt)
					break;

				send_ptr = req->msg.send_info[send_idx].send_addr;
				send_len = req->msg.send_info[send_idx].send_len;
			} else {
				send_ptr += copy_len;
			}

			if (recv_len == 0) {
				recv_idx++;

				if (recv_idx == req->msg.recv_iov_cnt)
					break;

				recv_ptr = req->msg.recv_info[recv_idx].recv_addr;
				recv_len = req->msg.recv_info[recv_idx].recv_len;
			} else {
				recv_ptr += copy_len;
			}

		}
	} else {
		/* The CQE should not contain a valid buffer. */
		req->msg.recv_info[0].recv_addr = 0;
	}

	ret = __sstmacx_msg_recv_completion(req->sstmacx_ep, req);
	if (ret != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "__sstmacx_msg_recv_completion() failed: %d\n",
			  ret);

	return ret;
}

static int __sstmacx_discard_request(struct sstmacx_fab_req *req)
{
	int ret = FI_SUCCESS;
	int rendezvous = !!(req->msg.send_flags & SSTMACX_MSG_RENDEZVOUS);

	/* The CQE should not contain a valid buffer. */
	req->msg.recv_info[0].recv_addr = 0;
	req->msg.cum_send_len = req->msg.send_info[0].send_len = 0;

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "discarding req=%p\n", req);
	if (rendezvous) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA,
			  "returning rndzv completion for req, %p", req);

		/* Complete rendezvous request, skipping data transfer. */
		req->work_fn = __sstmacx_rndzv_req_send_fin;
		ret = _sstmacx_vc_queue_work_req(req);
	} else {
		/* Data has already been delivered, so just discard it and
		 * generate a CQE. */
		ret = __sstmacx_msg_recv_completion(req->sstmacx_ep, req);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "__sstmacx_msg_recv_completion() failed: %d\n",
				  ret);

		/* Free unexpected eager receive buffer. */
		free((void *)req->msg.send_info[0].send_addr);
		_sstmacx_fr_free(req->sstmacx_ep, req);
	}

	return ret;
}

static int __sstmacx_msg_addr_lookup(struct sstmacx_fid_ep *ep, uint64_t src_addr,
				  struct sstmacx_address *sstmacx_addr)
{
	int ret;
	struct sstmacx_fid_av *av;
	struct sstmacx_av_addr_entry av_entry;

	/* Translate source address. */
	if (SSTMACX_EP_RDM_DGM(ep->type)) {
		if ((ep->caps & FI_DIRECTED_RECV) &&
		    (src_addr != FI_ADDR_UNSPEC)) {
			av = ep->av;
			assert(av != NULL);
			ret = _sstmacx_av_lookup(av, src_addr, &av_entry);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_AV,
					  "_sstmacx_av_lookup returned %d\n",
					  ret);
				return ret;
			}
			*sstmacx_addr = av_entry.sstmacx_addr;
		} else {
			*(uint64_t *)sstmacx_addr = FI_ADDR_UNSPEC;
		}
	}
	/* NOP for MSG EPs. */

	return FI_SUCCESS;
}

/*******************************************************************************
 * Generic EP recv handling
 ******************************************************************************/

ssize_t _sstmacx_recv(struct sstmacx_fid_ep *ep, uint64_t buf, size_t len,
		   void *mdesc, uint64_t src_addr, void *context,
		   uint64_t flags, uint64_t tag, uint64_t ignore,
		   struct sstmacx_fab_req *mrecv_req)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fab_req *req = NULL;
	struct sstmacx_address sstmacx_addr;
	struct sstmacx_tag_storage *posted_queue = NULL;
	struct sstmacx_tag_storage *unexp_queue = NULL;
	uint64_t match_flags;
	struct sstmacx_fid_mem_desc *md = NULL;
	int tagged = !!(flags & FI_TAGGED);

	if (!ep->recv_cq && !ep->recv_cntr) {
		return -FI_ENOCQ;
	}

	if (!tagged) {
		if (!ep->ep_ops.msg_recv_allowed)
			return -FI_EOPNOTSUPP;
	} else {
		if (!ep->ep_ops.tagged_recv_allowed)
			return -FI_EOPNOTSUPP;
	}

	ret = __sstmacx_msg_addr_lookup(ep, src_addr, &sstmacx_addr);
	if (ret != FI_SUCCESS)
		return ret;

	match_flags = flags & (FI_CLAIM | FI_DISCARD | FI_PEEK);

	__sstmacx_msg_queues(ep, tagged, &posted_queue, &unexp_queue);

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "posted_queue = %p\n", posted_queue);

	if (!tagged) {
		tag = 0;
		ignore = ~0;
	}

	COND_ACQUIRE(ep->requires_lock, &ep->vc_lock);

	/* Look for a matching unexpected receive request. */
	req = _sstmacx_match_tag(unexp_queue, tag, ignore,
			      match_flags, context, &sstmacx_addr);
	if (req) {
		/*
		 * if we posted a multi-recv buffer and we can't
		 * hold the matched message, stop dequeuing and
		 * return.
		 */
		if (OFI_UNLIKELY(mrecv_req != NULL)) {

			mrecv_req->msg.mrecv_space_left -=
				req->msg.cum_send_len;
			mrecv_req->msg.mrecv_buf_addr +=
				req->msg.cum_send_len;
			req->msg.parent = mrecv_req;
			_sstmacx_ref_get(mrecv_req);
		}

		/* Found matching request, populate local fields. */

		req->sstmacx_ep = ep;
		req->user_context = context;
		req->msg.recv_info[0].recv_addr = (uint64_t)buf;
		req->msg.recv_info[0].recv_len = len;
		req->msg.cum_recv_len = len;

		if (mdesc) {
			md = container_of(mdesc,
					  struct sstmacx_fid_mem_desc,
					  mr_fid);
			req->msg.recv_info[0].mem_hndl = md->mem_hndl;
		}
		req->msg.recv_md[0] = md;
		req->msg.recv_iov_cnt = 1;
		req->msg.recv_flags = flags;
		req->msg.ignore = ignore;

		if ((flags & SSTMACX_SUPPRESS_COMPLETION) ||
		    (ep->recv_selective_completion &&
		    !(flags & FI_COMPLETION))) {
			req->msg.recv_flags &= ~FI_COMPLETION;
		} else {
			req->msg.recv_flags |= FI_COMPLETION;
		}

		/* Check to see if we are using P/C/D matching flags. */
		if (match_flags & FI_DISCARD) {
			ret = __sstmacx_discard_request(req);
			goto pdc_exit;
		} else if (match_flags & FI_PEEK) {
			ret = __sstmacx_peek_request(req);
			goto pdc_exit;
		}

		if (req->msg.send_flags & SSTMACX_MSG_RENDEZVOUS) {
			/* Matched rendezvous request.  Start data movement. */
			SSTMACX_DEBUG(FI_LOG_EP_DATA, "matched RNDZV, req: %p\n",
				  req);

			/*
			 * this shouldn't happen
			 */
			if (OFI_UNLIKELY(req->vc == NULL)) {
				SSTMACX_ERR(FI_LOG_EP_DATA,
					 "fab req vc field NULL");
			}

			/* Check if second GET for unaligned data is needed. */
			if (req->msg.send_info[0].send_len > req->msg.recv_info[0].recv_len &&
			    ((req->msg.send_info[0].send_addr + req->msg.recv_info[0].recv_len) &
			     SSTMAC_READ_ALIGN_MASK)) {
				req->msg.recv_flags |= SSTMACX_MSG_GET_TAIL;
			}

			/* Initiate pull of source data. */
			req->work_fn = req->msg.send_iov_cnt == 1 ?
				__sstmacx_rndzv_req : __sstmacx_rndzv_iov_req_build;

			_sstmacx_remove_tag(unexp_queue, req);
			ret = _sstmacx_vc_queue_work_req(req);

		} else {
			/* Matched eager request.  Copy data and generate
			 * completions. */
			SSTMACX_DEBUG(FI_LOG_EP_DATA, "Matched recv, req: %p\n",
				  req);

			req->msg.cum_send_len = req->msg.send_info[0].send_len;

			/* Send length is truncated to receive buffer size. */
			req->msg.send_info[0].send_len =
				MIN(req->msg.send_info[0].send_len,
				    req->msg.recv_info[0].recv_len);

			/* Copy data from unexpected eager receive buffer. */
			memcpy((void *)buf, (void *)req->msg.send_info[0].send_addr,
			       req->msg.send_info[0].send_len);
			free((void *)req->msg.send_info[0].send_addr);

			_sstmacx_remove_tag(unexp_queue, req);
			__sstmacx_msg_recv_completion(ep, req);

			_sstmacx_fr_free(ep, req);
		}
	} else {

		/*
		 * if handling a multi receive request,
		 * just return
		 */
		if (mrecv_req)
			goto mrecv_exit;

		/* if peek/claim/discard, we didn't find what we
		 * were looking for, return FI_ENOMSG
		 */
		if (match_flags) {
			__recv_err(ep, context, flags, len,
				   (void *)buf, 0, tag, len, FI_ENOMSG,
				   FI_ENOMSG, NULL, 0);

			/* if handling trecvmsg flags, return here
			 * Never post a receive request from this type of context
			 */
			ret = FI_SUCCESS;
			goto pdc_exit;
		}

		req = _sstmacx_fr_alloc(ep);
		if (req == NULL) {
			ret = -FI_EAGAIN;
			goto err;
		}

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "New recv, req: %p\n", req);

		req->type = SSTMACX_FAB_RQ_RECV;

		req->addr = sstmacx_addr;
		req->sstmacx_ep = ep;
		req->user_context = context;

		req->msg.recv_info[0].recv_addr = (uint64_t)buf;
		req->msg.recv_info[0].recv_len = len;
		req->msg.cum_recv_len = len;

		if (mdesc) {
			md = container_of(mdesc,
					struct sstmacx_fid_mem_desc,
					mr_fid);

			req->msg.recv_info[0].mem_hndl = md->mem_hndl;
		}

		req->msg.recv_md[0] = md;
		req->msg.send_iov_cnt = req->msg.recv_iov_cnt = 1;
		req->msg.recv_flags = flags;
		req->msg.tag = tag;
		req->msg.ignore = ignore;
		req->msg.parent = NULL;
		ofi_atomic_initialize32(&req->msg.outstanding_txds, 0);

		if ((flags & SSTMACX_SUPPRESS_COMPLETION) ||
		    (ep->recv_selective_completion &&
		    !(flags & FI_COMPLETION))) {
			req->msg.recv_flags &= ~FI_COMPLETION;
		} else {
			req->msg.recv_flags |= FI_COMPLETION;
		}
		_sstmacx_insert_tag(posted_queue, tag, req, ignore);
	}

mrecv_exit:
pdc_exit:
err:
	COND_RELEASE(ep->requires_lock, &ep->vc_lock);

	return ret;
}

ssize_t _sstmacx_recv_mr(struct sstmacx_fid_ep *ep, uint64_t buf, size_t len,
		      void *mdesc, uint64_t src_addr, void *context,
		      uint64_t flags, uint64_t tag, uint64_t ignore)
{
	int ret;
	int tagged = !!(flags & FI_TAGGED);
	struct sstmacx_fab_req *mrecv_req = NULL;
	struct sstmacx_address sstmacx_addr;
	struct sstmacx_fid_mem_desc *md = NULL;
	struct fid_mr *auto_mr = NULL;
	struct sstmacx_tag_storage *posted_queue = NULL;
	struct sstmacx_tag_storage *unexp_queue = NULL;
	uint64_t last_space_left;

	assert(flags & FI_MULTI_RECV);

	mrecv_req = _sstmacx_fr_alloc_w_cb(ep, __sstmacx_msg_mrecv_completion);
	if (mrecv_req == NULL) {
		return -FI_ENOMEM;
	}

	mrecv_req->type = SSTMACX_FAB_RQ_MRECV;

	ret = __sstmacx_msg_addr_lookup(ep, src_addr, &sstmacx_addr);
	if (ret != FI_SUCCESS)
		return ret;

	mrecv_req->addr = sstmacx_addr;
	mrecv_req->sstmacx_ep = ep;
	mrecv_req->user_context = context;

	mrecv_req->msg.mrecv_buf_addr = (uint64_t)buf;
	mrecv_req->msg.mrecv_space_left = len;
	mrecv_req->msg.recv_flags = flags;

	if (mdesc) {
		md = container_of(mdesc,
				struct sstmacx_fid_mem_desc,
				mr_fid);

		mrecv_req->msg.recv_info[0].mem_hndl = md->mem_hndl;
		mrecv_req->msg.recv_md[0] = md;
	} else {
		ret = _sstmacx_mr_reg(&ep->domain->domain_fid.fid,
				  (void *)mrecv_req->msg.mrecv_buf_addr,
				  mrecv_req->msg.mrecv_space_left,
				  FI_READ | FI_WRITE, 0, 0, 0,
				  &auto_mr, NULL, ep->auth_key, SSTMACX_PROV_REG);
		if (ret != FI_SUCCESS) {
			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "Failed to auto-register local buffer: %s\n",
				  fi_strerror(-ret));

			return -FI_EAGAIN;
		}
		mrecv_req->msg.recv_flags |= FI_LOCAL_MR;
		mrecv_req->msg.recv_md[0] = container_of(auto_mr,
						   struct sstmacx_fid_mem_desc,
						   mr_fid);
		mrecv_req->msg.recv_info[0].mem_hndl =
					mrecv_req->msg.recv_md[0]->mem_hndl;
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "auto-reg MR: %p\n", auto_mr);
	}

	if (!tagged) {
		mrecv_req->msg.tag = 0;
		mrecv_req->msg.ignore = ~0;
	} else {
		mrecv_req->msg.tag = tag;
		mrecv_req->msg.ignore = ignore;
	}

	if ((flags & SSTMACX_SUPPRESS_COMPLETION) ||
	    (ep->recv_selective_completion &&
	    !(flags & FI_COMPLETION))) {
		mrecv_req->msg.recv_flags &= ~FI_COMPLETION;
	} else {
		mrecv_req->msg.recv_flags |= FI_COMPLETION;
	}

	last_space_left = mrecv_req->msg.mrecv_space_left;

	do {
		ret = _sstmacx_recv(ep,
				 mrecv_req->msg.mrecv_buf_addr,
				 mrecv_req->msg.mrecv_space_left,
				 mdesc,
				 src_addr,
				 context,
				 mrecv_req->msg.recv_flags,
				 mrecv_req->msg.tag,
				 mrecv_req->msg.ignore,
				 mrecv_req);
		if (ret != FI_SUCCESS) {
			_sstmacx_fr_free(ep, mrecv_req);
			return ret;
		}
		if ((last_space_left == mrecv_req->msg.mrecv_space_left) ||
			(mrecv_req->msg.mrecv_space_left < ep->min_multi_recv))
			break;
		last_space_left = mrecv_req->msg.mrecv_space_left;
	} while (1);

	/*
	 * if space left in multi receive request
	 * add to posted receive queue.
	 * Otherwise free request via put ref.
	 */
	if ((int64_t)mrecv_req->msg.mrecv_space_left > ep->min_multi_recv) {
		__sstmacx_msg_queues(ep, tagged, &posted_queue, &unexp_queue);
		_sstmacx_insert_tag(posted_queue, tag, mrecv_req, ignore);
	} else {
		_sstmacx_ref_put(mrecv_req);
	}

	return ret;
}

/*******************************************************************************
 * Generic EP send handling
 ******************************************************************************/

static extern "C" int _sstmacx_send_req(void *arg)
{
	struct sstmacx_fab_req *req = (struct sstmacx_fab_req *)arg;
	struct sstmacx_nic *nic;
	struct sstmacx_fid_ep *ep;
	struct sstmacx_tx_descriptor *tdesc;
	sstmac_return_t status;
	int rc;
	int rendezvous = !!(req->msg.send_flags & SSTMACX_MSG_RENDEZVOUS);
	int hdr_len, data_len;
	void *hdr, *data;
	int tag;
	int inject_err = _sstmacx_req_inject_smsg_err(req);

	ep = req->sstmacx_ep;
	assert(ep != NULL);

	nic = ep->nic;
	assert(nic != NULL);

	rc = _sstmacx_nic_tx_alloc(nic, &tdesc);
	if (rc != FI_SUCCESS) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "_sstmacx_nic_tx_alloc() failed: %d\n",
			  rc);
		return -FI_ENOSPC;
	}
	assert(rc == FI_SUCCESS);

	if (OFI_UNLIKELY(rendezvous)) {
		switch(req->type) {

		case SSTMACX_FAB_RQ_SEND:
		case SSTMACX_FAB_RQ_TSEND:
			assert(req->msg.send_md);
			tag = SSTMACX_SMSG_T_RNDZV_START;
			tdesc->rndzv_start_hdr.flags = req->msg.send_flags;
			tdesc->rndzv_start_hdr.imm = req->msg.imm;
			tdesc->rndzv_start_hdr.msg_tag = req->msg.tag;
			tdesc->rndzv_start_hdr.mdh = req->msg.send_info[0].mem_hndl;
			tdesc->rndzv_start_hdr.addr = req->msg.send_info[0].send_addr;
			tdesc->rndzv_start_hdr.len = req->msg.send_info[0].send_len;
			tdesc->rndzv_start_hdr.req_addr = (uint64_t)req;

			if (req->msg.send_info[0].send_addr & SSTMAC_READ_ALIGN_MASK) {
				tdesc->rndzv_start_hdr.head =
					*(uint32_t *)(req->msg.send_info[0].send_addr &
						      ~SSTMAC_READ_ALIGN_MASK);
				SSTMACX_DEBUG(FI_LOG_EP_DATA,
					  "Sending %d unaligned head bytes (%x)\n",
					  SSTMAC_READ_ALIGN -
					  (req->msg.send_info[0].send_addr &
					   SSTMAC_READ_ALIGN_MASK),
					  tdesc->rndzv_start_hdr.head);
			}

			if ((req->msg.send_info[0].send_addr +
			     req->msg.send_info[0].send_len) &
			    SSTMAC_READ_ALIGN_MASK) {
				tdesc->rndzv_start_hdr.tail =
					*(uint32_t *)((req->msg.send_info[0].send_addr +
						       req->msg.send_info[0].send_len) &
						      ~SSTMAC_READ_ALIGN_MASK);
				SSTMACX_DEBUG(FI_LOG_EP_DATA,
					  "Sending %d unaligned tail bytes (%x)\n",
					  (req->msg.send_info[0].send_addr +
					   req->msg.send_info[0].send_len) &
					  SSTMAC_READ_ALIGN_MASK,
					  tdesc->rndzv_start_hdr.tail);
			}

			hdr = &tdesc->rndzv_start_hdr;
			hdr_len = sizeof(tdesc->rndzv_start_hdr);
			/* TODO: Unify send&sendv/recv&recvv, so data will be
			 * req->msg.send_info */
			data = NULL;
			data_len = 0;

			break;

		case SSTMACX_FAB_RQ_SENDV:
		case SSTMACX_FAB_RQ_TSENDV:
			assert(req->msg.send_md[0]);
			tag = SSTMACX_SMSG_T_RNDZV_IOV_START;
			tdesc->rndzv_iov_start_hdr.flags = req->msg.send_flags;
			tdesc->rndzv_iov_start_hdr.imm = req->msg.imm;
			tdesc->rndzv_iov_start_hdr.msg_tag = req->msg.tag;
			tdesc->rndzv_iov_start_hdr.iov_cnt =
				req->msg.send_iov_cnt;
			tdesc->rndzv_iov_start_hdr.req_addr = (uint64_t) req;
			tdesc->rndzv_iov_start_hdr.send_len = req->msg.cum_send_len;

			/* Send data at unaligned bytes in the iov addresses
			 * within the data section of the control message so
			 * that the remote peer can pull from four byte aligned
			 * addresses and still transfer all the data. */
			__sstmacx_msg_send_alignment(req);

			data_len = sizeof(struct send_info_t) * req->msg.send_iov_cnt;
			data = (void *) req->msg.send_info;
			hdr_len = sizeof(tdesc->rndzv_iov_start_hdr);
			hdr = &tdesc->rndzv_iov_start_hdr;

#if ENABLE_DEBUG
			int i;
			for (i = 0; i < req->msg.send_iov_cnt; i++) {
				SSTMACX_DEBUG(FI_LOG_EP_DATA,
					   "data[%d].send_addr = 0x%ux, "
					   "data[%d].send_len = %lu, "
					   "data[%d].mem_hndl = %hxx\n", i,
					   ((struct send_info_t *)data)[i].send_addr,
					   i,
					   ((struct send_info_t *)data)[i].send_len,
					   i,
					   ((struct send_info_t *)data)[i].mem_hndl);

			}
#endif
			break;
		default:
			SSTMACX_FATAL(FI_LOG_EP_DATA, "Invalid request type: %d\n", req->type);
			return -FI_EINVAL;
		}
	} else {
		tag = SSTMACX_SMSG_T_EGR_W_DATA;

		tdesc->eager_hdr.flags = req->msg.send_flags;
		tdesc->eager_hdr.imm = req->msg.imm;
		tdesc->eager_hdr.msg_tag = req->msg.tag;
		tdesc->eager_hdr.len = req->msg.cum_send_len;

		hdr = &tdesc->eager_hdr;
		hdr_len = sizeof(tdesc->eager_hdr);
		data = (void *)req->msg.send_info[0].send_addr;
		/* If this is not rndzv the send length should always be the
		 * cumulative length of all the send_info lengths */
		data_len = req->msg.cum_send_len;
	}
	tdesc->req = req;
	tdesc->completer_fn = sstmacx_ep_smsg_completers[tag];

	COND_ACQUIRE(nic->requires_lock, &nic->lock);

	if (OFI_UNLIKELY(inject_err)) {
		_sstmacx_nic_txd_err_inject(nic, tdesc);
		status = SSTMAC_RC_SUCCESS;
	} else {
		status = SSTMAC_SmsgSendWTag(req->vc->sstmac_ep,
					  hdr, hdr_len, data, data_len,
					  tdesc->id, tag);
	}

	/*
	 * if this is a rendezvous message, we want to generate
	 * IRQ at remote peer.
	 * TODO: Do we need to do this for sendv?
	 */
	if ((status == SSTMAC_RC_SUCCESS) &&
		(tag == SSTMACX_SMSG_T_RNDZV_START ||
		 tag == SSTMACX_SMSG_T_RNDZV_IOV_START))
		_sstmacx_rma_post_irq(req->vc);

	COND_RELEASE(nic->requires_lock, &nic->lock);

	if (status == SSTMAC_RC_NOT_DONE) {
		_sstmacx_nic_tx_free(nic, tdesc);
		SSTMACX_DEBUG(FI_LOG_EP_DATA,
			  "SSTMAC_SmsgSendWTag returned %s\n",
			  sstmac_err_str[status]);
	} else if (status != SSTMAC_RC_SUCCESS) {
		_sstmacx_nic_tx_free(nic, tdesc);
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "SSTMAC_SmsgSendWTag returned %s\n",
			  sstmac_err_str[status]);
	}

	return sstmacxu_to_fi_errno(status);
}

ssize_t _sstmacx_send(struct sstmacx_fid_ep *ep, uint64_t loc_addr, size_t len,
		   void *mdesc, uint64_t dest_addr, void *context,
		   uint64_t flags, uint64_t data, uint64_t tag)
{
	int ret = FI_SUCCESS;
	struct sstmacx_vc *vc = NULL;
	struct sstmacx_fab_req *req;
	struct sstmacx_fid_mem_desc *md = NULL;
	int rendezvous;
	struct fid_mr *auto_mr = NULL;
	int connected;

	if (!ep->send_cq && !ep->send_cntr) {
		return -FI_ENOCQ;
	}

	if (flags & FI_TRIGGER) {
		struct fi_triggered_context *trigger_context =
				(struct fi_triggered_context *)context;
		if ((trigger_context->event_type != FI_TRIGGER_THRESHOLD) ||
		    (flags & FI_INJECT)) {
			return -FI_EINVAL;
		}
	}

	if ((flags & FI_INJECT) && (len > SSTMACX_INJECT_SIZE)) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA,
			  "Send length %d exceeds inject max size: %d\n",
			  len, SSTMACX_INJECT_SIZE);
		return -FI_EINVAL;
	}

	if (!(flags & FI_TAGGED)) {
		if (!ep->ep_ops.msg_send_allowed)
			return -FI_EOPNOTSUPP;
	} else {
		if (!ep->ep_ops.tagged_send_allowed)
			return -FI_EOPNOTSUPP;
	}

	rendezvous = len >= ep->domain->params.msg_rendezvous_thresh;

	/* need a memory descriptor for large sends */
	if (rendezvous && !mdesc) {
		ret = _sstmacx_mr_reg(&ep->domain->domain_fid.fid, (void *)loc_addr,
				 len, FI_READ | FI_WRITE, 0,
				 0, 0,
				 &auto_mr, NULL, ep->auth_key,
				 SSTMACX_PROV_REG);
		if (ret != FI_SUCCESS) {
			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "Failed to auto-register local buffer: %s\n",
				   fi_strerror(-ret));
			return ret;
		}
		flags |= FI_LOCAL_MR;
		mdesc = (void *)auto_mr;
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "auto-reg MR: %p\n", auto_mr);
	}

	req = _sstmacx_fr_alloc(ep);
	if (req == NULL) {
		return -FI_ENOSPC;
	}

	req->type = SSTMACX_FAB_RQ_SEND;
	req->sstmacx_ep = ep;
	req->user_context = context;
	req->work_fn = _sstmacx_send_req;

	if (flags & FI_TAGGED) {
		req->msg.tag = tag;
	} else {
		/* Make sure zeroed tag ends up in the send CQE. */
		req->msg.tag = 0;
	}

	if (mdesc) {
		md = container_of(mdesc, struct sstmacx_fid_mem_desc, mr_fid);
		req->msg.send_info[0].mem_hndl = md->mem_hndl;
	}
	req->msg.send_md[0] = md;
	req->msg.send_iov_cnt = 1;
	req->msg.send_flags = flags;
	req->msg.send_info[0].send_len = len;
	req->msg.cum_send_len = len;
	req->msg.imm = data;
	req->flags = flags;

	if (flags & FI_INJECT) {
		memcpy(req->inject_buf, (void *)loc_addr, len);
		req->msg.send_info[0].send_addr = (uint64_t)req->inject_buf;
	} else {
		req->msg.send_info[0].send_addr = loc_addr;
	}

	if ((flags & SSTMACX_SUPPRESS_COMPLETION) ||
	    (ep->send_selective_completion &&
	    !(flags & FI_COMPLETION))) {
		req->msg.send_flags &= ~FI_COMPLETION;
	} else {
		req->msg.send_flags |= FI_COMPLETION;
	}

	if (rendezvous) {
		/*
		 * this initialization is not necessary currently
		 * but is a place holder in the event a RDMA write
		 * path is implemented for rendezvous
		 */
		ofi_atomic_initialize32(&req->msg.outstanding_txds, 0);
		req->msg.send_flags |= SSTMACX_MSG_RENDEZVOUS;
	}

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "Queuing (%p %d)\n",
		  (void *)loc_addr, len);

	COND_ACQUIRE(ep->requires_lock, &ep->vc_lock);

	ret = _sstmacx_vc_ep_get_vc(ep, dest_addr, &vc);
	if (ret) {
		goto err_get_vc;
	}

	req->vc = vc;

	ret = _sstmacx_vc_queue_tx_req(req);
	connected = (vc->conn_state == SSTMACX_VC_CONNECTED);

	COND_RELEASE(ep->requires_lock, &ep->vc_lock);

	/*
	 * If a new VC was allocated, progress CM before returning.
	 * If the VC is connected and there's a backlog, poke
	 * the nic progress engine befure returning.
	 */
	if (!connected) {
		_sstmacx_cm_nic_progress(ep->cm_nic);
	} else if (!dlist_empty(&vc->tx_queue)) {
		_sstmacx_nic_progress(vc->ep->nic);
	}

	return ret;

err_get_vc:
	COND_RELEASE(ep->requires_lock, &ep->vc_lock);
	_sstmacx_fr_free(ep, req);
	if (flags & FI_LOCAL_MR)
		fi_close(&auto_mr->fid);
	return ret;
}

ssize_t _sstmacx_recvv(struct sstmacx_fid_ep *ep, const struct iovec *iov,
		    void **desc, size_t count, uint64_t src_addr, void *context,
		    uint64_t flags, uint64_t ignore, uint64_t tag)
{
	int i, ret = FI_SUCCESS;
	size_t cum_len = 0;
	struct sstmacx_fab_req *req = NULL;
	struct sstmacx_address sstmacx_addr;
	struct sstmacx_tag_storage *posted_queue = NULL;
	struct sstmacx_tag_storage *unexp_queue = NULL;
	uint64_t match_flags;
	int tagged = flags & FI_TAGGED;

	if (!ep->recv_cq && !ep->recv_cntr) {
		return -FI_ENOCQ;
	}

	if (!tagged) {
		if (!ep->ep_ops.msg_send_allowed)
			return -FI_EOPNOTSUPP;

		tag = 0;
		ignore = ~0;
	} else {
		if (!ep->ep_ops.tagged_send_allowed)
			return -FI_EOPNOTSUPP;
	}

	match_flags = flags & (FI_CLAIM | FI_DISCARD | FI_PEEK);

	/*
	 * Lookup the sstmac addr in the av_table or av_hashtable.
	 * If the sstmac addr doesn't exist the addr is FI_ADDR_UNSPEC,
	 * meaning this remote node wants to receive from all senders?
	 */
	ret = __sstmacx_msg_addr_lookup(ep, src_addr, &sstmacx_addr);
	if (ret != FI_SUCCESS)
		return ret;

	/* calculate cumulative size of the iovec buf lens */
	for (i = 0; i < count; i++) {
		cum_len += iov[i].iov_len;
	}

	/*
	 * Initialize the tag storage objects.
	 * The posted_queue holds information about receives that have
	 * been posted on the remote endpoint.
	 *
	 * The unexp_queue holds information about data that has arrived
	 * prior to posting a receive on the remote endpoint.
	 *
	 * Both {unexp,posted}_queue objects have two sets, one for tagged
	 * messages and the other for untagged messages.
	 *
	 * The untagged queues match based off the source address.
	 *
	 * The tagged queues match based off the tag and source address (when
	 * the ep is created with FI_DIRECTED_RECV).
	 *
	 * A "message" is added to the unexpected queue when it arrives at a
	 * remote endpoint and the completer_fn doesn't find an existing request
	 * in the posted queue (i.e. no fi_recvs have been called (or posted)
	 * on the remote endpoint).
	 */
	__sstmacx_msg_queues(ep, tagged, &posted_queue, &unexp_queue);

	COND_ACQUIRE(ep->requires_lock, &ep->vc_lock);

	/*
	 * Posting a recv, look for an existing request in the
	 * unexpected queue.
	 */
	req = _sstmacx_match_tag(unexp_queue, tag, ignore,
			      match_flags, context, &sstmacx_addr);

	if (req) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "UNEXPECTED, req = %p\n", req);
		/* Found a matching request in the unexpected queue. */

		/*
		 * reset ep, it might be different than the ep the message came
		 * in on.
		 */
		req->sstmacx_ep = ep;
		req->user_context = context;
		req->flags = 0;
		req->msg.recv_flags = flags;
		req->msg.recv_iov_cnt = count;
		req->msg.cum_recv_len = cum_len;
		/* req->msg.cum_send_len = MIN(req->msg.cum_send_len, cum_len); */

		if (tagged) {
			req->type = SSTMACX_FAB_RQ_TRECVV;
		} else {
			req->type = SSTMACX_FAB_RQ_RECVV;
		}

		if ((flags & SSTMACX_SUPPRESS_COMPLETION) ||
		    (ep->recv_selective_completion &&
		     !(flags & FI_COMPLETION))) {
			req->msg.recv_flags &= ~FI_COMPLETION;
		} else {
			req->msg.recv_flags |= FI_COMPLETION;
		}

		/* Check to see if we are using P/C/D matching flags. */
		if (match_flags & FI_DISCARD) {
			ret = __sstmacx_discard_request(req);
			goto pdc_exit;
		} else if (match_flags & FI_PEEK) {
			ret = __sstmacx_peek_request(req);
			goto pdc_exit;
		}

		for (i = 0; i < count; i++) {
			req->msg.recv_info[i].recv_addr = (uint64_t) iov[i].iov_base;
			req->msg.recv_info[i].recv_len = iov[i].iov_len;
		}

		if (req->msg.send_flags & SSTMACX_MSG_RENDEZVOUS) {
			req->work_fn = __sstmacx_rndzv_iov_req_build;
			if (!(req->vc->modes & SSTMACX_VC_MODE_XPMEM)) {
				if (!desc) {
					ret = __sstmacx_msg_register_iov(ep,
								      iov,
								      count,
								      req->msg.recv_md);
					if (ret != FI_SUCCESS) {
						SSTMACX_DEBUG(FI_LOG_EP_DATA,
							   "Failed to "
							   "auto-register"
							   " local buffer: %s\n"
							   , fi_strerror(-ret));
						goto err;
					}
					req->msg.send_flags |= FI_LOCAL_MR;

				} else {	/* User registered their memory */

					for (i = 0; i < count; i++) {
						if (!desc[i]) {
							SSTMACX_WARN(FI_LOG_EP_DATA,
								  "invalid memory reg"
								  "istration (%p).\n",
								  desc[i]);
							ret = -FI_EINVAL;
							goto err;
						}

						req->msg.recv_md[i] =
							container_of(desc[i],
							struct sstmacx_fid_mem_desc,
							mr_fid);
					}
				}

				for (i = 0; i < count; i++)
					req->msg.recv_info[i].mem_hndl =
						req->msg.recv_md[i]->mem_hndl;
			}

			ret = _sstmacx_vc_queue_work_req(req);
		} else {

			/*
			 * This request is associate with a regular eager smsg,
			 * the rndzv threshold on the sender was not reached or
			 * exceeded.
			 */
			__sstmacx_msg_unpack_data_into_iov(req->msg.recv_info,
							count,
							req->msg.send_info[0].send_addr,
							req->msg.send_info[0].send_len);

			__sstmacx_msg_recv_completion(ep, req);
			_sstmacx_fr_free(ep, req);
		}
	} else {
		/* if peek/claim/discard, we didn't find what we
		 * were looking for, return FI_ENOMSG
		 */
		if (match_flags) {
			__recv_err(ep, context, flags, cum_len,
				   (void *) iov, 0, tag, cum_len, FI_ENOMSG,
				   FI_ENOMSG, NULL, 0);

			/* if handling trecvmsg flags, return here
			 * Never post a receive request from this type of
			 * context
			 */
			ret = FI_SUCCESS;
			goto pdc_exit;
		}

		/*
		 * No matching requests found, create a new one and enqueue
		 * it in the posted queue.
		 */
		req = _sstmacx_fr_alloc(ep);
		if (req == NULL) {
			ret = -FI_EAGAIN;
			goto err;
		}

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "EXPECTED, req = %p\n", req);

		if (tagged) {
			req->type = SSTMACX_FAB_RQ_TRECVV;
		} else {
			req->type = SSTMACX_FAB_RQ_RECVV;
		}

		if ((flags & SSTMACX_SUPPRESS_COMPLETION) ||
		    (ep->recv_selective_completion &&
		     !(flags & FI_COMPLETION))) {
			req->msg.recv_flags &= ~FI_COMPLETION;
		} else {
			req->msg.recv_flags |= FI_COMPLETION;
		}

		req->addr = sstmacx_addr;
		req->sstmacx_ep = ep;
		req->user_context = context;
		req->flags = 0;

		for (i = 0; i < count; i++) {
			req->msg.recv_info[i].recv_addr = (uint64_t) iov[i].iov_base;
			req->msg.recv_info[i].recv_len = iov[i].iov_len;
			req->msg.recv_md[i] = NULL;
		}

		req->msg.recv_iov_cnt = count;
		req->msg.recv_flags = flags;
		req->msg.cum_recv_len = cum_len;
		req->msg.tag = tag;
		req->msg.ignore = ignore;
		req->msg.parent = NULL;
		ofi_atomic_initialize32(&req->msg.outstanding_txds, 0);


		if ((flags & SSTMACX_SUPPRESS_COMPLETION) ||
		    (ep->recv_selective_completion &&
		     !(flags & FI_COMPLETION))) {
			req->msg.recv_flags &= ~FI_COMPLETION;
		} else {
			req->msg.recv_flags |= FI_COMPLETION;
		}

		_sstmacx_insert_tag(posted_queue, tag, req, ignore);
	}

pdc_exit:
err:
	COND_RELEASE(ep->requires_lock, &ep->vc_lock);

	return ret;
}

ssize_t _sstmacx_sendv(struct sstmacx_fid_ep *ep, const struct iovec *iov,
		    void **mdesc, size_t count, uint64_t dest_addr,
		    void *context, uint64_t flags, uint64_t tag)
{
	int i, ret = FI_SUCCESS;
	unsigned long long cum_len = 0;
	void *tmp = NULL;
	struct sstmacx_vc *vc = NULL;
	struct sstmacx_fab_req *req = NULL;
	struct fid_mr *auto_mr;
	int connected;

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "iov_count = %lu\n", count);

	if (!ep->send_cq && !ep->send_cntr) {
		return -FI_ENOCQ;
	}

	if (!(flags & FI_TAGGED)) {
		if (!ep->ep_ops.msg_send_allowed)
			return -FI_EOPNOTSUPP;
	} else {
		if (!ep->ep_ops.tagged_send_allowed)
			return -FI_EOPNOTSUPP;
	}

	req = _sstmacx_fr_alloc(ep);
	if (req == NULL) {
		return -FI_ENOSPC;
	}

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "Created req - %p\n", req);

	/* calculate cumulative size of the iovec buf lens */
	for (i = 0; i < count; i++) {
		/* TODO: handle possible overflow */
		cum_len += iov[i].iov_len;

		SSTMACX_DEBUG(FI_LOG_EP_DATA, "iov[%d].iov_len = %lu\n", i, iov[i].iov_len);
	}

	/* Fill out fabric request */
	if (flags & FI_TAGGED) {
		req->type = SSTMACX_FAB_RQ_TSENDV;
		req->msg.tag = tag;
		req->msg.ignore = 0;
	} else {
		req->type = SSTMACX_FAB_RQ_SENDV;
		req->msg.tag = 0;
		req->msg.ignore = ~0;
	}

	req->sstmacx_ep = ep;
	req->user_context = context;
	req->work_fn = _sstmacx_send_req;
	req->flags = flags;
	req->msg.send_flags = flags;
	req->msg.imm = 0;
	req->msg.parent = NULL;

	/*
	 * If the cum_len is >= ep->domain->params.msg_rendezvous_thresh
	 * transfer the iovec entries individually.
	 *
	 * For this case, use CtPostFma for iovec lengths that are smaller than
	 * the rendezvous thresh. For CtPostFma:
	 * the sum of the iov lens must be either <= 1GB or <= 1MB if the comm
	 * dom is configured with FmaSharing.
	 * otherwise use PostRdma.
	 */
	if (cum_len >= ep->domain->params.msg_rendezvous_thresh) {
		if (!mdesc) {	/* Register the memory for the user */
			for (i = 0; i < count; i++) {
				auto_mr = NULL;

				ret = _sstmacx_mr_reg(&ep->domain->domain_fid.fid,
						   iov[i].iov_base,
						   iov[i].iov_len,
						   FI_READ | FI_WRITE, 0, 0, 0,
						   &auto_mr, NULL, ep->auth_key, SSTMACX_PROV_REG);

				if (ret != FI_SUCCESS) {
					SSTMACX_DEBUG(FI_LOG_EP_DATA,
						   "Failed to auto-register"
						   " local buffer: %s\n",
						   fi_strerror(-ret));

					for (i--; i >= 0; i--) {
						ret = fi_close(&req->msg.send_md[i]->mr_fid.fid);
						if (ret != FI_SUCCESS) {
							SSTMACX_FATAL(FI_LOG_DOMAIN,
								"failed to release auto-registered region, "
								"rc=%d\n", ret);
						}
					}

					goto err_mr_reg;
				}

				req->msg.send_md[i] = container_of(
					(void *) auto_mr,
					struct sstmacx_fid_mem_desc,
					mr_fid);

				req->msg.send_info[i].send_addr = (uint64_t) iov[i].iov_base;
				req->msg.send_info[i].send_len = iov[i].iov_len;
				req->msg.send_info[i].mem_hndl =
					req->msg.send_md[i]->mem_hndl;

				SSTMACX_DEBUG(FI_LOG_EP_DATA, "iov[%d].iov_len = %lu,"
					   " req->msg.send_info[%d].send_addr = "
					   "%p, req->msg.send_info[%d].send_len "
					   "= %lu\n", i, iov[i].iov_len, i,
					   (void *) req->msg.send_info[i].send_addr,
					   i, req->msg.send_info[i].send_len);

				SSTMACX_DEBUG(FI_LOG_EP_DATA, "req->msg.send_md[%d] "
					   "= %p\n", i,
					   req->msg.send_md[i]);

				SSTMACX_DEBUG(FI_LOG_EP_DATA, "auto-reg MR: %p\n",
					   req->msg.send_md[i]);

			}

			req->msg.send_flags |= FI_LOCAL_MR;
		} else {	/* User registered their memory */
			for (i = 0; i < count; i++) {
				if (!mdesc[i]) {
					SSTMACX_WARN(FI_LOG_EP_DATA,
						  "invalid memory reg"
						  "istration (%p).\n",
						  mdesc[i]);
					ret = -FI_EINVAL;
					goto err_mr_reg;
				}

				req->msg.send_md[i] =
					container_of(mdesc[i],
						     struct sstmacx_fid_mem_desc,
						     mr_fid);

				req->msg.send_info[i].send_addr = (uint64_t) iov[i].iov_base;
				req->msg.send_info[i].send_len = iov[i].iov_len;
				req->msg.send_info[i].mem_hndl =
					req->msg.send_md[i]->mem_hndl;
			}
		}

		req->msg.send_iov_cnt = count;
		req->msg.send_flags |= SSTMACX_MSG_RENDEZVOUS;
	} else {
		/*
		 * TODO: Use buddy allocator with max alloc lim of
		 * ep->domain->params.msg_rendezvous_thresh
		 */
		/* This is freed in __comp_eager_msg_w_data */
		tmp = malloc(cum_len);
		assert(tmp != NULL);

		__sstmacx_msg_pack_data_from_iov((uint64_t) tmp, cum_len,
					      iov, count);
		req->msg.send_info[0].send_addr = (uint64_t) tmp;
		req->msg.send_info[0].send_len = cum_len;
	}

	if ((flags & SSTMACX_SUPPRESS_COMPLETION) ||
	    (ep->send_selective_completion &&
	     !(flags & FI_COMPLETION))) {
		req->msg.send_flags &= ~FI_COMPLETION;
	} else {
		req->msg.send_flags |= FI_COMPLETION;
	}

	req->msg.cum_send_len = (size_t) cum_len;

	COND_ACQUIRE(ep->requires_lock, &ep->vc_lock);

	ret = _sstmacx_vc_ep_get_vc(ep, dest_addr, &vc);
	if (ret != FI_SUCCESS) {
		goto err_get_vc;
	}

	req->vc = vc;

	ret = _sstmacx_vc_queue_tx_req(req);
	connected = (vc->conn_state == SSTMACX_VC_CONNECTED);

	COND_RELEASE(ep->requires_lock, &ep->vc_lock);

	/*
	 * If a new VC was allocated, progress CM before returning.
	 * If the VC is connected and there's a backlog, poke
	 * the nic progress engine befure returning.
	 */
	if (!connected) {
		_sstmacx_cm_nic_progress(ep->cm_nic);
	} else if (!dlist_empty(&vc->tx_queue)) {
		_sstmacx_nic_progress(vc->ep->nic);
	}

	return ret;

err_get_vc:
	COND_RELEASE(ep->requires_lock, &ep->vc_lock);
	if (req->msg.send_flags & FI_LOCAL_MR) {
		for (i = 0; i < count; i++) {
			fi_close(&req->msg.send_md[i]->mr_fid.fid);
		}
	}
err_mr_reg:
	_sstmacx_fr_free(ep, req);

	return ret;
}

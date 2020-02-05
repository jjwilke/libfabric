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
 * Copyright (c) 2015-2017 Cray Inc. All rights reserved.
 * Copyright (c) 2015-2017 Los Alamos National Security, LLC.
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
#include "sstmacx_nic.h"
#include "sstmacx_vc.h"
#include "sstmacx_ep.h"
#include "sstmacx_mr.h"
#include "sstmacx_cntr.h"

static int __sstmacx_amo_send_err(struct sstmacx_fid_ep *ep,
			       struct sstmacx_fab_req *req,
			       int error)
{
	struct sstmacx_fid_cntr *cntr = NULL;
	int rc = FI_SUCCESS;
	uint64_t flags = req->flags & SSTMACX_AMO_COMPLETION_FLAGS;

	if (ep->send_cq) {
		rc = _sstmacx_cq_add_error(ep->send_cq, req->user_context,
					flags, 0, 0, 0, 0, 0, error,
					sstmacxu_to_fi_errno(SSTMAC_RC_TRANSACTION_ERROR),
					NULL, 0);
		if (rc) {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_cq_add_error() failed: %d\n", rc);
		}
	}

	if (((req->type == SSTMACX_FAB_RQ_AMO) ||
	     (req->type == SSTMACX_FAB_RQ_NAMO_AX) ||
	     (req->type == SSTMACX_FAB_RQ_NAMO_AX_S)) &&
	    ep->write_cntr) {
		cntr = ep->write_cntr;
	} else if ((req->type == SSTMACX_FAB_RQ_FAMO ||
		    req->type == SSTMACX_FAB_RQ_CAMO ||
		    req->type == SSTMACX_FAB_RQ_NAMO_FAX ||
		    req->type == SSTMACX_FAB_RQ_NAMO_FAX_S) &&
		   ep->read_cntr) {
		cntr = ep->read_cntr;
	}

	if (cntr) {
		rc = _sstmacx_cntr_inc_err(cntr);
		if (rc)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_cntr_inc_err() failed: %d\n", rc);
	}

	return rc;
}

static int __sstmacx_amo_send_completion(struct sstmacx_fid_ep *ep,
				      struct sstmacx_fab_req *req)
{
	struct sstmacx_fid_cntr *cntr = NULL;
	int rc = FI_SUCCESS;
	uint64_t flags = req->flags & SSTMACX_AMO_COMPLETION_FLAGS;

	if ((req->flags & FI_COMPLETION) && ep->send_cq) {
		rc = _sstmacx_cq_add_event(ep->send_cq, ep, req->user_context,
					flags, 0, 0, 0, 0, FI_ADDR_NOTAVAIL);
		if (rc) {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_cq_add_event() failed: %d\n", rc);
		}
	}

	if ((req->type == SSTMACX_FAB_RQ_AMO ||
	     req->type == SSTMACX_FAB_RQ_NAMO_AX ||
	     req->type == SSTMACX_FAB_RQ_NAMO_AX_S) &&
	    ep->write_cntr) {
		cntr = ep->write_cntr;
	} else if ((req->type == SSTMACX_FAB_RQ_FAMO ||
		    req->type == SSTMACX_FAB_RQ_CAMO ||
		    req->type == SSTMACX_FAB_RQ_NAMO_FAX ||
		    req->type == SSTMACX_FAB_RQ_NAMO_FAX_S) &&
		   ep->read_cntr) {
		cntr = ep->read_cntr;
	}

	if (cntr) {
		rc = _sstmacx_cntr_inc(cntr);
		if (rc)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_cntr_inc() failed: %d\n", rc);
	}

	return FI_SUCCESS;
}

static void __sstmacx_amo_fr_complete(struct sstmacx_fab_req *req)
{
	int rc;

	if (req->flags & FI_LOCAL_MR) {
		SSTMACX_INFO(FI_LOG_EP_DATA, "freeing auto-reg MR: %p\n",
			  req->amo.loc_md);
		rc = fi_close(&req->amo.loc_md->mr_fid.fid);
		if (rc != FI_SUCCESS) {
			SSTMACX_ERR(FI_LOG_DOMAIN,
				"failed to deregister auto-registered region, "
				"rc=%d\n", rc);
		}

		req->flags &= ~FI_LOCAL_MR;
	}

	ofi_atomic_dec32(&req->vc->outstanding_tx_reqs);

	/* Schedule VC TX queue in case the VC is 'fenced'. */
	_sstmacx_vc_tx_schedule(req->vc);

	_sstmacx_fr_free(req->vc->ep, req);
}

static int __sstmacx_amo_post_err(struct sstmacx_fab_req *req, int error)
{
	int rc;

	rc = __sstmacx_amo_send_err(req->vc->ep, req, error);
	if (rc != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "__sstmacx_amo_send_err() failed: %d\n",
			  rc);

	__sstmacx_amo_fr_complete(req);
	return FI_SUCCESS;
}

/* SMSG callback for AMO remote counter control message. */
int __smsg_amo_cntr(void *data, void *msg)
{
	int ret = FI_SUCCESS;
	struct sstmacx_vc *vc = (struct sstmacx_vc *)data;
	struct sstmacx_smsg_amo_cntr_hdr *hdr =
			(struct sstmacx_smsg_amo_cntr_hdr *)msg;
	struct sstmacx_fid_ep *ep = vc->ep;
	sstmac_return_t status;

	if (hdr->flags & FI_REMOTE_WRITE && ep->rwrite_cntr) {
		ret = _sstmacx_cntr_inc(ep->rwrite_cntr);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_cntr_inc() failed: %d\n",
				  ret);
	}

	if (hdr->flags & FI_REMOTE_READ && ep->rread_cntr) {
		ret = _sstmacx_cntr_inc(ep->rread_cntr);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_cntr_inc() failed: %d\n",
				  ret);
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

static int __sstmacx_amo_txd_cntr_complete(void *arg, sstmac_return_t tx_status)
{
	struct sstmacx_tx_descriptor *txd = (struct sstmacx_tx_descriptor *)arg;
	struct sstmacx_fab_req *req = txd->req;
	int rc;

	_sstmacx_nic_tx_free(req->sstmacx_ep->nic, txd);

	if (tx_status != SSTMAC_RC_SUCCESS)
		return __sstmacx_amo_post_err(req, FI_ECANCELED);

	/* Successful data delivery.  Generate local completion. */
	rc = __sstmacx_amo_send_completion(req->vc->ep, req);
	if (rc != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "__sstmacx_amo_send_completion() failed: %d\n",
			  rc);

	__sstmacx_amo_fr_complete(req);

	return FI_SUCCESS;
}

static int __sstmacx_amo_send_cntr_req(void *arg)
{
	struct sstmacx_fab_req *req = (struct sstmacx_fab_req *)arg;
	struct sstmacx_fid_ep *ep = req->sstmacx_ep;
	struct sstmacx_nic *nic = ep->nic;
	struct sstmacx_tx_descriptor *txd;
	sstmac_return_t status;
	int rc;
	int inject_err = _sstmacx_req_inject_err(req);

	rc = _sstmacx_nic_tx_alloc(nic, &txd);
	if (rc) {
		SSTMACX_INFO(FI_LOG_EP_DATA,
				"_sstmacx_nic_tx_alloc() failed: %d\n",
				rc);
		return -FI_ENOSPC;
	}

	txd->req = req;
	txd->completer_fn = __sstmacx_amo_txd_cntr_complete;

	if (req->type == SSTMACX_FAB_RQ_AMO) {
		txd->amo_cntr_hdr.flags = FI_REMOTE_WRITE;
	} else {
		txd->amo_cntr_hdr.flags = FI_REMOTE_READ;
	}

	COND_ACQUIRE(nic->requires_lock, &nic->lock);
	if (inject_err) {
		_sstmacx_nic_txd_err_inject(nic, txd);
		status = SSTMAC_RC_SUCCESS;
	} else {
		status = SSTMAC_SmsgSendWTag(req->vc->sstmac_ep,
					  &txd->amo_cntr_hdr,
					  sizeof(txd->amo_cntr_hdr),
					  NULL, 0, txd->id,
					  SSTMACX_SMSG_T_AMO_CNTR);
	}
	COND_RELEASE(nic->requires_lock, &nic->lock);

	if (status == SSTMAC_RC_NOT_DONE) {
		_sstmacx_nic_tx_free(nic, txd);
		SSTMACX_INFO(FI_LOG_EP_DATA,
			  "SSTMAC_SmsgSendWTag returned %s\n",
			  sstmac_err_str[status]);
	} else if (status != SSTMAC_RC_SUCCESS) {
		_sstmacx_nic_tx_free(nic, txd);
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "SSTMAC_SmsgSendWTag returned %s\n",
			  sstmac_err_str[status]);
	} else {
		SSTMACX_INFO(FI_LOG_EP_DATA, "Sent RMA CQ data, req: %p\n", req);
	}

	return sstmacxu_to_fi_errno(status);
}

static int __sstmacx_amo_txd_complete(void *arg, sstmac_return_t tx_status)
{
	struct sstmacx_tx_descriptor *txd = (struct sstmacx_tx_descriptor *)arg;
	struct sstmacx_fab_req *req = txd->req;
	int rc = FI_SUCCESS;

	_sstmacx_nic_tx_free(req->vc->ep->nic, txd);

	if (tx_status != SSTMAC_RC_SUCCESS) {
		return __sstmacx_amo_post_err(req, FI_ECANCELED);
	}

	if (req->vc->peer_caps & FI_RMA_EVENT) {
		/* control message needed for a counter event. */
		req->work_fn = __sstmacx_amo_send_cntr_req;
		_sstmacx_vc_queue_work_req(req);
	} else {
		/* complete request */
		rc = __sstmacx_amo_send_completion(req->vc->ep, req);
		if (rc != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "__sstmacx_amo_send_completion() failed: %d\n",
				  rc);

		__sstmacx_amo_fr_complete(req);
	}

	return FI_SUCCESS;
}

/*
 * Datatypes:
 *
 * FI_INT8, FI_UINT8, FI_INT16, FI_UINT16,
 * FI_INT32, FI_UINT32,
 * FI_INT64, FI_UINT64,
 * FI_FLOAT, FI_DOUBLE,
 * FI_FLOAT_COMPLEX, FI_DOUBLE_COMPLEX,
 * FI_LONG_DOUBLE, FI_LONG_DOUBLE_COMPLEX
 */

static int __sstmacx_amo_cmds[FI_ATOMIC_OP_LAST][FI_DATATYPE_LAST] = {
	/*
	 * Basic AMO types:
	 * FI_MIN, FI_MAX, FI_SUM, FI_PROD, FI_LOR, FI_LAND,  FI_BOR,  FI_BAND,
	 *       FI_LXOR, FI_BXOR, and FI_ATOMIC_WRITE.
	 */
	[FI_MIN] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_IMIN_S, 0, SSTMAC_FMA_ATOMIC2_IMIN, 0, SSTMAC_FMA_ATOMIC2_FPMIN_S, SSTMAC_FMA_ATOMIC2_FPMIN },
	[FI_MAX] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_IMAX_S, 0, SSTMAC_FMA_ATOMIC2_IMAX, 0, SSTMAC_FMA_ATOMIC2_FPMAX_S, SSTMAC_FMA_ATOMIC2_FPMAX },
	[FI_SUM] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_IADD_S, SSTMAC_FMA_ATOMIC2_IADD_S, SSTMAC_FMA_ATOMIC2_IADD, SSTMAC_FMA_ATOMIC2_IADD, SSTMAC_FMA_ATOMIC2_FPADD_S, 0 /* DP addition is broken */ },
	[FI_BOR] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_OR_S, SSTMAC_FMA_ATOMIC2_OR_S, SSTMAC_FMA_ATOMIC2_OR, SSTMAC_FMA_ATOMIC2_OR, 0, 0 },
	[FI_BAND] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_AND_S, SSTMAC_FMA_ATOMIC2_AND_S, SSTMAC_FMA_ATOMIC2_AND, SSTMAC_FMA_ATOMIC2_AND, 0, 0 },
	[FI_BXOR] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_XOR_S, SSTMAC_FMA_ATOMIC2_XOR_S, SSTMAC_FMA_ATOMIC2_XOR, SSTMAC_FMA_ATOMIC2_XOR, 0, 0 },
	[FI_ATOMIC_WRITE] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_SWAP_S, SSTMAC_FMA_ATOMIC2_SWAP_S, SSTMAC_FMA_ATOMIC2_SWAP, SSTMAC_FMA_ATOMIC2_SWAP, SSTMAC_FMA_ATOMIC2_SWAP_S, SSTMAC_FMA_ATOMIC2_SWAP },
};

static int __sstmacx_fetch_amo_cmds[FI_ATOMIC_OP_LAST][FI_DATATYPE_LAST] = {
	/*
	 * Fetch AMO types:
	 * FI_MIN, FI_MAX, FI_SUM, FI_PROD, FI_LOR, FI_LAND, FI_BOR,  FI_BAND,
	 *      FI_LXOR, FI_BXOR, FI_ATOMIC_READ, and FI_ATOMIC_WRITE.
	 */
	[FI_MIN] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_FIMIN_S, 0, SSTMAC_FMA_ATOMIC2_FIMIN, 0, SSTMAC_FMA_ATOMIC2_FFPMIN_S, SSTMAC_FMA_ATOMIC2_FFPMIN },
	[FI_MAX] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_FIMAX_S, 0, SSTMAC_FMA_ATOMIC2_FIMAX, 0, SSTMAC_FMA_ATOMIC2_FFPMAX_S, SSTMAC_FMA_ATOMIC2_FFPMAX },
	[FI_SUM] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_FIADD_S, SSTMAC_FMA_ATOMIC2_FIADD_S, SSTMAC_FMA_ATOMIC2_FIADD, SSTMAC_FMA_ATOMIC2_FIADD, SSTMAC_FMA_ATOMIC2_FFPADD_S, 0 /* DP addition is broken */ },
	[FI_BOR] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_FOR_S, SSTMAC_FMA_ATOMIC2_FOR_S, SSTMAC_FMA_ATOMIC2_FOR, SSTMAC_FMA_ATOMIC2_FOR, 0, 0 },
	[FI_BAND] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_FAND_S, SSTMAC_FMA_ATOMIC2_FAND_S, SSTMAC_FMA_ATOMIC2_FAND, SSTMAC_FMA_ATOMIC2_FAND, 0, 0 },
	[FI_BXOR] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_FXOR_S, SSTMAC_FMA_ATOMIC2_FXOR_S, SSTMAC_FMA_ATOMIC2_FXOR, SSTMAC_FMA_ATOMIC2_FXOR, 0, 0 },
	[FI_ATOMIC_READ] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_FAND_S, SSTMAC_FMA_ATOMIC2_FAND_S, SSTMAC_FMA_ATOMIC2_FAND, SSTMAC_FMA_ATOMIC2_FAND, SSTMAC_FMA_ATOMIC2_FAND_S, SSTMAC_FMA_ATOMIC2_FAND },
	[FI_ATOMIC_WRITE] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_FSWAP_S, SSTMAC_FMA_ATOMIC2_FSWAP_S, SSTMAC_FMA_ATOMIC2_FSWAP, SSTMAC_FMA_ATOMIC2_FSWAP, SSTMAC_FMA_ATOMIC2_FSWAP_S, SSTMAC_FMA_ATOMIC2_FSWAP },
};

static int __sstmacx_cmp_amo_cmds[FI_ATOMIC_OP_LAST][FI_DATATYPE_LAST] = {
	/*
	 * Compare AMO types:
	 * FI_CSWAP,  FI_CSWAP_NE,  FI_CSWAP_LE,
	 *      FI_CSWAP_LT, FI_CSWAP_GE, FI_CSWAP_GT, and FI_MSWAP.
	 */
	[FI_CSWAP] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_FCSWAP_S, SSTMAC_FMA_ATOMIC2_FCSWAP_S, SSTMAC_FMA_ATOMIC2_FCSWAP, SSTMAC_FMA_ATOMIC2_FCSWAP, SSTMAC_FMA_ATOMIC2_FCSWAP_S, SSTMAC_FMA_ATOMIC2_FCSWAP },
	[FI_MSWAP] = { 0,0,0,0, SSTMAC_FMA_ATOMIC2_FAX_S, SSTMAC_FMA_ATOMIC2_FAX_S, SSTMAC_FMA_ATOMIC2_FAX, SSTMAC_FMA_ATOMIC2_FAX, SSTMAC_FMA_ATOMIC2_FAX_S, SSTMAC_FMA_ATOMIC2_FAX },
};

/* Return a SSTMAC AMO command for a LF operation, datatype, AMO type. */
extern "C" int _sstmacx_atomic_cmd(enum fi_datatype dt, enum fi_op op,
		     enum sstmacx_fab_req_type fr_type)
{
	if (!((fr_type == SSTMACX_FAB_RQ_NAMO_AX)   ||
	      (fr_type == SSTMACX_FAB_RQ_NAMO_FAX)  ||
	      (fr_type == SSTMACX_FAB_RQ_NAMO_AX_S) ||
	      (fr_type == SSTMACX_FAB_RQ_NAMO_FAX_S)) &&
	    (dt >= FI_DATATYPE_LAST || op >= FI_ATOMIC_OP_LAST)) {
		return -FI_EOPNOTSUPP;
	}

	switch(fr_type) {
	case SSTMACX_FAB_RQ_AMO:
		return __sstmacx_amo_cmds[op][dt] ?: -FI_EOPNOTSUPP;
	case SSTMACX_FAB_RQ_FAMO:
		return __sstmacx_fetch_amo_cmds[op][dt] ?: -FI_EOPNOTSUPP;
	case SSTMACX_FAB_RQ_CAMO:
		return __sstmacx_cmp_amo_cmds[op][dt] ?: -FI_EOPNOTSUPP;
	case SSTMACX_FAB_RQ_NAMO_AX:
		return SSTMAC_FMA_ATOMIC2_AX;
	case SSTMACX_FAB_RQ_NAMO_AX_S:
		return SSTMAC_FMA_ATOMIC2_AX_S;
	case SSTMACX_FAB_RQ_NAMO_FAX:
		return SSTMAC_FMA_ATOMIC2_FAX;
	case SSTMACX_FAB_RQ_NAMO_FAX_S:
		return SSTMAC_FMA_ATOMIC2_FAX_S;
	default:
		break;
	}

	return -FI_EOPNOTSUPP;
}

extern "C" int _sstmacx_amo_post_req(void *data)
{
	struct sstmacx_fab_req *fab_req = (struct sstmacx_fab_req *)data;
	struct sstmacx_fid_ep *ep = fab_req->sstmacx_ep;
	struct sstmacx_nic *nic = ep->nic;
	struct sstmacx_fid_mem_desc *loc_md;
	struct sstmacx_tx_descriptor *txd;
	sstmac_mem_handle_t mdh;
	sstmac_return_t status;
	int rc;
	int inject_err = _sstmacx_req_inject_err(fab_req);

	if (!sstmacx_ops_allowed(ep, fab_req->vc->peer_caps, fab_req->flags)) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "flags:0x%llx, %s\n", fab_req->flags,
			   fi_tostr(&fab_req->flags, FI_TYPE_OP_FLAGS));
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "caps:0x%llx, %s\n",
			   ep->caps, fi_tostr(&ep->caps, FI_TYPE_CAPS));
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "peer_caps:0x%llx, %s\n",
			   fab_req->vc->peer_caps,
			   fi_tostr(&fab_req->vc->peer_caps, FI_TYPE_OP_FLAGS));

		rc = __sstmacx_amo_post_err(fab_req, FI_EOPNOTSUPP);
		if (rc != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "__sstmacx_amo_post_err() failed: %d\n", rc);
		return -FI_ECANCELED;
	}

	rc = _sstmacx_nic_tx_alloc(nic, &txd);
	if (rc) {
		SSTMACX_INFO(FI_LOG_EP_DATA, "_sstmacx_nic_tx_alloc() failed: %d\n",
			 rc);
		return -FI_ENOSPC;
	}

	txd->completer_fn = __sstmacx_amo_txd_complete;
	txd->req = fab_req;

	/* Mem handle CRC is not validated during FMA operations.  Skip this
	 * costly calculation. */
	_SSTMACX_CONVERT_MR_KEY(ep->auth_key->using_vmdh,
			fab_req->vc->peer_key_offset,
			_sstmacx_convert_key_to_mhdl_no_crc,
			&fab_req->amo.rem_mr_key, &mdh);

	loc_md = (struct sstmacx_fid_mem_desc *)fab_req->amo.loc_md;

	txd->sstmac_desc.type = SSTMAC_POST_AMO;
	txd->sstmac_desc.cq_mode = SSTMAC_CQMODE_GLOBAL_EVENT; /* check flags */
	txd->sstmac_desc.dlvr_mode = SSTMAC_DLVMODE_PERFORMANCE; /* check flags */
	txd->sstmac_desc.local_addr = (uint64_t)fab_req->amo.loc_addr;
	if (loc_md) {
		txd->sstmac_desc.local_mem_hndl = loc_md->mem_hndl;
	}
	txd->sstmac_desc.remote_addr = (uint64_t)fab_req->amo.rem_addr;
	txd->sstmac_desc.remote_mem_hndl = mdh;
	txd->sstmac_desc.length = fab_req->amo.len;
	txd->sstmac_desc.rdma_mode = 0; /* check flags */
	txd->sstmac_desc.src_cq_hndl = nic->tx_cq; /* check flags */

	txd->sstmac_desc.amo_cmd = _sstmacx_atomic_cmd(fab_req->amo.datatype,
						 fab_req->amo.op,
						 fab_req->type);
	txd->sstmac_desc.first_operand = fab_req->amo.first_operand;
	txd->sstmac_desc.second_operand = fab_req->amo.second_operand;

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "fo:%016lx so:%016lx\n",
		   txd->sstmac_desc.first_operand, txd->sstmac_desc.second_operand);
	SSTMACX_DEBUG(FI_LOG_EP_DATA, "amo_cmd:%x\n",
		   txd->sstmac_desc.amo_cmd);
	SSTMACX_LOG_DUMP_TXD(txd);

	COND_ACQUIRE(nic->requires_lock, &nic->lock);

	if (OFI_UNLIKELY(inject_err)) {
		_sstmacx_nic_txd_err_inject(nic, txd);
		status = SSTMAC_RC_SUCCESS;
	} else {
		status = SSTMAC_PostFma(fab_req->vc->sstmac_ep, &txd->sstmac_desc);
	}

	COND_RELEASE(nic->requires_lock, &nic->lock);

	if (status != SSTMAC_RC_SUCCESS) {
		_sstmacx_nic_tx_free(nic, txd);
		SSTMACX_INFO(FI_LOG_EP_DATA, "SSTMAC_Post*() failed: %s\n",
			  sstmac_err_str[status]);
	}

	return sstmacxu_to_fi_errno(status);
}

ssize_t _sstmacx_atomic(struct sstmacx_fid_ep *ep,
		     enum sstmacx_fab_req_type fr_type,
		     const struct fi_msg_atomic *msg,
		     const struct fi_ioc *comparev,
		     void **compare_desc,
		     size_t compare_count,
		     struct fi_ioc *resultv,
		     void **result_desc,
		     size_t result_count,
		     uint64_t flags)
{
	struct sstmacx_vc *vc;
	struct sstmacx_fab_req *req;
	struct sstmacx_fid_mem_desc *md = NULL;
	int rc, len;
	struct fid_mr *auto_mr = NULL;
	void *mdesc = NULL;
	uint64_t compare_operand = 0;
	void *loc_addr = NULL;
	int dt_len, dt_align;
	int connected;

	if (!(flags & FI_INJECT) && !ep->send_cq &&
	    (((fr_type == SSTMACX_FAB_RQ_AMO ||
	      fr_type == SSTMACX_FAB_RQ_NAMO_AX ||
	      fr_type == SSTMACX_FAB_RQ_NAMO_AX_S) &&
	      !ep->write_cntr) ||
	     ((fr_type == SSTMACX_FAB_RQ_FAMO ||
	      fr_type == SSTMACX_FAB_RQ_CAMO ||
	      fr_type == SSTMACX_FAB_RQ_NAMO_FAX ||
	      fr_type == SSTMACX_FAB_RQ_NAMO_FAX_S) &&
	      !ep->read_cntr))) {
		return -FI_ENOCQ;
	}


	if (!ep || !msg || !msg->msg_iov ||
	    msg->msg_iov[0].count != 1 ||
	    msg->iov_count != SSTMACX_MAX_ATOMIC_IOV_LIMIT ||
	    !msg->rma_iov)
		return -FI_EINVAL;

	/*
	 * see fi_atomic man page
	 */

	if ((msg->op != FI_ATOMIC_READ) &&
		!msg->msg_iov[0].addr)
		return -FI_EINVAL;

	if (flags & FI_TRIGGER) {
		struct fi_triggered_context *trigger_context =
				(struct fi_triggered_context *)msg->context;
		if ((trigger_context->event_type != FI_TRIGGER_THRESHOLD) ||
		    (flags & FI_INJECT)) {
			return -FI_EINVAL;
		}
	}

	if (fr_type == SSTMACX_FAB_RQ_CAMO) {
		if (!comparev || !comparev[0].addr || compare_count != 1)
			return -FI_EINVAL;

		compare_operand = *(uint64_t *)comparev[0].addr;
	}

	dt_len = ofi_datatype_size(msg->datatype);
	dt_align = dt_len - 1;
	len = dt_len * msg->msg_iov->count;

	if (msg->rma_iov->addr & dt_align) {
		SSTMACX_INFO(FI_LOG_EP_DATA,
			  "Invalid target alignment: %d (mask 0x%x)\n",
			  msg->rma_iov->addr, dt_align);
		return -FI_EINVAL;
	}

	/* need a memory descriptor for all fetching and comparison AMOs */
	if (fr_type == SSTMACX_FAB_RQ_FAMO ||
	    fr_type == SSTMACX_FAB_RQ_CAMO ||
	    fr_type == SSTMACX_FAB_RQ_NAMO_FAX ||
	    fr_type == SSTMACX_FAB_RQ_NAMO_FAX_S) {
		if (!resultv || !resultv[0].addr || result_count != 1)
			return -FI_EINVAL;

		loc_addr = resultv[0].addr;

		if ((uint64_t)loc_addr & dt_align) {
			SSTMACX_INFO(FI_LOG_EP_DATA,
				  "Invalid source alignment: %d (mask 0x%x)\n",
				  loc_addr, dt_align);
			return -FI_EINVAL;
		}

		if (!result_desc || !result_desc[0]) {
			rc = _sstmacx_mr_reg(&ep->domain->domain_fid.fid,
					 loc_addr, len, FI_READ | FI_WRITE,
					 0, 0, 0, &auto_mr,
					 NULL, ep->auth_key, SSTMACX_PROV_REG);
			if (rc != FI_SUCCESS) {
				SSTMACX_INFO(FI_LOG_EP_DATA,
					  "Failed to auto-register local buffer: %d\n",
					  rc);
				return rc;
			}
			flags |= FI_LOCAL_MR;
			mdesc = (void *)auto_mr;
			SSTMACX_INFO(FI_LOG_EP_DATA, "auto-reg MR: %p\n",
				  auto_mr);
		} else {
			mdesc = result_desc[0];
		}
	}

	/* setup fabric request */
	req = _sstmacx_fr_alloc(ep);
	if (!req) {
		SSTMACX_INFO(FI_LOG_EP_DATA, "_sstmacx_fr_alloc() failed\n");
		rc = -FI_ENOSPC;
		goto err_fr_alloc;
	}

	req->type = fr_type;
	req->sstmacx_ep = ep;
	req->user_context = msg->context;
	req->work_fn = _sstmacx_amo_post_req;

	if (mdesc) {
		md = container_of(mdesc, struct sstmacx_fid_mem_desc, mr_fid);
	}
	req->amo.loc_md = (void *)md;
	req->amo.loc_addr = (uint64_t)loc_addr;

	if ((fr_type == SSTMACX_FAB_RQ_NAMO_AX)   ||
	    (fr_type == SSTMACX_FAB_RQ_NAMO_FAX)  ||
	    (fr_type == SSTMACX_FAB_RQ_NAMO_AX_S) ||
	    (fr_type == SSTMACX_FAB_RQ_NAMO_FAX_S)) {
		req->amo.first_operand =
			*(uint64_t *)msg->msg_iov[0].addr;
		req->amo.second_operand =
			*((uint64_t *)(msg->msg_iov[0].addr) + 1);
	} else if (msg->op == FI_ATOMIC_READ) {
		req->amo.first_operand = 0xFFFFFFFFFFFFFFFF; /* operand to FAND */
	} else if (msg->op == FI_CSWAP) {
		req->amo.first_operand = compare_operand;
		req->amo.second_operand = *(uint64_t *)msg->msg_iov[0].addr;
	} else if (msg->op == FI_MSWAP) {
		req->amo.first_operand = ~compare_operand;
		req->amo.second_operand = *(uint64_t *)msg->msg_iov[0].addr;
		req->amo.second_operand &= compare_operand;
	} else {
		req->amo.first_operand = *(uint64_t *)msg->msg_iov[0].addr;
	}

	req->amo.rem_addr = msg->rma_iov->addr;
	req->amo.rem_mr_key = msg->rma_iov->key;
	req->amo.len = len;
	req->amo.imm = msg->data;
	req->amo.datatype = msg->datatype;
	req->amo.op = msg->op;
	req->flags = flags;

	/* Inject interfaces always suppress completions.  If
	 * SELECTIVE_COMPLETION is set, honor any setting.  Otherwise, always
	 * deliver a completion. */
	if ((flags & SSTMACX_SUPPRESS_COMPLETION) ||
	    (ep->send_selective_completion && !(flags & FI_COMPLETION))) {
		req->flags &= ~FI_COMPLETION;
	} else {
		req->flags |= FI_COMPLETION;
	}

	COND_ACQUIRE(ep->requires_lock, &ep->vc_lock);

	/* find VC for target */
	rc = _sstmacx_vc_ep_get_vc(ep, msg->addr, &vc);
	if (rc) {
		SSTMACX_INFO(FI_LOG_EP_DATA,
			  "_sstmacx_vc_ep_get_vc() failed, addr: %lx, rc:\n",
			  msg->addr, rc);
		goto err_get_vc;
	}

	req->vc = vc;

	rc = _sstmacx_vc_queue_tx_req(req);
	connected = (vc->conn_state == SSTMACX_VC_CONNECTED);

	COND_RELEASE(ep->requires_lock, &ep->vc_lock);

	/*
	 *If a new VC was allocated, progress CM before returning.
	 * If the VC is connected and there's a backlog, poke
	 * the nic progress engine befure returning.
	 */
	if (!connected) {
		_sstmacx_cm_nic_progress(ep->cm_nic);
	} else if (!dlist_empty(&vc->tx_queue)) {
		_sstmacx_nic_progress(vc->ep->nic);
	}

	return rc;

err_get_vc:
	COND_RELEASE(ep->requires_lock, &ep->vc_lock);
err_fr_alloc:
	if (auto_mr) {
		fi_close(&auto_mr->fid);
	}
	return rc;
}


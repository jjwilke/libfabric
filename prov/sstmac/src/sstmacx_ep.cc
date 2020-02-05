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

/*
 * Endpoint common code
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
#include "sstmacx_vector.h"
#include "sstmacx_msg.h"
#include "sstmacx_rma.h"
#include "sstmacx_atomic.h"
#include "sstmacx_cntr.h"
#include "sstmacx_xpmem.h"
#include "sstmacx_eq.h"
#include "sstmacx_cm.h"
#include "sstmacx_auth_key.h"

/*******************************************************************************
 * sstmacx_fab_req freelist functions
 *
 * These are wrappers around the sstmacx_freelist
 *
 ******************************************************************************/

#define SSTMACX_FAB_REQ_FL_MIN_SIZE 100
#define SSTMACX_FAB_REQ_FL_REFILL_SIZE 10

extern "C" int _sstmacx_ep_int_tx_pool_grow(struct sstmacx_fid_ep *ep)
{
	int ret, i;
	uint8_t *tx_bufs;
	struct fid_mr *auto_mr = NULL;
	struct sstmacx_fid_mem_desc *md = NULL;
	struct sstmacx_int_tx_buf *tx_buf_list;
	struct sstmacx_int_tx_ptrs *tx_ptrs;
	
	assert(ep);

	if (ep->int_tx_pool.nbufs >= SSTMACX_INT_TX_POOL_COUNT) {
		SSTMACX_WARN(FI_LOG_EP_DATA, "int_tx_pool is at max size\n");
		return -FI_ENOSPC;
	}

	tx_bufs = malloc(SSTMACX_INT_TX_POOL_SIZE * SSTMACX_INT_TX_BUF_SZ);
	if (tx_bufs == NULL) {
		SSTMACX_WARN(FI_LOG_EP_DATA, "tx_bufs allocation failed\n");
		goto tx_buf_err;
	}

	tx_buf_list = malloc(SSTMACX_INT_TX_POOL_SIZE *
				 sizeof(struct sstmacx_int_tx_buf));
	if (tx_buf_list == NULL) {
		SSTMACX_WARN(FI_LOG_EP_DATA, "tx_bufs_list allocation failed\n");
		goto tx_buf_list_err;
	}

	tx_ptrs = malloc(sizeof(struct sstmacx_int_tx_ptrs));
	if (tx_buf_list == NULL) {
		SSTMACX_WARN(FI_LOG_EP_DATA, "tx_ptrs allocation failed\n");
		goto tx_ptrs_err;
	}

	ret = _sstmacx_mr_reg(&ep->domain->domain_fid.fid, tx_bufs,
			SSTMACX_INT_TX_BUF_SZ * SSTMACX_INT_TX_POOL_SIZE,
			FI_READ | FI_WRITE, 0, 0, 0,
			&auto_mr, NULL, ep->auth_key, SSTMACX_PROV_REG);

	if (OFI_UNLIKELY(ret != FI_SUCCESS)) {
		SSTMACX_WARN(FI_LOG_EP_DATA, "sstmacx_mr_req returned: %s\n",
			   fi_strerror(-ret));
		goto reg_err;
	}

	md = container_of(auto_mr, struct sstmacx_fid_mem_desc, mr_fid);

	fastlock_acquire(&ep->int_tx_pool.lock);

	for (i = 0; i < SSTMACX_INT_TX_POOL_SIZE; i++) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA,
			"tx_bufs + (%d * SSTMACX_INT_TX_BUF_SZ) = %p\n",
			i, tx_bufs + (i * SSTMACX_INT_TX_BUF_SZ));
		tx_buf_list[i].buf = tx_bufs + (i * SSTMACX_INT_TX_BUF_SZ);
		tx_buf_list[i].md = md;
		slist_insert_tail(&tx_buf_list[i].e, &ep->int_tx_pool.sl);
	}

	tx_ptrs->md = md;
	tx_ptrs->buf_ptr = (void *) tx_bufs;
	tx_ptrs->sl_ptr = (void *) tx_buf_list;
	slist_insert_tail(&tx_ptrs->e, &ep->int_tx_pool.bl);

	ep->int_tx_pool.nbufs++;

	fastlock_release(&ep->int_tx_pool.lock);

	return FI_SUCCESS;

reg_err:
	free(tx_ptrs);
tx_ptrs_err:
	free(tx_buf_list);
tx_buf_list_err:
	free(tx_bufs);
tx_buf_err:
	return -FI_ENOSPC;
}

extern "C" int _sstmacx_ep_int_tx_pool_init(struct sstmacx_fid_ep *ep)
{
	int ret;

	assert(ep);

	ep->int_tx_pool.nbufs = 0;
	slist_init(&ep->int_tx_pool.sl);
	slist_init(&ep->int_tx_pool.bl);
	fastlock_init(&ep->int_tx_pool.lock);

	ret = _sstmacx_ep_int_tx_pool_grow(ep);
	if (ret != FI_SUCCESS)
		return ret;

	ep->int_tx_pool.enabled = true;

	return FI_SUCCESS;
}

void _sstmacx_ep_int_tx_pool_fini(struct sstmacx_fid_ep *ep)
{
	int ret;
	struct slist_entry *e;
	struct sstmacx_int_tx_ptrs *tx_ptrs;

	assert(ep);

	if (ep->int_tx_pool.enabled == false)
		return;

	fastlock_acquire(&ep->int_tx_pool.lock);

	while (!slist_empty(&ep->int_tx_pool.bl)) {
		e = slist_remove_head(&ep->int_tx_pool.bl);
		tx_ptrs = (struct sstmacx_int_tx_ptrs *)e;

		ret = fi_close(&tx_ptrs->md->mr_fid.fid);

		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_DATA, "fi_close returned: %s\n",
				   fi_strerror(-ret));
		}

		if (tx_ptrs->buf_ptr != NULL) {
			free(tx_ptrs->buf_ptr);
			tx_ptrs->buf_ptr = NULL;
		}

		if (tx_ptrs->sl_ptr != NULL) {
			free(tx_ptrs->sl_ptr);
			tx_ptrs->sl_ptr = NULL;
		}

		free(tx_ptrs);
		ep->int_tx_pool.nbufs--;
	}

	ep->int_tx_pool.enabled = false;

	fastlock_release(&ep->int_tx_pool.lock);
}

static int __fr_freelist_init(struct sstmacx_fid_ep *ep)
{
	int ret;

	assert(ep);
	ret = _sstmacx_fl_init_ts(sizeof(struct sstmacx_fab_req),
			       offsetof(struct sstmacx_fab_req, dlist),
			       SSTMACX_FAB_REQ_FL_MIN_SIZE,
			       SSTMACX_FAB_REQ_FL_REFILL_SIZE,
			       0, 0, &ep->fr_freelist);

	if (ret != FI_SUCCESS) {
		SSTMACX_DEBUG(FI_LOG_EP_DATA, "_sstmacx_fl_init_ts returned: %s\n",
			   fi_strerror(-ret));
		return ret;
	}

	return ret;
}

static void __fr_freelist_destroy(struct sstmacx_fid_ep *ep)
{
	assert(ep);

	_sstmacx_fl_destroy(&ep->fr_freelist);
}

extern "C" int _sstmacx_ep_rx_enable(struct sstmacx_fid_ep *ep)
{
	if (ep->recv_cq) {
		_sstmacx_cq_poll_obj_add(ep->recv_cq, ep->nic,
				      _sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cq_poll_obj_add(ep->recv_cq, ep->cm_nic,
					      _sstmacx_cm_nic_progress);
		ep->rx_enabled = true;
	}

	if (ep->rwrite_cntr) {
		_sstmacx_cntr_poll_obj_add(ep->rwrite_cntr, ep->nic,
					_sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cntr_poll_obj_add(ep->rwrite_cntr, ep->cm_nic,
						_sstmacx_cm_nic_progress);
	}

	if (ep->rread_cntr) {
		_sstmacx_cntr_poll_obj_add(ep->rread_cntr, ep->nic,
					_sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cntr_poll_obj_add(ep->rread_cntr, ep->cm_nic,
						_sstmacx_cm_nic_progress);
	}

	return FI_SUCCESS;
}

extern "C" int _sstmacx_ep_tx_enable(struct sstmacx_fid_ep *ep)
{

	if (ep->send_cq) {
		_sstmacx_cq_poll_obj_add(ep->send_cq, ep->nic,
				      _sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cq_poll_obj_add(ep->send_cq, ep->cm_nic,
					      _sstmacx_cm_nic_progress);
		ep->tx_enabled = true;
	}

	if (ep->send_cntr) {
		_sstmacx_cntr_poll_obj_add(ep->send_cntr, ep->nic,
					_sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cntr_poll_obj_add(ep->send_cntr, ep->cm_nic,
						_sstmacx_cm_nic_progress);
	}

	if (ep->write_cntr) {
		_sstmacx_cntr_poll_obj_add(ep->write_cntr, ep->nic,
					_sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cntr_poll_obj_add(ep->write_cntr, ep->cm_nic,
						_sstmacx_cm_nic_progress);
	}

	if (ep->read_cntr) {
		_sstmacx_cntr_poll_obj_add(ep->read_cntr, ep->nic,
					_sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cntr_poll_obj_add(ep->read_cntr, ep->cm_nic,
						_sstmacx_cm_nic_progress);
	}

	return FI_SUCCESS;
}


/*******************************************************************************
 * Forward declaration for ops structures
 ******************************************************************************/

static struct fi_ops sstmacx_ep_fi_ops;
static struct fi_ops_ep sstmacx_ep_ops;
static struct fi_ops_msg sstmacx_ep_msg_ops;
static struct fi_ops_rma sstmacx_ep_rma_ops;
struct fi_ops_tagged sstmacx_ep_tagged_ops;
struct fi_ops_atomic sstmacx_ep_atomic_ops;

/*******************************************************************************
 * EP common messaging wrappers.
 ******************************************************************************/
ssize_t _ep_recv(struct fid_ep *ep, void *buf, size_t len,
		 void *desc, fi_addr_t src_addr, void *context,
		 uint64_t flags, uint64_t tag, uint64_t ignore)
{
	struct sstmacx_fid_ep *ep_priv;

	if (!ep) {
		return -FI_EINVAL;
	}

	ep_priv = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(ep_priv->type));

	if (!(ep_priv->op_flags & FI_MULTI_RECV)) {
		return _sstmacx_recv(ep_priv,
				  (uint64_t)buf,
				  len, desc,
				  src_addr,
				  context,
				  ep_priv->op_flags | flags,
				  tag,
				  ignore,
				  NULL);
	 } else {
		return _sstmacx_recv_mr(ep_priv,
				     (uint64_t)buf,
				     len,
				     desc,
				     src_addr,
				     context,
				     ep_priv->op_flags | flags,
				     tag,
				     ignore);
	}
}

ssize_t _ep_recvv(struct fid_ep *ep, const struct iovec *iov,
		  void **desc, size_t count, fi_addr_t src_addr,
		  void *context, uint64_t flags, uint64_t tag,
		  uint64_t ignore)
{
	struct sstmacx_fid_ep *ep_priv;

	if (!ep || !iov || count > SSTMACX_MAX_MSG_IOV_LIMIT) {
		return -FI_EINVAL;
	}

	ep_priv = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(ep_priv->type));

	if (count <= 1) {
		if (!(ep_priv->op_flags & FI_MULTI_RECV)) {
			return _sstmacx_recv(ep_priv,
					  (uint64_t)iov[0].iov_base,
					  iov[0].iov_len,
					  desc ? desc[0] : NULL,
					  src_addr,
					  context,
					  ep_priv->op_flags | flags,
					  tag,
					  ignore,
					  NULL);
		} else {
			return _sstmacx_recv_mr(ep_priv,
					  (uint64_t)iov[0].iov_base,
					  iov[0].iov_len,
					  desc ? desc[0] : NULL,
					  src_addr,
					  context,
					  ep_priv->op_flags | flags,
					  tag,
					  ignore);
		}
	}

	return _sstmacx_recvv(ep_priv, iov, desc, count, src_addr,
			   context, ep_priv->op_flags | flags, ignore, tag);
}

ssize_t _ep_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
		    uint64_t flags, uint64_t tag,
		    uint64_t ignore)
{
	struct iovec iov;
	struct sstmacx_fid_ep *ep_priv = container_of(ep, struct sstmacx_fid_ep, ep_fid);

	ep_priv = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(ep_priv->type));

	iov.iov_base = NULL;
	iov.iov_len = 0;

	if (!msg) {
		return -FI_EINVAL;
	}

	if (flags & FI_MULTI_RECV) {
		return _sstmacx_recv_mr(ep_priv,
				     (uint64_t)msg->msg_iov[0].iov_base,
				     msg->msg_iov[0].iov_len,
				     msg->desc ? msg->desc[0] : NULL,
				     msg->addr,
				     msg->context,
				     ep_priv->op_flags | flags,
				     tag,
				     ignore);
	}

	/* msg_iov can be undefined when using FI_PEEK, etc. */
	return _ep_recvv(ep, msg->msg_iov ? msg->msg_iov : &iov, msg->desc,
			 msg->iov_count, msg->addr, msg->context, flags, tag,
			 ignore);
}

ssize_t _ep_send(struct fid_ep *ep, const void *buf, size_t len,
		 void *desc, fi_addr_t dest_addr, void *context,
		 uint64_t flags, uint64_t tag)
{
	struct sstmacx_fid_ep *sstmacx_ep;

	if (!ep) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	return _sstmacx_send(sstmacx_ep, (uint64_t)buf, len, desc, dest_addr, context,
			  sstmacx_ep->op_flags | flags, 0, tag);
}

ssize_t _ep_sendv(struct fid_ep *ep, const struct iovec *iov,
		  void **desc, size_t count, fi_addr_t dest_addr,
		  void *context, uint64_t flags, uint64_t tag)
{
	struct sstmacx_fid_ep *sstmacx_ep;

	if (!ep || !iov || !count || count > SSTMACX_MAX_MSG_IOV_LIMIT) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	if (count == 1) {
		return _sstmacx_send(sstmacx_ep, (uint64_t)iov[0].iov_base,
				  iov[0].iov_len, desc ? desc[0] : NULL,
				  dest_addr, context, sstmacx_ep->op_flags | flags,
				  0, tag);
	}

	return _sstmacx_sendv(sstmacx_ep, iov, desc, count, dest_addr, context,
			   sstmacx_ep->op_flags | flags, tag);
}

ssize_t _ep_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
		     uint64_t flags, uint64_t tag)
{
	struct sstmacx_fid_ep *sstmacx_ep;

	if (!ep || !msg || !msg->msg_iov || !msg->iov_count) {
		return -FI_EINVAL;
	}

	/* Must check the iov count here, can't send msg->data to sendv */
	if (msg->iov_count > 1) {
		return _ep_sendv(ep, msg->msg_iov, msg->desc, msg->iov_count,
				 msg->addr, msg->context, flags, tag);
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	return _sstmacx_send(sstmacx_ep, (uint64_t)msg->msg_iov[0].iov_base,
			  msg->msg_iov[0].iov_len,
			  msg->desc ? msg->desc[0] : NULL, msg->addr,
			  msg->context, flags, msg->data, tag);
}

ssize_t _ep_inject(struct fid_ep *ep, const void *buf,
		   size_t len, uint64_t data, fi_addr_t dest_addr,
		   uint64_t flags, uint64_t tag)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	uint64_t inject_flags;

	if (!ep) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	inject_flags = (sstmacx_ep->op_flags | FI_INJECT |
			SSTMACX_SUPPRESS_COMPLETION | flags);

	return _sstmacx_send(sstmacx_ep, (uint64_t)buf, len, NULL, dest_addr,
			  NULL, inject_flags, data, tag);
}

ssize_t _ep_senddata(struct fid_ep *ep, const void *buf,
		     size_t len, void *desc, uint64_t data,
		     fi_addr_t dest_addr, void *context,
		     uint64_t flags, uint64_t tag)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	uint64_t sd_flags;

	if (!ep) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	sd_flags = sstmacx_ep->op_flags | FI_REMOTE_CQ_DATA | flags;

	return _sstmacx_send(sstmacx_ep, (uint64_t)buf, len, desc, dest_addr,
			  context, sd_flags, data, tag);
}

static void __sstmacx_vc_destroy_ht_entry(void *val)
{
	struct sstmacx_vc *vc = (struct sstmacx_vc *) val;

	_sstmacx_vc_destroy(vc);
}

/*******************************************************************************
 * EP vc initialization helper
 ******************************************************************************/

extern "C" int _sstmacx_ep_init_vc(struct sstmacx_fid_ep *ep_priv)
{
	int ret;
	sstmacx_hashtable_attr_t sstmacx_ht_attr;
	sstmacx_vec_attr_t sstmacx_vec_attr;

	if (ep_priv->av == NULL) {
		SSTMACX_FATAL(FI_LOG_EP_CTRL,
			   "_sstmacx_ep_init_vc av field NULL\n");
	}

	if (ep_priv->av->type == FI_AV_TABLE) {
		/* Use array to store EP VCs when using FI_AV_TABLE. */
		ep_priv->vc_table = calloc(1, sizeof(struct sstmacx_vector));
		if(ep_priv->vc_table == NULL)
			return -FI_ENOMEM;

		sstmacx_vec_attr.vec_initial_size =
				ep_priv->domain->params.ct_init_size;
		/* TODO: ep_priv->domain->params.ct_max_size; */
		sstmacx_vec_attr.vec_maximum_size = 1024*1024;
		sstmacx_vec_attr.vec_increase_step = ep_priv->domain->params.ct_step;
		sstmacx_vec_attr.vec_increase_type = SSTMACX_VEC_INCREASE_MULT;
		sstmacx_vec_attr.vec_internal_locking = SSTMACX_VEC_UNLOCKED;

		ret = _sstmacx_vec_init(ep_priv->vc_table, &sstmacx_vec_attr);
		SSTMACX_DEBUG(FI_LOG_EP_CTRL,
			   "ep_priv->vc_table = %p, ep_priv->vc_table->vector = %p\n",
			   ep_priv->vc_table, ep_priv->vc_table->vector);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL, "_sstmacx_vec_init returned %s\n",
				  fi_strerror(ret));
			goto err;
		}
	} else {
		/* Use hash table to store EP VCs when using FI_AV_MAP. */
		ep_priv->vc_ht = calloc(1, sizeof(struct sstmacx_hashtable));
		if (ep_priv->vc_ht == NULL)
			return -FI_ENOMEM;

		sstmacx_ht_attr.ht_initial_size =
				ep_priv->domain->params.ct_init_size;
		sstmacx_ht_attr.ht_maximum_size =
				ep_priv->domain->params.ct_max_size;
		sstmacx_ht_attr.ht_increase_step = ep_priv->domain->params.ct_step;
		sstmacx_ht_attr.ht_increase_type = SSTMACX_HT_INCREASE_MULT;
		sstmacx_ht_attr.ht_collision_thresh = 500;
		sstmacx_ht_attr.ht_hash_seed = 0xdeadbeefbeefdead;
		sstmacx_ht_attr.ht_internal_locking = 0;
		sstmacx_ht_attr.destructor = __sstmacx_vc_destroy_ht_entry;

		ret = _sstmacx_ht_init(ep_priv->vc_ht, &sstmacx_ht_attr);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "_sstmacx_ht_init returned %s\n",
				  fi_strerror(-ret));

			goto err;
		}
	}

	dlist_init(&ep_priv->unmapped_vcs);

	return FI_SUCCESS;

err:
	if (ep_priv->av->type == FI_AV_TABLE) {
		free(ep_priv->vc_table);
		ep_priv->vc_table = NULL;
	} else {
		free(ep_priv->vc_ht);
		ep_priv->vc_ht = NULL;
	}

	return ret;
}

static inline int __sstmacx_ep_fini_vc(struct sstmacx_fid_ep *ep)
{
	int ret;
	SSTMACX_VECTOR_ITERATOR(ep->vc_table, iter);
	struct sstmacx_vc *vc;

	/* Free unmapped VCs. */
	dlist_for_each(&ep->unmapped_vcs, vc, list) {
		_sstmacx_vc_destroy(vc);
	}

	if (!ep->av) {
		/* No AV bound, no mapped VCs clean up. */
		return FI_SUCCESS;
	}

	if (ep->av->type == FI_AV_TABLE) {
		/* Destroy all VCs */
		while ((vc = (struct sstmacx_vc *)
				_sstmacx_vec_iterator_next(&iter))) {
			_sstmacx_vec_remove_at(ep->vc_table,
					    SSTMACX_VECTOR_ITERATOR_IDX(iter));
			_sstmacx_vc_destroy(vc);
		}

		/* Destroy vector storage */
		ret = _sstmacx_vec_close(ep->vc_table);
		if (ret == FI_SUCCESS) {
			free(ep->vc_table);
			ep->vc_table = NULL;
		} else {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "_sstmacx_vec_close returned %s\n",
				  fi_strerror(-ret));
		}
	} else {
		/* Destroy VC storage, it automatically tears down VCs */
		ret = _sstmacx_ht_destroy(ep->vc_ht);
		if (ret == FI_SUCCESS) {
			free(ep->vc_ht);
			ep->vc_ht = NULL;
		} else {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				"_sstmacx_ht_destroy returned %s\n",
				  fi_strerror(-ret));
		}
	}

	return FI_SUCCESS;
}

/*******************************************************************************
 * EP messaging API function implementations.
 ******************************************************************************/

DIRECT_FN STATIC ssize_t sstmacx_ep_recv(struct fid_ep *ep, void *buf, size_t len,
				      void *desc, fi_addr_t src_addr,
				      void *context)
{
	return _ep_recv(ep, buf, len, desc, src_addr, context, 0, 0, 0);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_recvv(struct fid_ep *ep,
				       const struct iovec *iov,
				       void **desc, size_t count,
				       fi_addr_t src_addr,
				       void *context)
{
	return _ep_recvv(ep, iov, desc, count, src_addr, context, 0, 0, 0);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_recvmsg(struct fid_ep *ep,
					 const struct fi_msg *msg,
					 uint64_t flags)
{
	return _ep_recvmsg(ep, msg, flags & SSTMACX_RECVMSG_FLAGS, 0, 0);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_send(struct fid_ep *ep, const void *buf,
				      size_t len, void *desc,
				      fi_addr_t dest_addr, void *context)
{
	return _ep_send(ep, buf, len, desc, dest_addr, context, 0, 0);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_sendv(struct fid_ep *ep,
				       const struct iovec *iov,
				       void **desc, size_t count,
				       fi_addr_t dest_addr,
				       void *context)
{
	return _ep_sendv(ep, iov, desc, count, dest_addr, context, 0, 0);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_sendmsg(struct fid_ep *ep,
					 const struct fi_msg *msg,
					 uint64_t flags)
{
	return _ep_sendmsg(ep, msg, flags & SSTMACX_SENDMSG_FLAGS, 0);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_msg_inject(struct fid_ep *ep, const void *buf,
					    size_t len, fi_addr_t dest_addr)
{
	return _ep_inject(ep, buf, len, 0, dest_addr, 0, 0);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_senddata(struct fid_ep *ep, const void *buf,
					  size_t len, void *desc, uint64_t data,
					  fi_addr_t dest_addr, void *context)
{
	return _ep_senddata(ep, buf, len, desc, data, dest_addr, context, 0, 0);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_msg_injectdata(struct fid_ep *ep, const void *buf, size_t len,
		       uint64_t data, fi_addr_t dest_addr)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	uint64_t flags;

	if (!ep) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	flags = sstmacx_ep->op_flags | FI_INJECT | FI_REMOTE_CQ_DATA |
		SSTMACX_SUPPRESS_COMPLETION;

	return _sstmacx_send(sstmacx_ep, (uint64_t)buf, len, NULL, dest_addr,
			  NULL, flags, data, 0);
}

/*******************************************************************************
 * EP RMA API function implementations.
 ******************************************************************************/

DIRECT_FN STATIC ssize_t sstmacx_ep_read(struct fid_ep *ep, void *buf, size_t len,
				      void *desc, fi_addr_t src_addr, uint64_t addr,
				      uint64_t key, void *context)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	uint64_t flags;

	if (!ep) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	flags = sstmacx_ep->op_flags | SSTMACX_RMA_READ_FLAGS_DEF;

	return _sstmacx_rma(sstmacx_ep, SSTMACX_FAB_RQ_RDMA_READ,
			 (uint64_t)buf, len, desc,
			 src_addr, addr, key,
			 context, flags, 0);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_readv(struct fid_ep *ep, const struct iovec *iov, void **desc,
	      size_t count, fi_addr_t src_addr, uint64_t addr, uint64_t key,
	      void *context)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	uint64_t flags;

	if (!ep || !iov || !desc || count > SSTMACX_MAX_RMA_IOV_LIMIT) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	flags = sstmacx_ep->op_flags | SSTMACX_RMA_READ_FLAGS_DEF;

	return _sstmacx_rma(sstmacx_ep, SSTMACX_FAB_RQ_RDMA_READ,
			 (uint64_t)iov[0].iov_base, iov[0].iov_len, desc[0],
			 src_addr, addr, key,
			 context, flags, 0);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_readmsg(struct fid_ep *ep, const struct fi_msg_rma *msg, uint64_t flags)
{
	struct sstmacx_fid_ep *sstmacx_ep;

	if (!ep || !msg || !msg->msg_iov || !msg->rma_iov || !msg->desc ||
	    msg->iov_count != 1 || msg->rma_iov_count != 1 ||
	    msg->rma_iov[0].len > msg->msg_iov[0].iov_len) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	flags = (flags & SSTMACX_READMSG_FLAGS) | SSTMACX_RMA_READ_FLAGS_DEF;

	return _sstmacx_rma(sstmacx_ep, SSTMACX_FAB_RQ_RDMA_READ,
			 (uint64_t)msg->msg_iov[0].iov_base,
			 msg->msg_iov[0].iov_len, msg->desc[0],
			 msg->addr, msg->rma_iov[0].addr, msg->rma_iov[0].key,
			 msg->context, flags, msg->data);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_write(struct fid_ep *ep, const void *buf, size_t len, void *desc,
	      fi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	uint64_t flags;

	if (!ep) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	flags = sstmacx_ep->op_flags | SSTMACX_RMA_WRITE_FLAGS_DEF;

	return _sstmacx_rma(sstmacx_ep, SSTMACX_FAB_RQ_RDMA_WRITE,
			 (uint64_t)buf, len, desc, dest_addr, addr, key,
			 context, flags, 0);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_writev(struct fid_ep *ep, const struct iovec *iov, void **desc,
	       size_t count, fi_addr_t dest_addr, uint64_t addr, uint64_t key,
	       void *context)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	uint64_t flags;

	if (!ep || !iov || !desc || count > SSTMACX_MAX_RMA_IOV_LIMIT) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	flags = sstmacx_ep->op_flags | SSTMACX_RMA_WRITE_FLAGS_DEF;

	return _sstmacx_rma(sstmacx_ep, SSTMACX_FAB_RQ_RDMA_WRITE,
			 (uint64_t)iov[0].iov_base, iov[0].iov_len, desc[0],
			 dest_addr, addr, key, context, flags, 0);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_writemsg(struct fid_ep *ep, const struct fi_msg_rma *msg,
				uint64_t flags)
{
	struct sstmacx_fid_ep *sstmacx_ep;

	if (!ep || !msg || !msg->msg_iov || !msg->rma_iov ||
	    msg->iov_count != 1 ||
		msg->rma_iov_count > SSTMACX_MAX_RMA_IOV_LIMIT ||
	    msg->rma_iov[0].len > msg->msg_iov[0].iov_len) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	flags = (flags & SSTMACX_WRITEMSG_FLAGS) | SSTMACX_RMA_WRITE_FLAGS_DEF;

	return _sstmacx_rma(sstmacx_ep, SSTMACX_FAB_RQ_RDMA_WRITE,
			 (uint64_t)msg->msg_iov[0].iov_base,
			 msg->msg_iov[0].iov_len, msg->desc ? msg->desc[0] : NULL,
			 msg->addr, msg->rma_iov[0].addr, msg->rma_iov[0].key,
			 msg->context, flags, msg->data);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_rma_inject(struct fid_ep *ep, const void *buf,
					    size_t len, fi_addr_t dest_addr,
					    uint64_t addr, uint64_t key)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	uint64_t flags;

	if (!ep) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	flags = sstmacx_ep->op_flags | FI_INJECT | SSTMACX_SUPPRESS_COMPLETION |
			SSTMACX_RMA_WRITE_FLAGS_DEF;

	return _sstmacx_rma(sstmacx_ep, SSTMACX_FAB_RQ_RDMA_WRITE,
			 (uint64_t)buf, len, NULL,
			 dest_addr, addr, key,
			 NULL, flags, 0);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_writedata(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		  uint64_t data, fi_addr_t dest_addr, uint64_t addr,
		  uint64_t key, void *context)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	uint64_t flags;

	if (!ep) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	flags = sstmacx_ep->op_flags | FI_REMOTE_CQ_DATA |
			SSTMACX_RMA_WRITE_FLAGS_DEF;

	return _sstmacx_rma(sstmacx_ep, SSTMACX_FAB_RQ_RDMA_WRITE,
			 (uint64_t)buf, len, desc,
			 dest_addr, addr, key,
			 context, flags, data);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_rma_injectdata(struct fid_ep *ep, const void *buf, size_t len,
		       uint64_t data, fi_addr_t dest_addr, uint64_t addr,
		       uint64_t key)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	uint64_t flags;

	if (!ep) {
		return -FI_EINVAL;
	}

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	flags = sstmacx_ep->op_flags | FI_INJECT | FI_REMOTE_CQ_DATA |
			SSTMACX_SUPPRESS_COMPLETION | SSTMACX_RMA_WRITE_FLAGS_DEF;

	return _sstmacx_rma(sstmacx_ep, SSTMACX_FAB_RQ_RDMA_WRITE,
			 (uint64_t)buf, len, NULL,
			 dest_addr, addr, key,
			 NULL, flags, data);
}

/*******************************************************************************
 * EP Tag matching API function implementations.
 ******************************************************************************/

DIRECT_FN STATIC ssize_t sstmacx_ep_trecv(struct fid_ep *ep, void *buf, size_t len,
				       void *desc, fi_addr_t src_addr,
				       uint64_t tag, uint64_t ignore,
				       void *context)
{
	return _ep_recv(ep, buf, len, desc, src_addr, context,
			FI_TAGGED, tag, ignore);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_trecvv(struct fid_ep *ep,
					const struct iovec *iov,
					void **desc, size_t count,
					fi_addr_t src_addr,
					uint64_t tag, uint64_t ignore,
					void *context)
{
	return _ep_recvv(ep, iov, desc, count, src_addr, context,
			  FI_TAGGED, tag, ignore);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_trecvmsg(struct fid_ep *ep,
					  const struct fi_msg_tagged *msg,
					  uint64_t flags)
{
	const struct fi_msg _msg = {
			.msg_iov = msg->msg_iov,
			.desc = msg->desc,
			.iov_count = msg->iov_count,
			.addr = msg->addr,
			.context = msg->context,
			.data = msg->data
	};

	if (flags & ~SSTMACX_TRECVMSG_FLAGS)
		return -FI_EINVAL;

	/* From the fi_tagged man page regarding the use of FI_CLAIM:
	 *
	 * In order to use the FI_CLAIM flag, an  application  must  supply  a
	 * struct  fi_context  structure as the context for the receive opera-
	 * tion.  The same fi_context structure used for an FI_PEEK + FI_CLAIM
	 * operation must be used by the paired FI_CLAIM requests
	 */
	if ((flags & FI_CLAIM) && _msg.context == NULL)
		return -FI_EINVAL;

	/* From the fi_tagged man page regarding the use of FI_DISCARD:
	 *
	 * This  flag  must  be used in conjunction with either
	 * FI_PEEK or FI_CLAIM.
	 *
	 * Note: I suspect the use of all three flags at the same time is invalid,
	 * but the man page does not say that it is.
	 */
	if ((flags & FI_DISCARD) && !(flags & (FI_PEEK | FI_CLAIM)))
		return -FI_EINVAL;

	return _ep_recvmsg(ep, &_msg, flags | FI_TAGGED, msg->tag,
			msg->ignore);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_tsend(struct fid_ep *ep, const void *buf,
				       size_t len, void *desc,
				       fi_addr_t dest_addr, uint64_t tag,
				       void *context)
{
	return _ep_send(ep, buf, len, desc, dest_addr, context,
			FI_TAGGED, tag);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_tsendv(struct fid_ep *ep,
					const struct iovec *iov,
					void **desc, size_t count,
					fi_addr_t dest_addr,
					uint64_t tag, void *context)
{
	return _ep_sendv(ep, iov, desc, count, dest_addr, context,
			 FI_TAGGED, tag);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_tsendmsg(struct fid_ep *ep,
					  const struct fi_msg_tagged *msg,
					  uint64_t flags)
{
	const struct fi_msg _msg = {
			.msg_iov = msg->msg_iov,
			.desc = msg->desc,
			.iov_count = msg->iov_count,
			.addr = msg->addr,
			.context = msg->context,
			.data = msg->data
	};

	if (flags & ~(SSTMACX_SENDMSG_FLAGS))
		return -FI_EINVAL;

	return _ep_sendmsg(ep, &_msg, flags | FI_TAGGED, msg->tag);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_tinject(struct fid_ep *ep, const void *buf,
					 size_t len, fi_addr_t dest_addr,
					 uint64_t tag)
{
	return _ep_inject(ep, buf, len, 0, dest_addr, FI_TAGGED, tag);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_tsenddata(struct fid_ep *ep, const void *buf,
					   size_t len, void *desc,
					   uint64_t data, fi_addr_t dest_addr,
					   uint64_t tag, void *context)
{
	return _ep_senddata(ep, buf, len, desc, data, dest_addr, context,
			FI_TAGGED, tag);
}

/**
 * Injects data into the data buffer and returns immediately.
 *
 * @param[in] ep	the endpoint we are sending data from
 * @param[in] buf	the data to send
 * @param[in] len	the length of buf
 * @param[in] data	remote CQ data to transfer with the data from buf
 * @param[in] dest_addr	the desitnation address for connectionless transfers
 * @param[in] tag	the tag associated with the message
 *
 * @return FI_SUCCESS	upon successfully writing to the destination
 * @return -FI_ERRNO	upon an error
 * @return -FI_ENOSYS	if this operation is not supported
 */
DIRECT_FN STATIC ssize_t sstmacx_ep_tinjectdata(struct fid_ep *ep, const void *buf,
					     size_t len, uint64_t data,
					     fi_addr_t dest_addr, uint64_t tag)
{
	return _ep_inject(ep, buf, len, data, dest_addr,
			  FI_TAGGED | FI_REMOTE_CQ_DATA, tag);
}

/*******************************************************************************
 * EP atomic API implementation.
 ******************************************************************************/

DIRECT_FN extern "C" int sstmacx_ep_atomic_valid(struct fid_ep *ep,
					  enum fi_datatype datatype,
					  enum fi_op op, size_t *count)
{
	if (count)
		*count = 1;

	return _sstmacx_atomic_cmd(datatype, op, SSTMACX_FAB_RQ_AMO) >= 0 ?
		0 : -FI_EOPNOTSUPP;
}

DIRECT_FN extern "C" int sstmacx_ep_fetch_atomic_valid(struct fid_ep *ep,
						enum fi_datatype datatype,
						enum fi_op op, size_t *count)
{
	if (count)
		*count = 1;

	return _sstmacx_atomic_cmd(datatype, op, SSTMACX_FAB_RQ_FAMO) >= 0 ?
		0 : -FI_EOPNOTSUPP;
}

DIRECT_FN extern "C" int sstmacx_ep_cmp_atomic_valid(struct fid_ep *ep,
					      enum fi_datatype datatype,
					      enum fi_op op, size_t *count)
{
	if (count)
		*count = 1;

	return _sstmacx_atomic_cmd(datatype, op, SSTMACX_FAB_RQ_CAMO) >= 0 ?
		0 : -FI_EOPNOTSUPP;
}

size_t
__sstmacx_fabric_ops_native_amo(struct fid_ep *ep, const void *buf, size_t count,
			 void *desc, void *result, void *result_desc,
				    fi_addr_t dest_addr,
				    uint64_t addr, uint64_t key,
				    enum fi_datatype datatype,
				    int req_type,
				    void *context)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	struct fi_msg_atomic msg;
	struct fi_ioc msg_iov;
	struct fi_rma_ioc rma_iov;
	struct fi_ioc result_iov;
	uint64_t flags;

	if (!ep)
		return -FI_EINVAL;
	if ((req_type < 0) || (req_type > SSTMACX_FAB_RQ_MAX_TYPES) ||
		(req_type >= SSTMACX_FAB_RQ_END_NON_NATIVE &&
		 req_type < SSTMACX_FAB_RQ_START_NATIVE))
		return -FI_EINVAL;

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	msg_iov.addr = (void *)buf;
	msg_iov.count = count;
	rma_iov.addr = addr;
	rma_iov.count = 1;
	rma_iov.key = key;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.addr = dest_addr;
	msg.rma_iov = &rma_iov;
	msg.datatype = datatype;
	msg.op = FI_ATOMIC_OP_LAST; /* not FI_ATOMIC_OP */
	msg.context = context;
	result_iov.addr = result;
	result_iov.count = 1;

	flags = sstmacx_ep->op_flags | SSTMACX_ATOMIC_WRITE_FLAGS_DEF;

	return _sstmacx_atomic(sstmacx_ep, req_type, &msg, NULL,
			    NULL, 0, &result_iov, &result_desc, 1, flags);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_atomic_write(struct fid_ep *ep, const void *buf, size_t count,
		     void *desc, fi_addr_t dest_addr, uint64_t addr,
		     uint64_t key, enum fi_datatype datatype, enum fi_op op,
		     void *context)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	struct fi_msg_atomic msg;
	struct fi_ioc msg_iov;
	struct fi_rma_ioc rma_iov;
	uint64_t flags;

	if (sstmacx_ep_atomic_valid(ep, datatype, op, NULL))
		return -FI_EOPNOTSUPP;

	if (!ep)
		return -FI_EINVAL;

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	msg_iov.addr = (void *)buf;
	msg_iov.count = count;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.addr = dest_addr;
	rma_iov.addr = addr;
	rma_iov.count = 1;
	rma_iov.key = key;
	msg.rma_iov = &rma_iov;
	msg.datatype = datatype;
	msg.op = op;
	msg.context = context;

	flags = sstmacx_ep->op_flags | SSTMACX_ATOMIC_WRITE_FLAGS_DEF;

	return _sstmacx_atomic(sstmacx_ep, SSTMACX_FAB_RQ_AMO, &msg,
			    NULL, NULL, 0, NULL, NULL, 0, flags);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_atomic_writev(struct fid_ep *ep, const struct fi_ioc *iov, void **desc,
		      size_t count, fi_addr_t dest_addr, uint64_t addr,
		      uint64_t key, enum fi_datatype datatype, enum fi_op op,
		      void *context)
{
	if (!iov || count > 1) {
		return -FI_EINVAL;
	}

	return sstmacx_ep_atomic_write(ep, iov[0].addr, iov[0].count,
				    desc ? desc[0] : NULL,
				    dest_addr, addr, key, datatype, op,
				    context);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_atomic_writemsg(struct fid_ep *ep, const struct fi_msg_atomic *msg,
			uint64_t flags)
{
	struct sstmacx_fid_ep *sstmacx_ep;

	if (sstmacx_ep_atomic_valid(ep, msg->datatype, msg->op, NULL))
		return -FI_EOPNOTSUPP;

	if (!ep)
		return -FI_EINVAL;

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	flags = (flags & SSTMACX_ATOMICMSG_FLAGS) | SSTMACX_ATOMIC_WRITE_FLAGS_DEF;

	return _sstmacx_atomic(sstmacx_ep, SSTMACX_FAB_RQ_AMO, msg,
			    NULL, NULL, 0, NULL, NULL, 0, flags);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_atomic_inject(struct fid_ep *ep, const void *buf, size_t count,
		      fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		      enum fi_datatype datatype, enum fi_op op)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	struct fi_msg_atomic msg;
	struct fi_ioc msg_iov;
	struct fi_rma_ioc rma_iov;
	uint64_t flags;

	if (sstmacx_ep_atomic_valid(ep, datatype, op, NULL))
		return -FI_EOPNOTSUPP;

	if (!ep)
		return -FI_EINVAL;

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	msg_iov.addr = (void *)buf;
	msg_iov.count = count;
	msg.msg_iov = &msg_iov;
	msg.desc = NULL;
	msg.iov_count = 1;
	msg.addr = dest_addr;
	rma_iov.addr = addr;
	rma_iov.count = 1;
	rma_iov.key = key;
	msg.rma_iov = &rma_iov;
	msg.datatype = datatype;
	msg.op = op;

	flags = sstmacx_ep->op_flags | FI_INJECT | SSTMACX_SUPPRESS_COMPLETION |
			SSTMACX_ATOMIC_WRITE_FLAGS_DEF;

	return _sstmacx_atomic(sstmacx_ep, SSTMACX_FAB_RQ_AMO, &msg,
			    NULL, NULL, 0, NULL, NULL, 0, flags);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_atomic_readwrite(struct fid_ep *ep, const void *buf, size_t count,
			 void *desc, void *result, void *result_desc,
			 fi_addr_t dest_addr, uint64_t addr, uint64_t key,
			 enum fi_datatype datatype, enum fi_op op,
			 void *context)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	struct fi_msg_atomic msg;
	struct fi_ioc msg_iov;
	struct fi_rma_ioc rma_iov;
	struct fi_ioc result_iov;
	uint64_t flags;

	if (sstmacx_ep_fetch_atomic_valid(ep, datatype, op, NULL))
		return -FI_EOPNOTSUPP;

	if (!ep)
		return -FI_EINVAL;

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	msg_iov.addr = (void *)buf;
	msg_iov.count = count;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.addr = dest_addr;
	rma_iov.addr = addr;
	rma_iov.count = 1;
	rma_iov.key = key;
	msg.rma_iov = &rma_iov;
	msg.datatype = datatype;
	msg.op = op;
	msg.context = context;
	result_iov.addr = result;
	result_iov.count = 1;

	flags = sstmacx_ep->op_flags | SSTMACX_ATOMIC_READ_FLAGS_DEF;

	return _sstmacx_atomic(sstmacx_ep, SSTMACX_FAB_RQ_FAMO, &msg,
			    NULL, NULL, 0,
			    &result_iov, &result_desc, 1,
			    flags);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_atomic_readwritev(struct fid_ep *ep, const struct fi_ioc *iov,
			  void **desc, size_t count, struct fi_ioc *resultv,
			  void **result_desc, size_t result_count,
			  fi_addr_t dest_addr, uint64_t addr, uint64_t key,
			  enum fi_datatype datatype, enum fi_op op,
			  void *context)
{
	if (!iov || count > 1 || !resultv)
		return -FI_EINVAL;

	return sstmacx_ep_atomic_readwrite(ep, iov[0].addr, iov[0].count,
					desc ? desc[0] : NULL,
					resultv[0].addr,
					result_desc ? result_desc[0] : NULL,
					dest_addr, addr, key, datatype, op,
					context);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_atomic_readwritemsg(struct fid_ep *ep, const struct fi_msg_atomic *msg,
			    struct fi_ioc *resultv, void **result_desc,
			    size_t result_count, uint64_t flags)
{
	struct sstmacx_fid_ep *sstmacx_ep;

	if (sstmacx_ep_fetch_atomic_valid(ep, msg->datatype, msg->op, NULL))
		return -FI_EOPNOTSUPP;

	if (!ep)
		return -FI_EINVAL;

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	flags = (flags & SSTMACX_FATOMICMSG_FLAGS) | SSTMACX_ATOMIC_READ_FLAGS_DEF;

	return _sstmacx_atomic(sstmacx_ep, SSTMACX_FAB_RQ_FAMO, msg,
			    NULL, NULL, 0,
			    resultv, result_desc, result_count,
			    flags);
}

DIRECT_FN STATIC ssize_t
sstmacx_ep_atomic_compwrite(struct fid_ep *ep, const void *buf, size_t count,
			 void *desc, const void *compare, void *compare_desc,
			 void *result, void *result_desc, fi_addr_t dest_addr,
			 uint64_t addr, uint64_t key, enum fi_datatype datatype,
			 enum fi_op op, void *context)
{
	struct sstmacx_fid_ep *sstmacx_ep;
	struct fi_msg_atomic msg;
	struct fi_ioc msg_iov;
	struct fi_rma_ioc rma_iov;
	struct fi_ioc result_iov;
	struct fi_ioc compare_iov;
	uint64_t flags;

	if (sstmacx_ep_cmp_atomic_valid(ep, datatype, op, NULL))
		return -FI_EOPNOTSUPP;

	if (!ep)
		return -FI_EINVAL;

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	msg_iov.addr = (void *)buf;
	msg_iov.count = count;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.addr = dest_addr;
	rma_iov.addr = addr;
	rma_iov.count = 1;
	rma_iov.key = key;
	msg.rma_iov = &rma_iov;
	msg.datatype = datatype;
	msg.op = op;
	msg.context = context;
	result_iov.addr = result;
	result_iov.count = 1;
	compare_iov.addr = (void *)compare;
	compare_iov.count = 1;

	flags = sstmacx_ep->op_flags | SSTMACX_ATOMIC_READ_FLAGS_DEF;

	return _sstmacx_atomic(sstmacx_ep, SSTMACX_FAB_RQ_CAMO, &msg,
			    &compare_iov, &compare_desc, 1,
			    &result_iov, &result_desc, 1,
			    flags);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_atomic_compwritev(struct fid_ep *ep,
						   const struct fi_ioc *iov,
						   void **desc,
						   size_t count,
						   const struct fi_ioc *comparev,
						   void **compare_desc,
						   size_t compare_count,
						   struct fi_ioc *resultv,
						   void **result_desc,
						   size_t result_count,
						   fi_addr_t dest_addr,
						   uint64_t addr, uint64_t key,
						   enum fi_datatype datatype,
						   enum fi_op op,
						   void *context)
{
	if (!iov || count > 1 || !resultv || !comparev)
		return -FI_EINVAL;

	return sstmacx_ep_atomic_compwrite(ep, iov[0].addr, iov[0].count,
					desc ? desc[0] : NULL,
					comparev[0].addr,
					compare_desc ? compare_desc[0] : NULL,
					resultv[0].addr,
					result_desc ? result_desc[0] : NULL,
					dest_addr, addr, key, datatype, op,
					context);
}

DIRECT_FN STATIC ssize_t sstmacx_ep_atomic_compwritemsg(struct fid_ep *ep,
						     const struct fi_msg_atomic *msg,
						     const struct fi_ioc *comparev,
						     void **compare_desc,
						     size_t compare_count,
						     struct fi_ioc *resultv,
						     void **result_desc,
						     size_t result_count,
						     uint64_t flags)
{
	struct sstmacx_fid_ep *sstmacx_ep;

	if (sstmacx_ep_cmp_atomic_valid(ep, msg->datatype, msg->op, NULL))
		return -FI_EOPNOTSUPP;

	if (!ep)
		return -FI_EINVAL;

	sstmacx_ep = container_of(ep, struct sstmacx_fid_ep, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(sstmacx_ep->type));

	flags = (flags & SSTMACX_CATOMICMSG_FLAGS) | SSTMACX_ATOMIC_READ_FLAGS_DEF;

	return _sstmacx_atomic(sstmacx_ep, SSTMACX_FAB_RQ_CAMO, msg,
			    comparev, compare_desc, compare_count,
			    resultv, result_desc, result_count,
			    flags);
}

/*******************************************************************************
 * Base EP API function implementations.
 ******************************************************************************/

DIRECT_FN STATIC extern "C" int sstmacx_ep_control(fid_t fid, int command, void *arg)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_ep *ep;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	ep = container_of(fid, struct sstmacx_fid_ep, ep_fid);

	switch (command) {
	/*
	 * for FI_EP_RDM/DGRAM, enable the cm_nic associated
	 * with this ep.
	 */
	case FI_ENABLE:

		if (SSTMACX_EP_RDM_DGM(ep->type)) {
			if ((ep->send_cq && ep->tx_enabled)) {
				ret = -FI_EOPBADSTATE;
				goto err;
			}
			if ((ep->recv_cq && ep->rx_enabled)) {
				ret = -FI_EOPBADSTATE;
				goto err;
			}
			ret = _sstmacx_vc_cm_init(ep->cm_nic);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
				     "_sstmacx_vc_cm_nic_init call returned %d\n",
					ret);
				goto err;
			}
			ret = _sstmacx_cm_nic_enable(ep->cm_nic);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
				     "_sstmacx_cm_nic_enable call returned %d\n",
					ret);
				goto err;
			}
		}

		ret = _sstmacx_ep_tx_enable(ep);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
			     "_sstmacx_ep_tx_enable call returned %d\n",
				ret);
			goto err;
		}

		ret = _sstmacx_ep_rx_enable(ep);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
			     "_sstmacx_ep_rx_enable call returned %d\n",
				ret);
			goto err;
		}

		ret = _sstmacx_ep_int_tx_pool_init(ep);
		break;

	case FI_GETOPSFLAG:
	case FI_SETOPSFLAG:
	case FI_ALIAS:
	default:
		return -FI_ENOSYS;
	}

err:
	return ret;
}

static int __destruct_tag_storages(struct sstmacx_fid_ep *ep)
{
	int ret;

	SSTMACX_INFO(FI_LOG_EP_CTRL, "destroying tag storage\n");

	ret = _sstmacx_tag_storage_destroy(&ep->unexp_recv_queue);
	if (ret)
		return ret;

	ret = _sstmacx_tag_storage_destroy(&ep->posted_recv_queue);
	if (ret)
		return ret;

	ret = _sstmacx_tag_storage_destroy(&ep->tagged_unexp_recv_queue);
	if (ret)
		return ret;

	ret = _sstmacx_tag_storage_destroy(&ep->tagged_posted_recv_queue);

	return ret;
}

static void __ep_destruct(void *obj)
{
	int ret;
	struct sstmacx_fid_domain *domain;
	struct sstmacx_fid_av *av;
	sstmacx_ht_key_t *key_ptr;
	struct sstmacx_fid_ep *ep = (struct sstmacx_fid_ep *) obj;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (ep->type == FI_EP_MSG) {
		if (SSTMACX_EP_CONNECTED(ep)) {
			assert(ep->vc);
			ret = _sstmacx_vc_destroy(ep->vc);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "_sstmacx_vc_destroy returned %s\n",
					  fi_strerror(-ret));
			}
		}
	} else if (ep->av) {
		/* Remove EP from CM NIC lookup list. */
		key_ptr = (sstmacx_ht_key_t *)&ep->src_addr.sstmacx_addr;
		ret =  _sstmacx_ht_remove(ep->cm_nic->addr_to_ep_ht,
				       *key_ptr);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "_sstmacx_ht_remove returned %s\n",
				  fi_strerror(-ret));
		}

		/* Destroy EP VC storage. */
		ret = __sstmacx_ep_fini_vc(ep);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "_sstmacx_ht_remove returned %s\n",
				  fi_strerror(-ret));
		}
	}

	if (ep->eq) {
		_sstmacx_eq_poll_obj_rem(ep->eq, &ep->ep_fid.fid);
		_sstmacx_ref_put(ep->eq);
	}

	if (ep->send_cq) {
		_sstmacx_cq_poll_obj_rem(ep->send_cq, ep->nic,
				      _sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cq_poll_obj_rem(ep->send_cq, ep->cm_nic,
					      _sstmacx_cm_nic_progress);
		_sstmacx_ref_put(ep->send_cq);
	}

	if (ep->recv_cq) {
		_sstmacx_cq_poll_obj_rem(ep->recv_cq, ep->nic,
				       _sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cq_poll_obj_rem(ep->recv_cq, ep->cm_nic,
					      _sstmacx_cm_nic_progress);
		_sstmacx_ref_put(ep->recv_cq);
	}

	if (ep->send_cntr) {
		_sstmacx_cntr_poll_obj_rem(ep->send_cntr, ep->nic,
					_sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cntr_poll_obj_rem(ep->send_cntr, ep->cm_nic,
						_sstmacx_cm_nic_progress);
		_sstmacx_ref_put(ep->send_cntr);
	}

	if (ep->recv_cntr) {
		_sstmacx_cntr_poll_obj_rem(ep->recv_cntr, ep->nic,
					_sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cntr_poll_obj_rem(ep->recv_cntr, ep->cm_nic,
						_sstmacx_cm_nic_progress);
		_sstmacx_ref_put(ep->recv_cntr);
	}

	if (ep->write_cntr) {
		_sstmacx_cntr_poll_obj_rem(ep->write_cntr, ep->nic,
					_sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cntr_poll_obj_rem(ep->write_cntr, ep->cm_nic,
						_sstmacx_cm_nic_progress);
		_sstmacx_ref_put(ep->write_cntr);
	}

	if (ep->read_cntr) {
		_sstmacx_cntr_poll_obj_rem(ep->read_cntr, ep->nic,
					_sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cntr_poll_obj_rem(ep->read_cntr, ep->cm_nic,
						_sstmacx_cm_nic_progress);
		_sstmacx_ref_put(ep->read_cntr);
	}

	if (ep->rwrite_cntr) {
		_sstmacx_cntr_poll_obj_rem(ep->rwrite_cntr, ep->nic,
					_sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cntr_poll_obj_rem(ep->rwrite_cntr, ep->cm_nic,
						_sstmacx_cm_nic_progress);
		_sstmacx_ref_put(ep->rwrite_cntr);
	}

	if (ep->rread_cntr) {
		_sstmacx_cntr_poll_obj_rem(ep->rread_cntr, ep->nic,
					_sstmacx_nic_progress);
		if (ep->cm_nic) /* No CM NIC for MSG EPs */
			_sstmacx_cntr_poll_obj_rem(ep->rread_cntr, ep->cm_nic,
						_sstmacx_cm_nic_progress);
		_sstmacx_ref_put(ep->rread_cntr);
	}

	if (ep->stx_ctx)
		_sstmacx_ref_put(ep->stx_ctx);

	if (ep->xpmem_hndl) {
		ret = _sstmacx_xpmem_handle_destroy(ep->xpmem_hndl);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "_sstmacx_xpmem_handle_destroy returned %s\n",
				  fi_strerror(-ret));
	}

	domain = ep->domain;
	assert(domain != NULL);
	_sstmacx_ref_put(domain);

	av = ep->av;
	if (av != NULL)
		_sstmacx_ref_put(av);

	if (ep->nic) {
		ret = _sstmacx_nic_free(ep->nic);
		if (ret != FI_SUCCESS)
			SSTMACX_FATAL(FI_LOG_EP_CTRL,
				   "_sstmacx_nic_free failed: %d\n");
	}

	if (ep->cm_nic) {
		ret = _sstmacx_cm_nic_free(ep->cm_nic);
		if (ret != FI_SUCCESS)
			SSTMACX_FATAL(FI_LOG_EP_CTRL,
				   "_sstmacx_cm_nic_free failed: %d\n");
	}

	__destruct_tag_storages(ep);

	/*
	 * Free fab_reqs
	 */

	__fr_freelist_destroy(ep);
	_sstmacx_ep_int_tx_pool_fini(ep);

	fi_freeinfo(ep->info);

	free(ep);
}

extern "C" int sstmacx_ep_close(fid_t fid)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_ep *ep;
	int references_held;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	ep = container_of(fid, struct sstmacx_fid_ep, ep_fid.fid);

	references_held = _sstmacx_ref_put(ep);
	if (references_held)
		SSTMACX_INFO(FI_LOG_EP_CTRL, "failed to fully close ep due "
			  "to lingering references. references=%i ep=%p\n",
			  references_held, ep);

	return ret;
}

DIRECT_FN extern "C" int sstmacx_ep_bind(fid_t fid, struct fid *bfid, uint64_t flags)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_ep  *ep;
	struct sstmacx_fid_eq *eq;
	struct sstmacx_fid_av  *av;
	struct sstmacx_fid_cq  *cq;
	struct sstmacx_fid_stx *stx;
	struct sstmacx_fid_cntr *cntr;
	struct sstmacx_fid_trx *trx_priv;
	struct sstmacx_nic_attr nic_attr = {0};

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	switch (fid->fclass) {
	case FI_CLASS_TX_CTX:
	case FI_CLASS_RX_CTX:
		trx_priv = container_of(fid, struct sstmacx_fid_trx, ep_fid);
		ep = trx_priv->ep;
		break;
	default:
		ep = container_of(fid, struct sstmacx_fid_ep, ep_fid.fid);
	}

	ret = ofi_ep_bind_valid(&sstmacx_prov, bfid, flags);
	if (ret)
		return ret;

	/*
	 * Per fi_endpoint man page, can't bind an object
	 * to an ep after its been enabled.
	 * For scalable endpoints, the rx/tx contexts are bound to the same
	 * sstmacx_ep so we allow enabling of the tx before binding the rx and
	 * vice versa.
	 */
	switch (fid->fclass) {
	case FI_CLASS_TX_CTX:
		if (ep->send_cq && ep->tx_enabled) {
			return -FI_EOPBADSTATE;
		}
		break;
	case FI_CLASS_RX_CTX:
		if (ep->recv_cq && ep->rx_enabled) {
			return -FI_EOPBADSTATE;
		}
		break;
	default:
		if ((ep->send_cq && ep->tx_enabled) ||
			(ep->recv_cq && ep->rx_enabled)) {
			return -FI_EOPBADSTATE;
		}
	}

	switch (bfid->fclass) {
	case FI_CLASS_EQ:
		eq = container_of(bfid, struct sstmacx_fid_eq, eq_fid.fid);
		if (ep->domain->fabric != eq->fabric) {
			ret = -FI_EINVAL;
			break;
		}

		if (ep->eq) {
			ret = -FI_EINVAL;
			break;
		}

		ep->eq = eq;
		_sstmacx_eq_poll_obj_add(eq, &ep->ep_fid.fid);
		_sstmacx_ref_get(eq);

		SSTMACX_DEBUG(FI_LOG_EP_CTRL, "Bound EQ to EP: %p, %p\n", eq, ep);
		break;
	case FI_CLASS_CQ:
		cq = container_of(bfid, struct sstmacx_fid_cq, cq_fid.fid);
		if (ep->domain != cq->domain) {
			ret = -FI_EINVAL;
			break;
		}
		if (flags & FI_TRANSMIT) {
			/* don't allow rebinding */
			if (ep->send_cq) {
				ret = -FI_EINVAL;
				break;
			}

			ep->send_cq = cq;
			if (flags & FI_SELECTIVE_COMPLETION) {
				ep->send_selective_completion = 1;
			}

			_sstmacx_ref_get(cq);
		}
		if (flags & FI_RECV) {
			/* don't allow rebinding */
			if (ep->recv_cq) {
				ret = -FI_EINVAL;
				break;
			}

			ep->recv_cq = cq;
			if (flags & FI_SELECTIVE_COMPLETION) {
				ep->recv_selective_completion = 1;
			}

			_sstmacx_ref_get(cq);
		}
		break;
	case FI_CLASS_AV:
		av = container_of(bfid, struct sstmacx_fid_av, av_fid.fid);
		if (ep->domain != av->domain) {
			ret = -FI_EINVAL;
			break;
		}
		ep->av = av;
		_sstmacx_ep_init_vc(ep);
		_sstmacx_ref_get(ep->av);
		break;
	case FI_CLASS_CNTR:
		cntr = container_of(bfid, struct sstmacx_fid_cntr, cntr_fid.fid);
		if (ep->domain != cntr->domain) {
			ret = -FI_EINVAL;
			break;
		}

		if (flags & FI_SEND) {
			/* don't allow rebinding */
			if (ep->send_cntr) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "cannot rebind send counter (%p)\n",
					  cntr);
				ret = -FI_EINVAL;
				break;
			}
			ep->send_cntr = cntr;
			_sstmacx_ref_get(cntr);
		}

		if (flags & FI_RECV) {
			/* don't allow rebinding */
			if (ep->recv_cntr) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "cannot rebind recv counter (%p)\n",
					  cntr);
				ret = -FI_EINVAL;
				break;
			}
			ep->recv_cntr = cntr;
			_sstmacx_ref_get(cntr);
		}

		if (flags & FI_WRITE) {
			/* don't allow rebinding */
			if (ep->write_cntr) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "cannot rebind write counter (%p)\n",
					  cntr);
				ret = -FI_EINVAL;
				break;
			}
			ep->write_cntr = cntr;
			_sstmacx_ref_get(cntr);
		}

		if (flags & FI_READ) {
			/* don't allow rebinding */
			if (ep->read_cntr) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "cannot rebind read counter (%p)\n",
					  cntr);
				ret = -FI_EINVAL;
				break;
			}
			ep->read_cntr = cntr;
			_sstmacx_ref_get(cntr);
		}

		if (flags & FI_REMOTE_WRITE) {
			/* don't allow rebinding */
			if (ep->rwrite_cntr) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "cannot rebind rwrite counter (%p)\n",
					  cntr);
				ret = -FI_EINVAL;
				break;
			}
			ep->rwrite_cntr = cntr;
			_sstmacx_ref_get(cntr);
		}

		if (flags & FI_REMOTE_READ) {
			/* don't allow rebinding */
			if (ep->rread_cntr) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "cannot rebind rread counter (%p)\n",
					  cntr);
				ret = -FI_EINVAL;
				break;
			}
			ep->rread_cntr = cntr;
			_sstmacx_ref_get(cntr);
		}

		break;

	case FI_CLASS_STX_CTX:
		stx = container_of(bfid, struct sstmacx_fid_stx, stx_fid.fid);
		if (ep->domain != stx->domain) {
			ret = -FI_EINVAL;
			break;
		}

		/*
		 * can only bind an STX to an ep opened with
		 * FI_SHARED_CONTEXT ep_attr->tx_ctx_cnt and also
		 * if a nic has not been previously bound
		 */

		if (ep->shared_tx == false || ep->nic) {
			ret =  -FI_EOPBADSTATE;
			break;
		}

		/*
		 * we force allocation of a nic to make semantics
		 * match the intent fi_endpoint man page, provide
		 * a TX context (aka sstmacx nic) that can be shared
		 * explicitly amongst endpoints
		 */
		if (stx->auth_key && ep->auth_key != stx->auth_key) {
			ret = -FI_EINVAL;
			break;
		}

		if (!stx->nic) {
			nic_attr.must_alloc = true;
			nic_attr.auth_key = ep->auth_key;
			ret = sstmacx_nic_alloc(ep->domain, &nic_attr,
				&stx->nic);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					 "_sstmacx_nic_alloc call returned %d\n",
					ret);
					break;
			}
			stx->auth_key = nic_attr.auth_key;
		}

		ep->stx_ctx = stx;
		_sstmacx_ref_get(ep->stx_ctx);

		ep->nic = stx->nic;
		if (ep->nic->smsg_callbacks == NULL)
			ep->nic->smsg_callbacks = sstmacx_ep_smsg_callbacks;
		_sstmacx_ref_get(ep->nic);
		break;

	case FI_CLASS_MR:/*TODO: got to figure this one out */
	default:
		ret = -FI_ENOSYS;
		break;
	}

	return ret;
}

static void sstmacx_ep_caps(struct sstmacx_fid_ep *ep_priv, uint64_t caps)
{
	if (ofi_recv_allowed(caps & ~FI_TAGGED))
		ep_priv->ep_ops.msg_recv_allowed = 1;

	if (ofi_send_allowed(caps & ~FI_TAGGED))
		ep_priv->ep_ops.msg_send_allowed = 1;

	if (ofi_recv_allowed(caps & ~FI_MSG))
		ep_priv->ep_ops.tagged_recv_allowed = 1;

	if (ofi_send_allowed(caps & ~FI_MSG))
		ep_priv->ep_ops.tagged_send_allowed = 1;

}

static int __init_tag_storages(struct sstmacx_fid_ep *ep, int tag_type,
			       int use_addrs)
{
	int tsret;
	struct sstmacx_tag_storage_attr untagged_attr = {
			.type = tag_type,
			.use_src_addr_matching = use_addrs,
	};
	struct sstmacx_tag_storage_attr tagged_attr = {
			.type = tag_type,
			.use_src_addr_matching = use_addrs,
	};

	SSTMACX_INFO(FI_LOG_EP_CTRL, "initializing tag storage, tag_type=%d\n",
			tag_type);

	/* init untagged storages */
	tsret = _sstmacx_posted_tag_storage_init(
			&ep->posted_recv_queue, &untagged_attr);
	if (tsret)
		return tsret;

	tsret = _sstmacx_unexpected_tag_storage_init(
			&ep->unexp_recv_queue, &untagged_attr);
	if (tsret)
		return tsret;

	/* init tagged storages */
	tsret = _sstmacx_posted_tag_storage_init(
			&ep->tagged_posted_recv_queue, &tagged_attr);
	if (tsret)
		return tsret;

	tsret = _sstmacx_unexpected_tag_storage_init(
			&ep->tagged_unexp_recv_queue, &tagged_attr);

	return tsret;
}

static extern "C" int _sstmacx_ep_nic_init(struct sstmacx_fid_domain *domain,
			     struct fi_info *info,
			     struct sstmacx_fid_ep *ep)
{
	int ret = FI_SUCCESS;
	uint32_t cdm_id = SSTMACX_CREATE_CDM_ID;
	struct sstmacx_ep_name *name;
	struct sstmacx_nic_attr nic_attr = {0};

	if (ep->type == FI_EP_MSG) {
		if (ep->shared_tx == false) {
			nic_attr.auth_key = ep->auth_key;

			ret = sstmacx_nic_alloc(domain, &nic_attr,
				&ep->nic);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "_sstmacx_nic_alloc call returned %d\n",
					  ret);
			}
		}
		return ret;
	}

	name = (struct sstmacx_ep_name *)info->src_addr;
	if (name && name->name_type == SSTMACX_EPN_TYPE_BOUND) {
		/* Endpoint was bound to a specific source address.  Create a
		 * new CM NIC to listen on this address. */
		ret = _sstmacx_cm_nic_alloc(domain, info, name->sstmacx_addr.cdm_id,
				ep->auth_key, &ep->cm_nic);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "_sstmacx_cm_nic_alloc returned %s\n",
				  fi_strerror(-ret));
			return ret;
		}

		ep->src_addr = ep->cm_nic->my_name;

		/*
		 * if this endpoint is not going to use a shared TX
		 * aka sstmacx_nic, link its nic with the one being
		 * used for the cm_nic to reduce pressure on underlying
		* hardware resources.
		*/
		if (ep->shared_tx == false) {
			ep->nic = ep->cm_nic->nic;
			_sstmacx_ref_get(ep->nic);

			SSTMACX_INFO(FI_LOG_EP_CTRL,
				  "Allocated new NIC for bound EP: %p (ID:%d)\n",
				  ep->src_addr.sstmacx_addr.cdm_id);
			}
	} else {
		fastlock_acquire(&domain->cm_nic_lock);

		/* Allocate a domain CM NIC, if needed. */
		if (domain->cm_nic == NULL) {
			ret = _sstmacx_cm_nic_create_cdm_id(domain, &cdm_id);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "sstmacx_cm_nic_create_cdm_id returned %s\n",
					  fi_strerror(-ret));
				return ret;
			}

			ret = _sstmacx_cm_nic_alloc(domain, info, cdm_id,
					ep->auth_key, &domain->cm_nic);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "_sstmacx_cm_nic_alloc returned %s\n",
					  fi_strerror(-ret));
				fastlock_release(&domain->cm_nic_lock);
				return ret;
			}

			/* Use the newly allocated domain CM NIC for data
			 * movement on this EP if not using STX. */
			ep->cm_nic = domain->cm_nic;
			if (ep->shared_tx == false) {
				ep->nic = ep->cm_nic->nic;
				_sstmacx_ref_get(ep->nic);
			}

			SSTMACX_INFO(FI_LOG_EP_CTRL,
				  "Allocated new NIC for EP: %p (ID:%d)\n",
				  ep->src_addr.sstmacx_addr.cdm_id);
		} else {
			/* Re-use the existing domain CM NIC. */
			ep->cm_nic = domain->cm_nic;
			_sstmacx_ref_get(ep->cm_nic);

			if (ep->shared_tx == false) {
				nic_attr.auth_key = ep->auth_key;

				/* Allocate a new NIC for data
				   movement on this EP. */
				ret = sstmacx_nic_alloc(domain,
					&nic_attr, &ep->nic);
				if (ret != FI_SUCCESS) {
					SSTMACX_WARN(FI_LOG_EP_CTRL,
					    "_sstmacx_nic_alloc call returned %d\n",
					     ret);
					fastlock_release(&domain->cm_nic_lock);
					return ret;
				}

				SSTMACX_INFO(FI_LOG_EP_CTRL,
					  "Allocated new NIC for xfers: %p (ID:%d)\n",
					  ep->src_addr.sstmacx_addr.cdm_id);
			}
		}

		fastlock_release(&domain->cm_nic_lock);

		ep->src_addr.sstmacx_addr.device_addr =
			ep->cm_nic->my_name.sstmacx_addr.device_addr;
		ep->src_addr.cm_nic_cdm_id =
			ep->cm_nic->my_name.sstmacx_addr.cdm_id;

		ret = _sstmacx_cm_nic_create_cdm_id(domain, &cdm_id);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "sstmacx_cm_nic_create_cdm_id returned %s\n",
				  fi_strerror(-ret));
			if(ep->nic != NULL)
				_sstmacx_ref_put(ep->nic);
			return ret;
		}
		ep->src_addr.sstmacx_addr.cdm_id = cdm_id;
	}

	return FI_SUCCESS;
}

static extern "C" int _sstmacx_ep_msg_open(struct sstmacx_fid_domain *domain,
			     struct fi_info *info,
			     struct sstmacx_fid_ep *ep)
{
	ep->ep_fid.cm = &sstmacx_ep_msg_ops_cm;
	ep->conn_fd = -1;
	ep->conn_state = SSTMACX_EP_UNCONNECTED;

	return FI_SUCCESS;
}

static extern "C" int _sstmacx_ep_unconn_open(struct sstmacx_fid_domain *domain,
				struct fi_info *info,
				struct sstmacx_fid_ep *ep)
{
	int ret;
	sstmacx_ht_key_t *key_ptr;

	key_ptr = (sstmacx_ht_key_t *)&ep->src_addr.sstmacx_addr;
	ret = _sstmacx_ht_insert(ep->cm_nic->addr_to_ep_ht,
			      *key_ptr, ep);
	if ((ret != FI_SUCCESS) && (ret != -FI_ENOSPC)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "__sstmacx_ht_insert returned %d\n",
			  ret);
		return ret;
	}

	/* Unconnected endpoints use a limited set of CM ops. */
	ep->ep_fid.cm = &sstmacx_ep_ops_cm;

	return FI_SUCCESS;
}

DIRECT_FN extern "C" int sstmacx_ep_open(struct fid_domain *domain, struct fi_info *info,
			   struct fid_ep **ep, void *context)
{
	int ret = FI_SUCCESS;
	int err_ret;
	struct sstmacx_fid_domain *domain_priv;
	struct sstmacx_fid_ep *ep_priv;
	struct sstmacx_auth_key *auth_key;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if ((domain == NULL) || (info == NULL) || (ep == NULL) ||
	    (info->ep_attr == NULL))
		return -FI_EINVAL;

	domain_priv = container_of(domain, struct sstmacx_fid_domain, domain_fid);

	if (FI_VERSION_LT(domain_priv->fabric->fab_fid.api_version,
		FI_VERSION(1, 5)) &&
		(info->ep_attr->auth_key || info->ep_attr->auth_key_size))
		return -FI_EINVAL;

	if (info->ep_attr->auth_key_size) {
		auth_key = SSTMACX_GET_AUTH_KEY(info->ep_attr->auth_key,
				info->ep_attr->auth_key_size,
				domain_priv->using_vmdh);
		if (!auth_key)
			return -FI_EINVAL;
	} else {
		auth_key = domain_priv->auth_key;
		assert(auth_key);
	}

	ep_priv = calloc(1, sizeof *ep_priv);
	if (!ep_priv)
		return -FI_ENOMEM;

	/* Set up libfabric fid data. */
	ep_priv->ep_fid.fid.fclass = FI_CLASS_EP;
	ep_priv->ep_fid.fid.context = context;
	ep_priv->ep_fid.fid.ops = &sstmacx_ep_fi_ops;
	ep_priv->ep_fid.ops = &sstmacx_ep_ops;
	ep_priv->ep_fid.msg = &sstmacx_ep_msg_ops;
	ep_priv->ep_fid.rma = &sstmacx_ep_rma_ops;
	ep_priv->ep_fid.tagged = &sstmacx_ep_tagged_ops;
	ep_priv->ep_fid.atomic = &sstmacx_ep_atomic_ops;

	/* Init SSTMACX data. */
	ep_priv->auth_key = auth_key;
	ep_priv->type = info->ep_attr->type;
	ep_priv->domain = domain_priv;
	_sstmacx_ref_init(&ep_priv->ref_cnt, 1, __ep_destruct);
	ep_priv->min_multi_recv = SSTMACX_OPT_MIN_MULTI_RECV_DEFAULT;
	fastlock_init(&ep_priv->vc_lock);
	ep_priv->progress_fn = NULL;
	ep_priv->rx_progress_fn = NULL;
	ep_priv->tx_enabled = false;
	ep_priv->rx_enabled = false;
	ep_priv->requires_lock = (domain_priv->thread_model !=
				  FI_THREAD_COMPLETION);
	ep_priv->info = fi_dupinfo(info);
	ep_priv->info->addr_format = info->addr_format;

	SSTMACX_DEBUG(FI_LOG_DEBUG, "ep(%p) is using addr_format(%s)\n", ep_priv,
		  ep_priv->info->addr_format == FI_ADDR_STR ? "FI_ADDR_STR" :
		  "FI_ADDR_SSTMAC");

	if (info->src_addr) {
		memcpy(&ep_priv->src_addr, info->src_addr,
		       sizeof(struct sstmacx_ep_name));
	}

	if (info->dest_addr) {
		memcpy(&ep_priv->dest_addr, info->dest_addr,
		       sizeof(struct sstmacx_ep_name));
	}

	ret = __init_tag_storages(ep_priv, SSTMACX_TAG_LIST,
				  ep_priv->type == FI_EP_MSG ? 0 : 1);
	if (ret)
		goto err_tag_init;

	ret = __fr_freelist_init(ep_priv);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			 "Error allocating sstmacx_fab_req freelist (%s)",
			 fi_strerror(-ret));
		goto err_fl_init;
	}

	ep_priv->shared_tx = (info->ep_attr->tx_ctx_cnt == FI_SHARED_CONTEXT) ?
				true : false;
	/*
	 * try out XPMEM
	 */
	ret = _sstmacx_xpmem_handle_create(domain_priv,
					&ep_priv->xpmem_hndl);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "_sstmacx_xpmem_handl_create returned %s\n",
			  fi_strerror(-ret));
	}

	/* Initialize caps, modes, permissions, behaviors. */
	ep_priv->caps = info->caps & SSTMACX_EP_CAPS_FULL;

	if (ep_priv->info->tx_attr)
		ep_priv->op_flags = ep_priv->info->tx_attr->op_flags;
	if (ep_priv->info->rx_attr)
		ep_priv->op_flags |= ep_priv->info->rx_attr->op_flags;
	ep_priv->op_flags &= SSTMACX_EP_OP_FLAGS;

	sstmacx_ep_caps(ep_priv, ep_priv->caps);

	ret = _sstmacx_ep_nic_init(domain_priv, ep_priv->info, ep_priv);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "_sstmacx_ep_nic_init returned %d\n",
			  ret);
		goto err_nic_init;
	}

	/* Do EP type specific initialization. */
	switch (ep_priv->type) {
	case FI_EP_DGRAM:
	case FI_EP_RDM:
		ret = _sstmacx_ep_unconn_open(domain_priv, ep_priv->info, ep_priv);
		if (ret != FI_SUCCESS) {
			SSTMACX_INFO(FI_LOG_EP_CTRL,
				  "_sstmacx_ep_unconn_open() failed, err: %d\n",
				  ret);
			goto err_type_init;
		}
		break;
	case FI_EP_MSG:
		ret = _sstmacx_ep_msg_open(domain_priv, ep_priv->info, ep_priv);
		if (ret != FI_SUCCESS) {
			SSTMACX_INFO(FI_LOG_EP_CTRL,
				  "_sstmacx_ep_msg_open() failed, err: %d\n",
				  ret);
			goto err_type_init;
		}
		break;
	default:
		ret = -FI_EINVAL;
		goto err_type_init;
	}

	_sstmacx_ref_get(ep_priv->domain);

	*ep = &ep_priv->ep_fid;

	return ret;

err_type_init:
	if (ep_priv->nic)
		_sstmacx_nic_free(ep_priv->nic);
	_sstmacx_cm_nic_free(ep_priv->cm_nic);
err_nic_init:
	if (ep_priv->xpmem_hndl) {
		err_ret = _sstmacx_xpmem_handle_destroy(ep_priv->xpmem_hndl);
		if (err_ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "_sstmacx_xpmem_handle_destroy returned %s\n",
				  fi_strerror(-err_ret));
		}
	}

	__fr_freelist_destroy(ep_priv);
err_fl_init:
	__destruct_tag_storages(ep_priv);
err_tag_init:
	free(ep_priv);

	return ret;
}

extern "C" int _sstmacx_ep_alloc(struct fid_domain *domain, struct fi_info *info,
			   struct sstmacx_ep_attr *attr,
			   struct fid_ep **ep, void *context)
{
	int ret = FI_SUCCESS;
	int err_ret;
	struct sstmacx_fid_domain *domain_priv;
	struct sstmacx_fid_ep *ep_priv;
	sstmacx_ht_key_t *key_ptr;
	struct sstmacx_auth_key *auth_key;
	uint32_t cdm_id;
	bool free_list_inited = false;
	struct sstmacx_nic_attr nic_attr = {0};

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if ((domain == NULL) || (info == NULL) || (ep == NULL) ||
	    (info->ep_attr == NULL))
		return -FI_EINVAL;

	domain_priv = container_of(domain, struct sstmacx_fid_domain, domain_fid);

	if (info->ep_attr->auth_key_size) {
		auth_key = SSTMACX_GET_AUTH_KEY(info->ep_attr->auth_key,
				info->ep_attr->auth_key_size,
				domain_priv->using_vmdh);
		if (!auth_key)
			return -FI_EINVAL;
	} else {
		auth_key = domain_priv->auth_key;
		assert(auth_key);
	}

	ep_priv = calloc(1, sizeof(*ep_priv));
	if (!ep_priv)
		return -FI_ENOMEM;

	ep_priv->auth_key = auth_key;

	ep_priv->requires_lock = (domain_priv->thread_model !=
				FI_THREAD_COMPLETION);

	ep_priv->ep_fid.fid.fclass = FI_CLASS_EP;
	ep_priv->ep_fid.fid.context = context;

	ep_priv->ep_fid.fid.ops = &sstmacx_ep_fi_ops;
	ep_priv->ep_fid.ops = &sstmacx_ep_ops;
	ep_priv->domain = domain_priv;
	ep_priv->type = info->ep_attr->type;
	ep_priv->info = fi_dupinfo(info);

	_sstmacx_ref_init(&ep_priv->ref_cnt, 1, __ep_destruct);

	ep_priv->caps = info->caps & SSTMACX_EP_CAPS_FULL;

	if (info->tx_attr)
		ep_priv->op_flags = info->tx_attr->op_flags;
	if (info->rx_attr)
		ep_priv->op_flags |= info->rx_attr->op_flags;
	ep_priv->op_flags &= SSTMACX_EP_OP_FLAGS;

	ep_priv->min_multi_recv = SSTMACX_OPT_MIN_MULTI_RECV_DEFAULT;

	if (attr && attr->msg_ops)
		ep_priv->ep_fid.msg = attr->msg_ops;
	else
		ep_priv->ep_fid.msg = &sstmacx_ep_msg_ops;

	if (attr && attr->rma_ops)
		ep_priv->ep_fid.rma = attr->rma_ops;
	else
		ep_priv->ep_fid.rma = &sstmacx_ep_rma_ops;

	if (attr && attr->tagged_ops)
		ep_priv->ep_fid.tagged = attr->tagged_ops;
	else
		ep_priv->ep_fid.tagged = &sstmacx_ep_tagged_ops;

	if (attr && attr->atomic_ops)
		ep_priv->ep_fid.atomic = attr->atomic_ops;
	else
		ep_priv->ep_fid.atomic = &sstmacx_ep_atomic_ops;

	if (attr && attr->cm_ops)
		ep_priv->ep_fid.cm = attr->cm_ops;
	else
		ep_priv->ep_fid.cm = &sstmacx_ep_ops_cm;

	sstmacx_ep_caps(ep_priv, ep_priv->caps);

	ret = __init_tag_storages(ep_priv, SSTMACX_TAG_LIST, 1);
	if (ret) {
		goto err;
	}

	ret = __fr_freelist_init(ep_priv);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			 "Error allocating sstmacx_fab_req freelist (%s)",
			 fi_strerror(-ret));
		goto err;
	} else
		free_list_inited = true;

	/*
	 * try out XPMEM
	 */

	ret = _sstmacx_xpmem_handle_create(domain_priv,
					&ep_priv->xpmem_hndl);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "xpmem_handl_create returned %s\n",
			  fi_strerror(-ret));
	}

	if (attr && attr->cm_nic) {
		ep_priv->cm_nic = attr->cm_nic;
		_sstmacx_ref_get(ep_priv->cm_nic);
	} else {

		/*
		 * if a cm_nic has not yet been allocated for this
		 * domain, do it now.  Reuse the embedded sstmacx_nic
		 * in the cm_nic as the nic for this endpoint
		 * to reduce demand on Aries hw resources.
		 */

		fastlock_acquire(&domain_priv->cm_nic_lock);
		if (domain_priv->cm_nic == NULL) {
			ret = _sstmacx_cm_nic_alloc(domain_priv, info,
						 cdm_id,
						 ep_priv->auth_key,
						 &domain_priv->cm_nic);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					"_sstmacx_cm_nic_alloc returned %s\n",
					fi_strerror(-ret));
				fastlock_release(
					 &domain_priv->cm_nic_lock);
				goto err;
			}
			ep_priv->cm_nic = domain_priv->cm_nic;
			ep_priv->nic = ep_priv->cm_nic->nic;
			_sstmacx_ref_get(ep_priv->nic);
		} else {
			ep_priv->cm_nic = domain_priv->cm_nic;
			_sstmacx_ref_get(ep_priv->cm_nic);
		}

		fastlock_release(&domain_priv->cm_nic_lock);

	}

	ep_priv->src_addr.sstmacx_addr.device_addr =
		ep_priv->cm_nic->my_name.sstmacx_addr.device_addr;
	ep_priv->src_addr.cm_nic_cdm_id =
		ep_priv->cm_nic->my_name.sstmacx_addr.cdm_id;

	if (attr && attr->use_cdm_id) {
		cdm_id = attr->cdm_id;
	} else {
		ret = _sstmacx_cm_nic_create_cdm_id(domain_priv, &cdm_id);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				    "sstmacx_cm_nic_create_cdm_id returned %s\n",
				     fi_strerror(-ret));
			goto err;
		}
	}
	ep_priv->src_addr.sstmacx_addr.cdm_id = cdm_id;

	key_ptr = (sstmacx_ht_key_t *)&ep_priv->src_addr.sstmacx_addr;
	ret = _sstmacx_ht_insert(ep_priv->cm_nic->addr_to_ep_ht,
			      *key_ptr,
			      ep_priv);
	if ((ret != FI_SUCCESS) && (ret != -FI_ENOSPC)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "__sstmacx_ht_insert returned %d\n",
			  ret);
		goto err;
	}

	fastlock_init(&ep_priv->vc_lock);

	ep_priv->progress_fn = NULL;
	ep_priv->rx_progress_fn = NULL;
	ep_priv->tx_enabled = false;
	ep_priv->rx_enabled = false;

	if (attr && attr->nic) {
		ep_priv->nic = attr->nic;
	} else {
		assert(ep_priv->nic == NULL);
		nic_attr.auth_key = ep_priv->auth_key;

		ret = sstmacx_nic_alloc(domain_priv, &nic_attr,
			&ep_priv->nic);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				    "sstmacx_nic_alloc call returned %d\n", ret);
			goto err;
		}
		if (!(attr && attr->cm_nic)) {
			ep_priv->cm_nic = domain_priv->cm_nic;
		}
		_sstmacx_ref_get(ep_priv->nic);
	}

	/*
	 * if smsg callbacks not present hook them up now
	 */

	if (ep_priv->nic->smsg_callbacks == NULL)
		ep_priv->nic->smsg_callbacks = sstmacx_ep_smsg_callbacks;

	_sstmacx_ref_get(ep_priv->domain);
	*ep = &ep_priv->ep_fid;
	return ret;

err:
	if (ep_priv->xpmem_hndl) {
		err_ret = _sstmacx_xpmem_handle_destroy(ep_priv->xpmem_hndl);
		if (err_ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
					"_sstmacx_xpmem_handle_destroy returned %s\n",
					fi_strerror(-err_ret));
		}
	}

	err_ret = __destruct_tag_storages(ep_priv);
	if (err_ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
				"__destruct_tag_stroages returned %s\n",
				fi_strerror(-err_ret));
	}

	if (free_list_inited == true)
		__fr_freelist_destroy(ep_priv);

	if (ep_priv->cm_nic != NULL) {
		err_ret = _sstmacx_cm_nic_free(ep_priv->cm_nic);
		if (err_ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
					"_sstmacx_cm_nic_free returned %s\n",
					fi_strerror(-err_ret));
		}
	}

	if (ep_priv->nic != NULL) {
		err_ret = _sstmacx_nic_free(ep_priv->nic);
		if (err_ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
					"_sstmacx_nic_free returned %s\n",
					fi_strerror(-err_ret));
		}
	}

	free(ep_priv);
	return ret;
}

static int __match_context(struct dlist_entry *item, const void *arg)
{
	struct sstmacx_fab_req *req;

	req = container_of(item, struct sstmacx_fab_req, dlist);

	return req->user_context == arg;
}

static inline struct sstmacx_fab_req *__find_tx_req(
		struct sstmacx_fid_ep *ep,
		void *context)
{
	struct sstmacx_fab_req *req = NULL;
	struct dlist_entry *entry;
	struct sstmacx_vc *vc;

	SSTMACX_DEBUG(FI_LOG_EP_CTRL, "searching VCs for the correct context to"
		   " cancel, context=%p", context);

	COND_ACQUIRE(ep->requires_lock, &ep->vc_lock);

	if (ep->av->type == FI_AV_TABLE) {
		SSTMACX_VECTOR_ITERATOR(ep->vc_table, iter);

		while ((vc = (struct sstmacx_vc *)
				_sstmacx_vec_iterator_next(&iter))) {
			entry = dlist_remove_first_match(&vc->tx_queue,
							 __match_context,
							 context);

			if (entry) {
				req = container_of(entry,
						   struct sstmacx_fab_req,
						   dlist);
				break;
			}
		}
	} else {
		SSTMACX_HASHTABLE_ITERATOR(ep->vc_ht, iter);

		while ((vc = _sstmacx_ht_iterator_next(&iter))) {
			entry = dlist_remove_first_match(&vc->tx_queue,
							 __match_context,
							 context);

			if (entry) {
				req = container_of(entry,
						   struct sstmacx_fab_req,
						   dlist);
				break;
			}
		}
	}

	COND_RELEASE(ep->requires_lock, &ep->vc_lock);

	return req;
}

static inline struct sstmacx_fab_req *__find_rx_req(
		struct sstmacx_fid_ep *ep,
		void *context)
{
	struct sstmacx_fab_req *req = NULL;

	COND_ACQUIRE(ep->requires_lock, &ep->vc_lock);
	req = _sstmacx_remove_req_by_context(&ep->posted_recv_queue, context);
	if (req) {
		COND_RELEASE(ep->requires_lock, &ep->vc_lock);
		return req;
	}

	req = _sstmacx_remove_req_by_context(&ep->tagged_posted_recv_queue,
			context);
	COND_RELEASE(ep->requires_lock, &ep->vc_lock);

	return req;
}

DIRECT_FN STATIC ssize_t sstmacx_ep_cancel(fid_t fid, void *context)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_ep *ep;
	struct sstmacx_fab_req *req;
	struct sstmacx_fid_cq *err_cq = NULL;
	struct sstmacx_fid_cntr *err_cntr = NULL;
	void *addr;
	uint64_t tag, flags;
	size_t len;
	int is_send = 0;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	ep = container_of(fid, struct sstmacx_fid_ep, ep_fid.fid);

	if (!ep->domain)
		return -FI_EDOMAIN;

	/* without context, we will have to find a request that matches
	 * a recv or send request. Try the send requests first.
	 */
	SSTMACX_INFO(FI_LOG_EP_CTRL, "looking for event to cancel\n");

	req = __find_tx_req(ep, context);
	if (!req) {
		req = __find_rx_req(ep, context);
		if (req) {
			err_cq = ep->recv_cq;
			err_cntr = ep->recv_cntr;
		}
	} else {
		is_send = 1;
		err_cq = ep->send_cq;
		err_cntr = ep->send_cntr;
	}
	SSTMACX_INFO(FI_LOG_EP_CTRL, "finished searching\n");

	if (!req)
		return -FI_ENOENT;

	if (err_cq) {
		/* add canceled event */
		if (!(req->type == SSTMACX_FAB_RQ_RDMA_READ ||
		      req->type == SSTMACX_FAB_RQ_RDMA_WRITE)) {
			if (!is_send) {
				addr = (void *) req->msg.recv_info[0].recv_addr;
				len = req->msg.cum_recv_len;
			} else {
				addr = (void *) req->msg.send_info[0].send_addr;
				len = req->msg.cum_send_len;
			}
			tag = req->msg.tag;
		} else {
			/* rma information */
			addr = (void *) req->rma.loc_addr;
			len = req->rma.len;
			tag = 0;
		}
		flags = req->flags;

		_sstmacx_cq_add_error(err_cq, context, flags, len, addr, 0 /* data */,
				tag, len, FI_ECANCELED, FI_ECANCELED, 0, 0);

	}

	if (err_cntr) {
		/* signal increase in cntr errs */
		_sstmacx_cntr_inc_err(err_cntr);
	}

	if (req->flags & FI_LOCAL_MR) {
		fi_close(&req->amo.loc_md->mr_fid.fid);
		req->flags &= ~FI_LOCAL_MR;
	}

	_sstmacx_fr_free(ep, req);

	return ret;
}

ssize_t sstmacx_cancel(fid_t fid, void *context)
{
	ssize_t ret;
	struct sstmacx_fid_ep *ep;
	struct sstmacx_fid_trx *trx_ep;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	switch (fid->fclass) {
	case FI_CLASS_EP:
		ret = sstmacx_ep_cancel(fid, context);
		break;

	case FI_CLASS_RX_CTX:
	case FI_CLASS_TX_CTX:
		trx_ep = container_of(fid, struct sstmacx_fid_trx, ep_fid);
		ep = trx_ep->ep;
		ret = sstmacx_ep_cancel(&ep->ep_fid.fid, context);
		break;
	/* not supported yet */
	case FI_CLASS_SRX_CTX:
	case FI_CLASS_STX_CTX:
		return -FI_ENOENT;

	default:
		SSTMACX_WARN(FI_LOG_EP_CTRL, "Invalid fid type\n");
		return -FI_EINVAL;
	}

	return ret;
}

static int
__sstmacx_ep_ops_get_val(struct fid *fid, ep_ops_val_t t, void *val)
{
	struct sstmacx_fid_ep *ep;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	assert(val);

	if (fid->fclass != FI_CLASS_EP) {
		SSTMACX_WARN(FI_LOG_DOMAIN, "Invalid ep\n");
		return -FI_EINVAL;
	}

	ep = container_of(fid, struct sstmacx_fid_ep, ep_fid.fid);

	switch (t) {
	case SSTMAC_HASH_TAG_IMPL:
		*(uint32_t *)val = (ep->use_tag_hlist) ? 1 : 0;
		break;

	default:
		SSTMACX_WARN(FI_LOG_DOMAIN, ("Invalid dom_ops_val\n"));
		return -FI_EINVAL;
	}

	return FI_SUCCESS;
}

static int
__sstmacx_ep_ops_set_val(struct fid *fid, ep_ops_val_t t, void *val)
{
	struct sstmacx_fid_ep *ep;
	int v;
	int ret;
	int tag_type;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	assert(val);

	if (fid->fclass != FI_CLASS_EP) {
		SSTMACX_WARN(FI_LOG_DOMAIN, "Invalid ep\n");
		return -FI_EINVAL;
	}

	ep = container_of(fid, struct sstmacx_fid_ep, ep_fid.fid);
	switch (t) {
	case SSTMAC_HASH_TAG_IMPL:
		if (ep->tx_enabled || ep->rx_enabled) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
					"EP enabled, cannot modify tag matcher\n");
			return -FI_EINVAL;
		}

		v = *(uint32_t *) val;
		if ((v && !(ep->use_tag_hlist)) ||
				(!v && (ep->use_tag_hlist))) {
			ret = __destruct_tag_storages(ep);
			if (ret) {
				SSTMACX_FATAL(FI_LOG_EP_CTRL,
						"failed to destroy existing tag storage\n");
			}

			tag_type = (v) ? SSTMACX_TAG_HLIST : SSTMACX_TAG_LIST;

			ret = __init_tag_storages(ep, tag_type, 1);
			if (ret)
				return ret;

			ep->use_tag_hlist = v;
		}
		break;
	default:
		SSTMACX_WARN(FI_LOG_DOMAIN, ("Invalid dom_ops_val\n"));
		return -FI_EINVAL;
	}

	return FI_SUCCESS;
}

static struct fi_sstmac_ops_ep sstmacx_ops_ep = {
	.set_val = __sstmacx_ep_ops_set_val,
	.get_val = __sstmacx_ep_ops_get_val,
	.native_amo = __sstmacx_fabric_ops_native_amo
};

static int
sstmacx_ep_ops_open(struct fid *fid, const char *ops_name, uint64_t flags,
		     void **ops, void *context)
{
	int ret = FI_SUCCESS;

	if (strcmp(ops_name, FI_SSTMAC_EP_OPS_1) == 0)
		*ops = &sstmacx_ops_ep;
	else
		ret = -FI_EINVAL;

	return ret;
}

DIRECT_FN STATIC extern "C" int sstmacx_ep_getopt(fid_t fid, int level, int optname,
				    void *optval, size_t *optlen)
{
	struct sstmacx_fid_ep *sstmacx_ep;

	sstmacx_ep = container_of(fid, struct sstmacx_fid_ep, ep_fid.fid);

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		*(size_t *)optval = sstmacx_ep->min_multi_recv;
		*optlen = sizeof(size_t);
		break;
	case FI_OPT_CM_DATA_SIZE:
		*(size_t *)optval = SSTMACX_CM_DATA_MAX_SIZE;
		*optlen = sizeof(size_t);
		break;
	default:
		return -FI_ENOPROTOOPT;
	}

	return 0;
}

extern "C" int sstmacx_getopt(fid_t fid, int level, int optname,
				    void *optval, size_t *optlen)
{
        ssize_t ret;
        struct sstmacx_fid_ep *ep;
        struct sstmacx_fid_trx *trx_ep;

        SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (!fid || !optval || !optlen)
		return -FI_EINVAL;
	else if (level != FI_OPT_ENDPOINT)
		return -FI_ENOPROTOOPT;

        switch (fid->fclass) {
        case FI_CLASS_EP:
                ret = sstmacx_ep_getopt(fid, level, optname, optval, optlen);
                break;

        case FI_CLASS_RX_CTX:
        case FI_CLASS_TX_CTX:
                trx_ep = container_of(fid, struct sstmacx_fid_trx, ep_fid);
                ep = trx_ep->ep;
                ret = sstmacx_ep_getopt(&ep->ep_fid.fid, level, optname, optval,
                        optlen);
                break;
        /* not supported yet */
        case FI_CLASS_SRX_CTX:
        case FI_CLASS_STX_CTX:
                return -FI_ENOENT;

        default:
                SSTMACX_WARN(FI_LOG_EP_CTRL, "Invalid fid type\n");
                return -FI_EINVAL;
        }

        return ret;
}

DIRECT_FN STATIC extern "C" int sstmacx_ep_setopt(fid_t fid, int level, int optname,
				    const void *optval, size_t optlen)
{
	struct sstmacx_fid_ep *sstmacx_ep;

	sstmacx_ep = container_of(fid, struct sstmacx_fid_ep, ep_fid.fid);

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		if (optlen != sizeof(size_t))
			return -FI_EINVAL;
		/*
		 * see https://github.com/ofi-cray/libfabric-cray/issues/1120
		 */
		if (*(size_t *)optval == 0UL)
			return -FI_EINVAL;
		sstmacx_ep->min_multi_recv = *(size_t *)optval;
		break;
	default:
		return -FI_ENOPROTOOPT;
	}

	return 0;
}

extern "C" int sstmacx_setopt(fid_t fid, int level, int optname,
				    const void *optval, size_t optlen)
{
        ssize_t ret;
        struct sstmacx_fid_ep *ep;
        struct sstmacx_fid_trx *trx_ep;

        SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (!fid || !optval)
		return -FI_EINVAL;
	else if (level != FI_OPT_ENDPOINT)
		return -FI_ENOPROTOOPT;

        switch (fid->fclass) {
        case FI_CLASS_EP:
                ret = sstmacx_ep_setopt(fid, level, optname, optval, optlen);
                break;

        case FI_CLASS_RX_CTX:
        case FI_CLASS_TX_CTX:
                trx_ep = container_of(fid, struct sstmacx_fid_trx, ep_fid);
                ep = trx_ep->ep;
                ret = sstmacx_ep_setopt(&ep->ep_fid.fid, level, optname, optval,
                        optlen);
                break;
        /* not supported yet */
        case FI_CLASS_SRX_CTX:
        case FI_CLASS_STX_CTX:
                return -FI_ENOENT;

        default:
                SSTMACX_WARN(FI_LOG_EP_CTRL, "Invalid fid type\n");
                return -FI_EINVAL;
        }

        return ret;
}

DIRECT_FN STATIC ssize_t sstmacx_ep_rx_size_left(struct fid_ep *ep)
{
	if (!ep) {
		return -FI_EINVAL;
	}

	struct sstmacx_fid_ep *ep_priv = container_of(ep,
						   struct sstmacx_fid_ep,
						   ep_fid);

	/* A little arbitrary... */
	if (ep_priv->int_tx_pool.enabled == false) {
		return -FI_EOPBADSTATE;
	}

	switch (ep->fid.fclass) {
	case FI_CLASS_EP:
		break;
	case FI_CLASS_RX_CTX:
	case FI_CLASS_SRX_CTX:
		break;
	default:
		SSTMACX_INFO(FI_LOG_EP_CTRL, "Invalid EP type\n");
		return -FI_EINVAL;
	}

	/* We can queue RXs indefinitely, so just return the default size. */
	return SSTMACX_RX_SIZE_DEFAULT;
}

DIRECT_FN STATIC ssize_t sstmacx_ep_tx_size_left(struct fid_ep *ep)
{
	if (!ep) {
		return -FI_EINVAL;
	}

	struct sstmacx_fid_ep *ep_priv = container_of(ep,
						   struct sstmacx_fid_ep,
						   ep_fid);

	/* A little arbitrary... */
	if (ep_priv->int_tx_pool.enabled == false) {
		return -FI_EOPBADSTATE;
	}

	switch (ep->fid.fclass) {
	case FI_CLASS_EP:
		break;
	case FI_CLASS_TX_CTX:
		break;
	default:
		SSTMACX_INFO(FI_LOG_EP_CTRL, "Invalid EP type\n");
		return -FI_EINVAL;
	}

	/* We can queue TXs indefinitely, so just return the default size. */
	return SSTMACX_TX_SIZE_DEFAULT;
}

__attribute__((unused))
DIRECT_FN STATIC extern "C" int sstmacx_tx_context(struct fid_ep *ep, int index,
				     struct fi_tx_attr *attr,
				     struct fid_ep **tx_ep, void *context)
{
	return -FI_ENOSYS;
}

__attribute__((unused))
DIRECT_FN STATIC extern "C" int sstmacx_rx_context(struct fid_ep *ep, int index,
				     struct fi_rx_attr *attr,
				     struct fid_ep **rx_ep, void *context)
{
	return -FI_ENOSYS;
}

/*******************************************************************************
 * FI_OPS_* data structures.
 ******************************************************************************/

static struct fi_ops sstmacx_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sstmacx_ep_close,
	.bind = sstmacx_ep_bind,
	.control = sstmacx_ep_control,
	.ops_open = sstmacx_ep_ops_open,
};

static struct fi_ops_ep sstmacx_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = sstmacx_cancel,
	.getopt = sstmacx_getopt,
	.setopt = sstmacx_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = sstmacx_ep_rx_size_left,
	.tx_size_left = sstmacx_ep_tx_size_left,
};

static struct fi_ops_msg sstmacx_ep_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = sstmacx_ep_recv,
	.recvv = sstmacx_ep_recvv,
	.recvmsg = sstmacx_ep_recvmsg,
	.send = sstmacx_ep_send,
	.sendv = sstmacx_ep_sendv,
	.sendmsg = sstmacx_ep_sendmsg,
	.inject = sstmacx_ep_msg_inject,
	.senddata = sstmacx_ep_senddata,
	.injectdata = sstmacx_ep_msg_injectdata,
};

static struct fi_ops_rma sstmacx_ep_rma_ops = {
	.size = sizeof(struct fi_ops_rma),
	.read = sstmacx_ep_read,
	.readv = sstmacx_ep_readv,
	.readmsg = sstmacx_ep_readmsg,
	.write = sstmacx_ep_write,
	.writev = sstmacx_ep_writev,
	.writemsg = sstmacx_ep_writemsg,
	.inject = sstmacx_ep_rma_inject,
	.writedata = sstmacx_ep_writedata,
	.injectdata = sstmacx_ep_rma_injectdata,
};

struct fi_ops_tagged sstmacx_ep_tagged_ops = {
	.size = sizeof(struct fi_ops_tagged),
	.recv = sstmacx_ep_trecv,
	.recvv = sstmacx_ep_trecvv,
	.recvmsg = sstmacx_ep_trecvmsg,
	.send = sstmacx_ep_tsend,
	.sendv = sstmacx_ep_tsendv,
	.sendmsg = sstmacx_ep_tsendmsg,
	.inject = sstmacx_ep_tinject,
	.senddata = sstmacx_ep_tsenddata,
	.injectdata = sstmacx_ep_tinjectdata,
};

struct fi_ops_atomic sstmacx_ep_atomic_ops = {
	.size = sizeof(struct fi_ops_atomic),
	.write = sstmacx_ep_atomic_write,
	.writev = sstmacx_ep_atomic_writev,
	.writemsg = sstmacx_ep_atomic_writemsg,
	.inject = sstmacx_ep_atomic_inject,
	.readwrite = sstmacx_ep_atomic_readwrite,
	.readwritev = sstmacx_ep_atomic_readwritev,
	.readwritemsg = sstmacx_ep_atomic_readwritemsg,
	.compwrite = sstmacx_ep_atomic_compwrite,
	.compwritev = sstmacx_ep_atomic_compwritev,
	.compwritemsg = sstmacx_ep_atomic_compwritemsg,
	.writevalid = sstmacx_ep_atomic_valid,
	.readwritevalid = sstmacx_ep_fetch_atomic_valid,
	.compwritevalid = sstmacx_ep_cmp_atomic_valid,
};

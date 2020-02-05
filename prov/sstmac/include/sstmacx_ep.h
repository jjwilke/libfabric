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

#ifndef _SSTMACX_EP_H_
#define _SSTMACX_EP_H_

#include "sstmacx.h"
#include "sstmacx_nic.h"

/* Default minimum multi receive buffer size. */
#define SSTMACX_OPT_MIN_MULTI_RECV_DEFAULT	64

/*
 * enum of tags used for SSTMAC_SmsgSendWTag
 * and callbacks at receive side to process
 * these messages
 */

enum {
	SSTMACX_SMSG_T_EGR_W_DATA = 10,
	SSTMACX_SMSG_T_EGR_W_DATA_ACK,
	SSTMACX_SMSG_T_EGR_GET,
	SSTMACX_SMSG_T_EGR_GET_ACK,
	SSTMACX_SMSG_T_RNDZV_RTS,
	SSTMACX_SMSG_T_RNDZV_RTR,
	SSTMACX_SMSG_T_RNDZV_COOKIE,
	SSTMACX_SMSG_T_RNDZV_SDONE,
	SSTMACX_SMSG_T_RNDZV_RDONE,
	SSTMACX_SMSG_T_RNDZV_START,
	SSTMACX_SMSG_T_RNDZV_FIN,
	SSTMACX_SMSG_T_RMA_DATA,
	SSTMACX_SMSG_T_AMO_CNTR,
	SSTMACX_SMSG_T_RNDZV_IOV_START
};

/**
 * Set of attributes that can be passed to the _sstmacx_alloc_ep
 *
 * @var cm_ops               pointer to connection management interface
 * @var msg_ops              pointer to message transfer interface
 * @var rma_ops              pointer to rma transfer interface
 * @var tagged_ops           pointer to tagged message transfer interface
 * @var atomic_ops           pointer to atomic interface
 * @var cm_nic               cm_nic associated with this EP
 * @var nic                  sstmacx nic associated with this EP
 * @var sstmac_cdm_modes        The mode bits sstmac_cdm_hndl was created with.
 * @var use_cdm_id           true if the cdm_id field should be used for
 *                           initializing underlying sstmac cdm, etc.
 * @var cdm_id               user supplied cmd_id to use for this endpoint
 */
struct sstmacx_ep_attr {
	struct fi_ops_cm *cm_ops;
	struct fi_ops_msg *msg_ops;
	struct fi_ops_rma *rma_ops;
	struct fi_ops_tagged *tagged_ops;
	struct fi_ops_atomic *atomic_ops;
	struct sstmacx_cm_nic *cm_nic;
	struct sstmacx_nic  *nic;
	bool use_cdm_id;
	uint32_t cdm_id;
};

extern smsg_completer_fn_t sstmacx_ep_smsg_completers[];
extern smsg_callback_fn_t sstmacx_ep_smsg_callbacks[];

/*
 * typedefs for function vectors used to steer send/receive/rma/amo requests,
 * i.e. fi_send, fi_recv, etc. to ep type specific methods
 */

typedef ssize_t (*send_func_t)(struct fid_ep *ep, const void *buf,
				size_t len, void *desc,
				fi_addr_t dest_addr, void *context);

typedef ssize_t (*sendv_func_t)(struct fid_ep *ep, const struct iovec *iov,
				void **desc, size_t count,
				fi_addr_t dest_addr, void *context);

typedef ssize_t (*sendmsg_func_t)(struct fid_ep *ep, const struct fi_msg *msg,
				   uint64_t flags);

typedef ssize_t (*msg_inject_func_t)(struct fid_ep *ep, const void *buf,
					size_t len, fi_addr_t dest_addr);

typedef ssize_t (*recv_func_t)(struct fid_ep *ep, const void *buf,
				size_t len, void *desc,
				fi_addr_t dest_addr, void *context);

typedef ssize_t (*recvv_func_t)(struct fid_ep *ep, const struct iovec *iov,
				 void **desc, size_t count,
				 fi_addr_t dest_addr, void *context);

typedef ssize_t (*recvmsg_func_t)(struct fid_ep *ep, const struct fi_msg *msg,
				  uint64_t flags);

typedef ssize_t (*tsend_func_t)(struct fid_ep *ep, const void *buf,
				 size_t len, void *desc,
				 fi_addr_t dest_addr, uint64_t tag,
				 void *context);

typedef ssize_t (*tsendv_func_t)(struct fid_ep *ep, const struct iovec *iov,
				  void **desc, size_t count,
				  fi_addr_t dest_addr, uint64_t tag,
				  void *context);

typedef ssize_t (*tsendmsg_func_t)(struct fid_ep *ep,
				    const struct fi_msg_tagged *msg,
				    uint64_t flags);

typedef ssize_t (*tinject_func_t)(struct fid_ep *ep,
				   const void *buf,
				   size_t len,
				   fi_addr_t dest_addr,
				   uint64_t flags);

typedef ssize_t (*trecv_func_t)(struct fid_ep *ep,
				 void *buf,
				 size_t len,
				 void *desc,
				 fi_addr_t src_addr,
				 uint64_t tag,
				 uint64_t ignore,
				 void *context);

typedef ssize_t (*trecvv_func_t)(struct fid_ep *ep,
				 const struct iovec *iov,
				 void **desc,
				 size_t count,
				 fi_addr_t src_addr,
				 uint64_t tag,
				 uint64_t ignore,
				 void *context);

typedef ssize_t (*trecvmsg_func_t)(struct fid_ep *ep,
				   const struct fi_msg_tagged *msg,
				   uint64_t flags);

/**
 * Internal function for growing tx buffer pool
 *
 * @param[in] ep	pointer to a EP
 */
int  _sstmacx_ep_int_tx_pool_grow(struct sstmacx_fid_ep *ep);

/**
 * Internal function for initializing tx buffer pool
 *
 * @param[in] ep	pointer to a EP
 */
int _sstmacx_ep_int_tx_pool_init(struct sstmacx_fid_ep *ep);


/*
 * inline functions
 */

static inline struct slist_entry
*_sstmacx_ep_get_int_tx_buf(struct sstmacx_fid_ep *ep)
{
	struct slist_entry *e;

	fastlock_acquire(&ep->int_tx_pool.lock);

	e = slist_remove_head(&ep->int_tx_pool.sl);

	fastlock_release(&ep->int_tx_pool.lock);

	if (e == NULL) {
		int ret;

		ret = _sstmacx_ep_int_tx_pool_grow(ep);
		if (ret != FI_SUCCESS)
			return NULL;

		fastlock_acquire(&ep->int_tx_pool.lock);
		e = slist_remove_head(&ep->int_tx_pool.sl);
		fastlock_release(&ep->int_tx_pool.lock);
	}

	return e;
}

static inline sstmac_mem_handle_t _sstmacx_ep_get_int_tx_mdh(void *e)
{
	return ((struct sstmacx_int_tx_buf *)e)->md->mem_hndl;
}

static inline void _sstmacx_ep_release_int_tx_buf(struct sstmacx_fid_ep *ep,
					       struct slist_entry *e)
{
	fastlock_acquire(&ep->int_tx_pool.lock);

	SSTMACX_DEBUG(FI_LOG_EP_DATA, "sl.head = %p, sl.tail = %p\n",
		   ep->int_tx_pool.sl.head, ep->int_tx_pool.sl.tail);

	slist_insert_head(e, &ep->int_tx_pool.sl);

	fastlock_release(&ep->int_tx_pool.lock);
}

static inline struct sstmacx_fab_req *
_sstmacx_fr_alloc(struct sstmacx_fid_ep *ep)
{
	struct dlist_entry *de = NULL;
	struct sstmacx_fab_req *fr = NULL;
	int ret = _sstmacx_fl_alloc(&de, &ep->fr_freelist);

	while (OFI_UNLIKELY(ret == -FI_EAGAIN))
		ret = _sstmacx_fl_alloc(&de, &ep->fr_freelist);

	if (ret == FI_SUCCESS) {
		fr = container_of(de, struct sstmacx_fab_req, dlist);
		fr->sstmacx_ep = ep;
		dlist_init(&fr->dlist);
		dlist_init(&fr->msg.tle.free);

		/* reset common fields */
		fr->tx_failures = 0;
		_sstmacx_ref_get(ep);
	}

	return fr;
}

static inline struct sstmacx_fab_req *
_sstmacx_fr_alloc_w_cb(struct sstmacx_fid_ep *ep, void (*cb)(void *))
{
	struct dlist_entry *de = NULL;
	struct sstmacx_fab_req *fr = NULL;
	int ret = _sstmacx_fl_alloc(&de, &ep->fr_freelist);

	while (OFI_UNLIKELY(ret == -FI_EAGAIN))
		ret = _sstmacx_fl_alloc(&de, &ep->fr_freelist);

	if (ret == FI_SUCCESS) {
		fr = container_of(de, struct sstmacx_fab_req, dlist);
		fr->sstmacx_ep = ep;
		fr->cb = cb;
		_sstmacx_ref_init(&fr->ref_cnt, 1, cb);
		dlist_init(&fr->dlist);
		dlist_init(&fr->msg.tle.free);

		/* reset common fields */
		fr->tx_failures = 0;
		_sstmacx_ref_get(ep);
	}

	return fr;
}

static inline void
_sstmacx_fr_free(struct sstmacx_fid_ep *ep, struct sstmacx_fab_req *fr)
{
	assert(fr->sstmacx_ep == ep);

	assert((fr->flags & FI_LOCAL_MR) == 0);

	if (fr->int_tx_buf_e != NULL) {
		_sstmacx_ep_release_int_tx_buf(ep, fr->int_tx_buf_e);
		fr->int_tx_buf_e = NULL;
		fr->int_tx_buf = NULL;
	}

	_sstmacx_fl_free(&fr->dlist, &ep->fr_freelist);
	_sstmacx_ref_put(ep);
}

static inline int
__msg_match_fab_req(struct dlist_entry *item, const void *arg)
{
	struct sstmacx_fab_req *req;
	const struct sstmacx_address *addr_ptr = arg;

	req = container_of(item, struct sstmacx_fab_req, dlist);

	return ((SSTMACX_ADDR_UNSPEC(*addr_ptr)) ||
				(SSTMACX_ADDR_EQUAL(req->addr, *addr_ptr)));
}

/*
 * EP related internal helper functions
 */

ssize_t _ep_recv(struct fid_ep *ep, void *buf, size_t len,
		 void *desc, fi_addr_t src_addr, void *context,
		 uint64_t flags, uint64_t tag, uint64_t ignore);
ssize_t _ep_recvv(struct fid_ep *ep, const struct iovec *iov,
		  void **desc, size_t count, fi_addr_t src_addr,
		  void *context, uint64_t flags, uint64_t tag,
		  uint64_t ignore);
ssize_t _ep_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
		    uint64_t flags, uint64_t tag,
		    uint64_t ignore);
ssize_t _ep_send(struct fid_ep *ep, const void *buf, size_t len,
		 void *desc, fi_addr_t dest_addr, void *context,
		 uint64_t flags, uint64_t tag);
ssize_t _ep_sendv(struct fid_ep *ep, const struct iovec *iov,
		  void **desc, size_t count, fi_addr_t dest_addr,
		  void *context, uint64_t flags, uint64_t tag);
ssize_t _ep_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
		    uint64_t flags, uint64_t tag);
ssize_t _ep_inject(struct fid_ep *ep, const void *buf,
		   size_t len, uint64_t data, fi_addr_t dest_addr,
		   uint64_t flags, uint64_t tag);
ssize_t _ep_senddata(struct fid_ep *ep, const void *buf,
		     size_t len, void *desc, uint64_t data,
		     fi_addr_t dest_addr, void *context,
		     uint64_t flags, uint64_t tag);

/**
 * Allocate a sstmacx ep struct
 *
 * @param[in] domain	the domain from which this EP is being created
 * @param[in] info	details about the domain endpoint to be opened
 * @param[in] attr	attributes to be used for allocating the EP
 * @param[out] ep	the endpoint to open
 * @param[in] context	the context associated with the endpoint
 *
 * @return FI_SUCCESS	upon successfully opening a passive endpoint
 * @return -FI_EINVAL	invalid input arguments supplied
 * @return -FI_ENOMEM	no memory to allocate EP struct
 */
int _sstmacx_ep_alloc(struct fid_domain *domain, struct fi_info *info,
			   struct sstmacx_ep_attr *attr,
			   struct fid_ep **ep, void *context);

int _sstmacx_ep_init_vc(struct sstmacx_fid_ep *ep_priv);

/**
 * Internal function for enabling ep tx resources
 *
 * @param[in] ep_priv	 pointer to a previously allocated EP
 */
int _sstmacx_ep_tx_enable(struct sstmacx_fid_ep *ep_priv);

/**
 * Internal function for enabling ep rx resources
 *
 * @param[in] ep_priv	 pointer to a previously allocated EP
 */
int _sstmacx_ep_rx_enable(struct sstmacx_fid_ep *ep_priv);

/*******************************************************************************
 * API Functions
 ******************************************************************************/
/**
 * Allocates a new passive endpoint.
 *
 * @param[in] fabric	the fabric
 * @param[in] info	details about the fabric endpoint to be opened
 * @param[in/out] pep	the passive endpoint to open
 * @param[in] context	the context associated with the endpoint
 *
 * @return FI_SUCCESS	upon successfully opening a passive endpoint
 * @return -FI_ERRNO	upon an error
 * @return -FI_ENOSYS	if this operation is not supported
 */
int sstmacx_pep_open(struct fid_fabric *fabric,
		  struct fi_info *info, struct fid_pep **pep,
		  void *context);

int sstmacx_scalable_ep_bind(fid_t fid, struct fid *bfid, uint64_t flags);

/**
 * Associates the passive endpoint with an event queue.
 *
 * @param[in] fid	the fabric or access domain
 * @param[in] bfid	the fabric identifier for the endpoint
 * @param[in] flags	flags to apply to the binding
 *
 * @return FI_SUCCESS	upon successfully binding a passive endpoint to an EQ
 * @return -FI_ERRNO	upon an error
 * @return -FI_ENOSYS	if this operation is not supported
 */
int sstmacx_pep_bind(fid_t fid, struct fid *bfid, uint64_t flags);

/**
 * Cancels a transaction posted to an endpoint, if possible.
 *
 * @param[in] fid	the endpoint
 * @param[in] context	context of the transaction to be canceled
 *
 * @return FI_SUCCESS	upon successfully canceling transaction
 * @return -FI_ENONT	no entry to cancel
 */
ssize_t sstmacx_cancel(fid_t fid, void *context);

/**
 * Get an endpoint option
 *
 * @param[in] fid       the endpoint
 * @param[in] level     the option level, must be FI_OPT_ENDPOINT
 * @param[in] optname   the option name
 * @param[out] optval   the value of the named option
 * @param[out] optlen   the width of the value in bytes
 *
 * @return FI_SUCCESS	upon successfully returning the value of the option
 * @return -FI_EINVAL   missing or invalid fid, optval, and/or optlen
 * @return -FI_ENOENT   unsupported context type
 * @return -FI_ENOPROTOOPT  unknown option level or name
 */

int sstmacx_getopt(fid_t fid, int level, int optname,
                                    void *optval, size_t *optlen);

/**
 * Set an endpoint option
 *
 * @param[in] fid       the endpoint
 * @param[in] level     the option level, must be FI_OPT_ENDPOINT
 * @param[in] optname   the option name
 * @param[out] optval   the value to set in the named option
 * @param[out] optlen   the width of the value in bytes
 *
 * @return FI_SUCCESS	upon successfully setting the value of the option
 * @return -FI_EINVAL   missing or invalid fid, optval, and/or optlen
 * @return -FI_ENOENT   unsupported context type
 * @return -FI_ENOPROTOOPT  unknown option level or name
 */

int sstmacx_setopt(fid_t fid, int level, int optname,
                                    const void *optval, size_t optlen);

DIRECT_FN int sstmacx_ep_atomic_valid(struct fid_ep *ep,
				   enum fi_datatype datatype,
				   enum fi_op op, size_t *count);

DIRECT_FN int sstmacx_ep_fetch_atomic_valid(struct fid_ep *ep,
					 enum fi_datatype datatype,
					 enum fi_op op, size_t *count);

DIRECT_FN int sstmacx_ep_cmp_atomic_valid(struct fid_ep *ep,
				       enum fi_datatype datatype,
				       enum fi_op op, size_t *count);
#endif /* _GN IX_EP_H_ */

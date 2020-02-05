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

/*
 * code for managing VC's
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sstmacx.h"
#include "sstmacx_vc.h"
#include "sstmacx_util.h"
#include "sstmacx_datagram.h"
#include "sstmacx_cm_nic.h"
#include "sstmacx_nic.h"
#include "sstmacx_ep.h"
#include "sstmacx_mbox_allocator.h"
#include "sstmacx_hashtable.h"
#include "sstmacx_av.h"
#include "sstmacx_trigger.h"
#include "sstmacx_vector.h"
#include "sstmacx_xpmem.h"
#include "sstmacx_cq.h"

/*
 * forward declarations and local struct defs.
 */

struct wq_hndl_conn_req {
	sstmac_smsg_attr_t src_smsg_attr;
	int src_vc_id;
	struct sstmacx_vc *vc;
	uint64_t src_vc_ptr;
	sstmac_mem_handle_t irq_mem_hndl;
	xpmem_segid_t peer_segid;
};

static int __sstmacx_vc_conn_ack_prog_fn(void *data, int *complete_ptr);
static int __sstmacx_vc_conn_ack_comp_fn(void *data);
static int __sstmacx_vc_push_tx_reqs(struct sstmacx_vc *vc);

static int __sstmacx_vc_work_schedule(struct sstmacx_vc *vc);
static extern "C" int _sstmacx_vc_sched_new_conn(struct sstmacx_vc *vc);

/*******************************************************************************
 * Helper functions
 ******************************************************************************/

/**
 * Set key to the given sstmacx_addr.
 *
 * NOTE: If struct sstmacx_address is ever bit packed or packed by
 * the compiler this assignment may not set key to the correct
 * bytes.
 */
static inline void __sstmacx_vc_set_ht_key(void *sstmacx_addr,
					sstmacx_ht_key_t *key)
{
	*key = *((sstmacx_ht_key_t *)sstmacx_addr);
}

static struct sstmacx_vc *_sstmacx_ep_vc_lookup(struct sstmacx_fid_ep *ep, uint64_t key)
{
	struct sstmacx_vc *vc = NULL;
	int ret;
	int i;

	assert(ep->av);


	for (i = 0; i < SSTMACX_ADDR_CACHE_SIZE; i++)
	{
		if (ep->addr_cache[i].addr == key && ep->addr_cache[i].vc != NULL)
			return ep->addr_cache[i].vc;
	}

	if (ep->av->type == FI_AV_TABLE) {
		ret = _sstmacx_vec_at(ep->vc_table, (void **)&vc, key);
		if (ret != FI_SUCCESS) {
			vc = NULL;
		}
	} else {
		vc = (struct sstmacx_vc *)_sstmacx_ht_lookup(ep->vc_ht, key);
	}

	if (vc) {
		ep->addr_cache[ep->last_cached].addr = key;
		ep->addr_cache[ep->last_cached].vc = vc;
		ep->last_cached = (ep->last_cached + 1) % 5;
	}

	return vc;
}

static extern "C" int _sstmacx_ep_vc_store(struct sstmacx_fid_ep *ep, struct sstmacx_vc *vc,
			     uint64_t key)
{
	int ret;

	assert(ep->av);

	if (ep->av->type == FI_AV_TABLE) {
		ret = _sstmacx_vec_insert_at(ep->vc_table, (void *)vc, key);
	} else {
		ret = _sstmacx_ht_insert(ep->vc_ht, key, vc);
	}

	return ret;
}

static int __sstmacx_vc_sstmacx_addr_equal(struct dlist_entry *item, const void *arg)
{
	struct sstmacx_vc *vc = dlist_entry(item, struct sstmacx_vc, list);

	return SSTMACX_ADDR_EQUAL(vc->peer_addr, *(struct sstmacx_address *)arg);
}

/* Find an unmapped VC that matches 'dest_addr' and map it into the EP's VC
 * look up table.
 *
 * Note: EP must be locked. */
static struct sstmacx_vc *__sstmacx_vc_lookup_unmapped(struct sstmacx_fid_ep *ep,
						 fi_addr_t dest_addr)
{
	struct sstmacx_av_addr_entry av_entry;
	struct dlist_entry *entry;
	struct sstmacx_vc *vc;
	int ret;

	/* Determine if the fi_addr now exists in the AV. */
	ret = _sstmacx_av_lookup(ep->av, dest_addr, &av_entry);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "_sstmacx_av_lookup for addr 0x%lx returned %s\n",
			  dest_addr, fi_strerror(-ret));
		return NULL;
	}

	/* Find a pre-existing, unmapped VC that matches the sstmacx_address
	 * mapped by dest_addr. */
	entry = dlist_remove_first_match(&ep->unmapped_vcs,
					 __sstmacx_vc_sstmacx_addr_equal,
					 (void *)&av_entry.sstmacx_addr);
	if (entry) {
		/* Found a matching, unmapped VC.  Map dest_addr to the VC in
		 * the EP's VC look up table. */
		vc = dlist_entry(entry, struct sstmacx_vc, list);
		SSTMACX_INFO(FI_LOG_EP_CTRL,
			  "Found unmapped VC: %p sstmacx_addr: 0x%lx fi_addr: 0x%lx\n",
			  vc, vc->peer_addr, vc->peer_fi_addr);

		ret = _sstmacx_ep_vc_store(ep, vc, dest_addr);
		if (OFI_UNLIKELY(ret != FI_SUCCESS)) {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_ep_vc_store returned %s\n",
				  fi_strerror(-ret));
			dlist_insert_tail(&vc->list, &ep->unmapped_vcs);
			return NULL;
		}

		return vc;
	}

	return NULL;
}

/**
 * Look up the vc by fi_addr_t, if it's found just return it,
 * otherwise allocate a new vc, insert it into the hashtable,
 * and vector for FI_AV_TABLE AV type, and start connection setup.
 *
 * assumptions: ep is non-null;
 * dest_addr is valid;
 * vc_ptr is non-null.
 *
 * Note: EP must be locked.
 */
static int __sstmacx_vc_get_vc_by_fi_addr(struct sstmacx_fid_ep *ep, fi_addr_t dest_addr,
				       struct sstmacx_vc **vc_ptr)
{
	struct sstmacx_fid_av *av;
	int ret = FI_SUCCESS;
	struct sstmacx_av_addr_entry av_entry;
	struct sstmacx_vc *vc;

	SSTMACX_DBG_TRACE(FI_LOG_EP_CTRL, "\n");

	SSTMACX_DEBUG(FI_LOG_EP_CTRL,
		   "ep->vc_table = %p, ep->vc_table->vector = %p\n",
		   ep->vc_table, ep->vc_table->vector);

	av = ep->av;
	if (OFI_UNLIKELY(av == NULL)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "av field NULL for ep %p\n", ep);
		return -FI_EINVAL;
	}

	/* Use FI address to lookup in EP VC table. */
	vc = _sstmacx_ep_vc_lookup(ep, dest_addr);
	if (vc) {
		*vc_ptr = vc;
		return FI_SUCCESS;
	}

	/* VC is not mapped yet.  We can receive a connection request from a
	 * remote peer before the target EP has bound to an AV or before the
	 * remote peer has had it's address inserted into the target EP's AV.
	 * Those requests will result in a connection as usual, but the VC will
	 * not be mapped into an EP's AV until the EP attempts to send to the
	 * remote peer.  Check the 'unmapped VC' list to see if such a VC
	 * exists and map it into the AV here. */
	vc = __sstmacx_vc_lookup_unmapped(ep, dest_addr);
	if (vc) {
		*vc_ptr = vc;
		return FI_SUCCESS;
	}

	/* No VC exists for the peer yet.  Look up full AV entry for the
	 * destination address. */
	ret = _sstmacx_av_lookup(av, dest_addr, &av_entry);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "_sstmacx_av_lookup for addr 0x%llx returned %s \n",
			  dest_addr, fi_strerror(-ret));
		goto err_w_lock;
	}

	/* Allocate new VC with AV entry. */
	ret = _sstmacx_vc_alloc(ep, &av_entry, &vc);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "_sstmacx_vc_alloc returned %s\n",
			  fi_strerror(-ret));
		goto err_w_lock;
	}

	/* Map new VC through the EP connection table. */
	ret = _sstmacx_ep_vc_store(ep, vc, dest_addr);
	if (OFI_UNLIKELY(ret != FI_SUCCESS)) {
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "_sstmacx_ep_vc_store returned %s\n",
			  fi_strerror(-ret));
		goto err_w_lock;
	}

	/* Initiate new VC connection. */
	ret = _sstmacx_vc_connect(vc);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "_sstmacx_vc_connect returned %s\n",
			  fi_strerror(-ret));
		goto err_w_lock;
	}

	*vc_ptr = vc;
	return ret;

err_w_lock:
	if (vc != NULL)
		_sstmacx_vc_destroy(vc);
	return ret;
}

/*******************************************************************************
 * connection request /response message pack/unpack functions
 ******************************************************************************/

/*
 * pack a connection request. Contents:
 * - target_addr (the addr of the targeted EP for the conn req)
 * - src_addr (the address of the EP originating the conn req)
 * - src_vc_id (the vc id the mbox the originating EP allocated to
 *              build this connection)
 * - src_vc_vaddr (virt. address of the vc struct allocated at the originating
 *                 EP to build this connection)
 * - src_smsg_attr (smsg attributes of the mbox allocated at the
 *                  originating EP for this connection)
 * - src_irq_cq_mhdl (SSTMAC memory handle for irq cq for originating EP)
 */
static void __sstmacx_vc_pack_conn_req(char *sbuf,
				    struct sstmacx_address *target_addr,
				    struct sstmacx_address *src_addr,
				    int src_vc_id,
				    uint64_t src_vc_vaddr,
				    sstmac_smsg_attr_t *src_smsg_attr,
				    sstmac_mem_handle_t *src_irq_cq_mhdl,
				    uint64_t caps,
				    xpmem_segid_t my_segid,
				    uint8_t name_type,
				    uint8_t rx_ctx_cnt,
					uint32_t key_offset)
{
	size_t __attribute__((unused)) len;
	char *cptr = sbuf;
	uint8_t rtype = SSTMACX_VC_CONN_REQ;

	/*
	 * sanity checks
	 */

	assert(sbuf != NULL);

	len = sizeof(rtype) +
	      sizeof(struct sstmacx_address) * 2 +
	      sizeof(int) +
	      sizeof(uint64_t) * 2 +
	      sizeof(sstmac_smsg_attr_t) +
	      sizeof(sstmac_mem_handle_t) +
	      sizeof(xpmem_segid_t) +
	      sizeof(name_type) +
	      sizeof(rx_ctx_cnt) +
		  sizeof(key_offset);

	assert(len <= SSTMACX_CM_NIC_MAX_MSG_SIZE);

	memcpy(cptr, &rtype, sizeof(rtype));
	cptr += sizeof(rtype);
	memcpy(cptr, target_addr, sizeof(struct sstmacx_address));
	cptr += sizeof(struct sstmacx_address);
	memcpy(cptr, src_addr, sizeof(struct sstmacx_address));
	cptr += sizeof(struct sstmacx_address);
	memcpy(cptr, &src_vc_id, sizeof(int));
	cptr += sizeof(int);
	memcpy(cptr, &src_vc_vaddr, sizeof(uint64_t));
	cptr += sizeof(uint64_t);
	memcpy(cptr, src_smsg_attr, sizeof(sstmac_smsg_attr_t));
	cptr += sizeof(sstmac_smsg_attr_t);
	memcpy(cptr, src_irq_cq_mhdl, sizeof(sstmac_mem_handle_t));
	cptr += sizeof(sstmac_mem_handle_t);
	memcpy(cptr, &caps, sizeof(uint64_t));
	cptr += sizeof(uint64_t);
	memcpy(cptr, &my_segid, sizeof(xpmem_segid_t));
	cptr += sizeof(xpmem_segid_t);
	memcpy(cptr, &name_type, sizeof(name_type));
	cptr += sizeof(name_type);
	memcpy(cptr, &rx_ctx_cnt, sizeof(rx_ctx_cnt));
	cptr += sizeof(rx_ctx_cnt);
	memcpy(cptr, &key_offset, sizeof(key_offset));
}

/*
 * unpack a connection request message
 */
static void __sstmacx_vc_unpack_conn_req(char *rbuf,
				      struct sstmacx_address *target_addr,
				      struct sstmacx_address *src_addr,
				      int *src_vc_id,
				      uint64_t *src_vc_vaddr,
				      sstmac_smsg_attr_t *src_smsg_attr,
				      sstmac_mem_handle_t *src_irq_cq_mhndl,
				      uint64_t *caps,
				      xpmem_segid_t *peer_segid,
				      uint8_t *name_type,
				      uint8_t *rx_ctx_cnt,
					  uint32_t *key_offset)
{
	size_t __attribute__((unused)) len;
	char *cptr = rbuf;

	/*
	 * sanity checks
	 */

	assert(rbuf);

	cptr += sizeof(uint8_t);
	memcpy(target_addr, cptr, sizeof(struct sstmacx_address));
	cptr += sizeof(struct sstmacx_address);
	memcpy(src_addr, cptr, sizeof(struct sstmacx_address));
	cptr += sizeof(struct sstmacx_address);
	memcpy(src_vc_id, cptr, sizeof(int));
	cptr += sizeof(int);
	memcpy(src_vc_vaddr, cptr, sizeof(uint64_t));
	cptr += sizeof(uint64_t);
	memcpy(src_smsg_attr, cptr, sizeof(sstmac_smsg_attr_t));
	cptr += sizeof(sstmac_smsg_attr_t);
	memcpy(src_irq_cq_mhndl, cptr, sizeof(sstmac_mem_handle_t));
	cptr += sizeof(sstmac_mem_handle_t);
	memcpy(caps, cptr, sizeof(uint64_t));
	cptr += sizeof(uint64_t);
	memcpy(peer_segid, cptr, sizeof(xpmem_segid_t));
	cptr += sizeof(xpmem_segid_t);
	memcpy(name_type, cptr, sizeof(*name_type));
	cptr += sizeof(*name_type);
	memcpy(rx_ctx_cnt, cptr, sizeof(*rx_ctx_cnt));
	cptr += sizeof(*rx_ctx_cnt);
	memcpy(key_offset, cptr, sizeof(*key_offset));
}

/*
 * pack a connection response. Contents:
 * - src_vc_vaddr (vaddr of the vc struct allocated at the originating
 *                EP to build this connection)
 * - resp_vc_id (the vc id of the mbox the responding EP allocated to
 *          build this connection)
 * - resp_smsg_attr (smsg attributes of the mbox allocated at the
 *                   responding EP for this connection)
 * - resp_irq_cq_mhndl (SSTMAC memhndl for irq cq of responding EP)
 */

static void __sstmacx_vc_pack_conn_resp(char *sbuf,
				     uint64_t src_vc_vaddr,
				     uint64_t resp_vc_vaddr,
				     int resp_vc_id,
				     sstmac_smsg_attr_t *resp_smsg_attr,
				     sstmac_mem_handle_t *resp_irq_cq_mhndl,
				     uint64_t caps,
				     xpmem_segid_t my_segid,
					 uint32_t key_offset)
{
	size_t __attribute__((unused)) len;
	char *cptr = sbuf;
	uint8_t rtype = SSTMACX_VC_CONN_RESP;

	/*
	 * sanity checks
	 */

	assert(sbuf != NULL);

	len = sizeof(rtype) +
	      sizeof(uint64_t) * 3 +
	      sizeof(int) +
	      sizeof(sstmac_smsg_attr_t) +
	      sizeof(sstmac_mem_handle_t) +
	      sizeof(xpmem_segid_t) +
		  sizeof(uint32_t);
	assert(len <= SSTMACX_CM_NIC_MAX_MSG_SIZE);

	memcpy(cptr, &rtype, sizeof(rtype));
	cptr += sizeof(rtype);
	memcpy(cptr, &src_vc_vaddr, sizeof(uint64_t));
	cptr += sizeof(uint64_t);
	memcpy(cptr, &resp_vc_vaddr, sizeof(uint64_t));
	cptr += sizeof(uint64_t);
	memcpy(cptr, &resp_vc_id, sizeof(int));
	cptr += sizeof(int);
	memcpy(cptr, resp_smsg_attr, sizeof(sstmac_smsg_attr_t));
	cptr += sizeof(sstmac_smsg_attr_t);
	memcpy(cptr, resp_irq_cq_mhndl, sizeof(sstmac_mem_handle_t));
	cptr += sizeof(sstmac_mem_handle_t);
	memcpy(cptr, &caps, sizeof(uint64_t));
	cptr += sizeof(uint64_t);
	memcpy(cptr, &my_segid, sizeof(xpmem_segid_t));
	cptr += sizeof(xpmem_segid_t);
	memcpy(cptr, &key_offset, sizeof(uint32_t));
}

/*
 * unpack a connection request response
 */
static void __sstmacx_vc_unpack_resp(char *rbuf,
				  uint64_t *src_vc_vaddr,
				  uint64_t *resp_vc_vaddr,
				  int *resp_vc_id,
				  sstmac_smsg_attr_t *resp_smsg_attr,
				  sstmac_mem_handle_t *resp_irq_cq_mhndl,
				  uint64_t *caps,
				  xpmem_segid_t *peer_segid,
				  uint32_t *key_offset)
{
	char *cptr = rbuf;

	cptr += sizeof(uint8_t);

	memcpy(src_vc_vaddr, cptr, sizeof(uint64_t));
	cptr += sizeof(uint64_t);
	memcpy(resp_vc_vaddr, cptr, sizeof(uint64_t));
	cptr += sizeof(uint64_t);
	memcpy(resp_vc_id, cptr, sizeof(int));
	cptr += sizeof(int);
	memcpy(resp_smsg_attr, cptr, sizeof(sstmac_smsg_attr_t));
	cptr += sizeof(sstmac_smsg_attr_t);
	memcpy(resp_irq_cq_mhndl, cptr, sizeof(sstmac_mem_handle_t));
	cptr += sizeof(sstmac_mem_handle_t);
	memcpy(caps, cptr, sizeof(uint64_t));
	cptr += sizeof(uint64_t);
	memcpy(peer_segid, cptr, sizeof(xpmem_segid_t));
	cptr += sizeof(xpmem_segid_t);
	memcpy(key_offset, cptr, sizeof(uint32_t));
}

static void __sstmacx_vc_get_msg_type(char *rbuf,
				  uint8_t *rtype)
{
	assert(rtype);
	memcpy(rtype, rbuf, sizeof(uint8_t));
}

/*
 * helper function to initialize an SMSG connection, plus
 * a mem handle to use for delivering IRQs to peer when needed
 */
extern "C" int _sstmacx_vc_smsg_init(struct sstmacx_vc *vc, int peer_id,
		       sstmac_smsg_attr_t *peer_smsg_attr,
		       sstmac_mem_handle_t *peer_irq_mem_hndl)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_ep *ep;
	struct sstmacx_fid_domain *dom;
	struct sstmacx_mbox *mbox = NULL;
	sstmac_smsg_attr_t local_smsg_attr;
	sstmac_return_t __attribute__((unused)) status;
	ssize_t __attribute__((unused)) len;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	assert(vc);

	ep = vc->ep;
	assert(ep);

	dom = ep->domain;
	if (dom == NULL)
		return -FI_EINVAL;

	mbox = vc->smsg_mbox;
	assert (mbox);

	local_smsg_attr.msg_type = SSTMAC_SMSG_TYPE_MBOX_AUTO_RETRANSMIT;
	local_smsg_attr.msg_buffer = mbox->base;
	local_smsg_attr.buff_size =  vc->ep->nic->mem_per_mbox;
	local_smsg_attr.mem_hndl = *mbox->memory_handle;
	local_smsg_attr.mbox_offset = (uint64_t)mbox->offset;
	local_smsg_attr.mbox_maxcredit = dom->params.mbox_maxcredit;
	local_smsg_attr.msg_maxsize = dom->params.mbox_msg_maxsize;

	/*
	 *  now build the SMSG connection
	 */

	COND_ACQUIRE(ep->nic->requires_lock, &ep->nic->lock);

	status = SSTMAC_EpCreate(ep->nic->sstmac_nic_hndl,
			      ep->nic->tx_cq,
			      &vc->sstmac_ep);
	if (status != SSTMAC_RC_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			"SSTMAC_EpCreate returned %s\n", sstmac_err_str[status]);
		ret = sstmacxu_to_fi_errno(status);
		goto err;
	}

	status = SSTMAC_EpBind(vc->sstmac_ep,
			    vc->peer_addr.device_addr,
			    vc->peer_addr.cdm_id);
	if (status != SSTMAC_RC_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "SSTMAC_EpBind returned %s\n", sstmac_err_str[status]);
		ret = sstmacxu_to_fi_errno(status);
		goto err1;
	}

	status = SSTMAC_SmsgInit(vc->sstmac_ep,
			      &local_smsg_attr,
			      peer_smsg_attr);
	if (status != SSTMAC_RC_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			"SSTMAC_SmsgInit returned %s\n", sstmac_err_str[status]);
		ret = sstmacxu_to_fi_errno(status);
		goto err1;
	}

	status = SSTMAC_EpSetEventData(vc->sstmac_ep,
				    vc->vc_id,
				    peer_id);
	if (status != SSTMAC_RC_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "SSTMAC_EpSetEventData returned %s\n",
			   sstmac_err_str[status]);
		ret = sstmacxu_to_fi_errno(status);
		goto err1;
	}

	if (peer_irq_mem_hndl != NULL)
		vc->peer_irq_mem_hndl = *peer_irq_mem_hndl;

	COND_RELEASE(ep->nic->requires_lock, &ep->nic->lock);
	return ret;
err1:
	SSTMAC_EpDestroy(vc->sstmac_ep);
err:
	COND_RELEASE(ep->nic->requires_lock, &ep->nic->lock);
	return ret;
}

static int __sstmacx_vc_connect_to_self(struct sstmacx_vc *vc)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_domain *dom = NULL;
	struct sstmacx_fid_ep *ep = NULL;
	struct sstmacx_cm_nic *cm_nic = NULL;
	struct sstmacx_mbox *mbox = NULL;
	sstmac_smsg_attr_t smsg_mbox_attr;
	xpmem_apid_t peer_apid;
	xpmem_segid_t my_segid;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	ep = vc->ep;
	if (ep == NULL)
		return -FI_EINVAL;

	cm_nic = ep->cm_nic;
	if (cm_nic == NULL)
		return -FI_EINVAL;

	dom = ep->domain;
	if (dom == NULL)
		return -FI_EINVAL;

	assert(vc->conn_state == SSTMACX_VC_CONN_NONE);
	vc->conn_state = SSTMACX_VC_CONNECTING;

	assert(vc->smsg_mbox == NULL);

	ret = _sstmacx_mbox_alloc(vc->ep->nic->mbox_hndl, &mbox);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "_sstmacx_mbox_alloc returned %s\n",
			  fi_strerror(-ret));
		return -FI_ENOSPC;
	}
	vc->smsg_mbox = mbox;

	smsg_mbox_attr.msg_type = SSTMAC_SMSG_TYPE_MBOX_AUTO_RETRANSMIT;
	smsg_mbox_attr.msg_buffer = mbox->base;
	smsg_mbox_attr.buff_size =  vc->ep->nic->mem_per_mbox;
	smsg_mbox_attr.mem_hndl = *mbox->memory_handle;
	smsg_mbox_attr.mbox_offset = (uint64_t)mbox->offset;
	smsg_mbox_attr.mbox_maxcredit = dom->params.mbox_maxcredit;
	smsg_mbox_attr.msg_maxsize = dom->params.mbox_msg_maxsize;

	ret = _sstmacx_vc_smsg_init(vc, vc->vc_id, &smsg_mbox_attr, NULL);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "_sstmacx_vc_smsg_init returned %s\n",
			  fi_strerror(-ret));
		goto err_mbox_init;
	}

	/* TODO: use special send-to-self mechanism to avoid overhead of XPMEM
	 * when just sending a message to oneself. */
	ret = _sstmacx_xpmem_get_my_segid(ep->xpmem_hndl, &my_segid);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "_sstmac_xpmem_get_my_segid returned %s\n",
			  fi_strerror(-ret));
	}

	ret = _sstmacx_xpmem_get_apid(ep->xpmem_hndl, my_segid, &peer_apid);
	if (ret == FI_SUCCESS) {
		vc->modes |= SSTMACX_VC_MODE_XPMEM;
		vc->peer_apid = peer_apid;
	} else {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "_sstmac_xpmem_get_apiid returned %s\n",
			  fi_strerror(-ret));
	}

	vc->peer_id = vc->vc_id;
	vc->peer_irq_mem_hndl = ep->nic->irq_mem_hndl;
	vc->peer_caps = ep->caps;
	vc->peer_key_offset = ep->auth_key->key_offset;
	vc->conn_state = SSTMACX_VC_CONNECTED;

	ret = _sstmacx_vc_sched_new_conn(vc);
	if (ret != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "_sstmacx_vc_sched_new_conn returned %s\n",
			  fi_strerror(-ret));

	SSTMACX_DEBUG(FI_LOG_EP_CTRL, "moving vc %p state to connected\n", vc);
	return ret;

err_mbox_init:
	_sstmacx_mbox_free(vc->smsg_mbox);
	vc->smsg_mbox = NULL;

	return ret;
}

/*******************************************************************************
 * functions for handling incoming connection request/response messages
 ******************************************************************************/

static int __sstmacx_vc_hndl_conn_resp(struct sstmacx_cm_nic *cm_nic,
				    char *msg_buffer,
				    struct sstmacx_address src_cm_nic_addr)
{
	int ret = FI_SUCCESS;
	int peer_id;
	struct sstmacx_vc *vc = NULL;
	uint64_t peer_vc_addr;
	struct sstmacx_fid_ep *ep;
	sstmac_smsg_attr_t peer_smsg_attr;
	sstmac_mem_handle_t tmp_mem_hndl;
	uint64_t peer_caps;
	xpmem_segid_t peer_segid;
	xpmem_apid_t peer_apid;
	uint32_t peer_key_offset;
	bool accessible;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	/*
	 * unpack the message
	 */

	__sstmacx_vc_unpack_resp(msg_buffer,
			      (uint64_t *)&vc,
			      &peer_vc_addr,
			      &peer_id,
			      &peer_smsg_attr,
			      &tmp_mem_hndl,
			      &peer_caps,
			      &peer_segid,
				  &peer_key_offset);

	SSTMACX_DEBUG(FI_LOG_EP_CTRL,
		"resp rx: (From Aries 0x%x Id %d src vc %p peer vc addr 0x%lx)\n",
		 src_cm_nic_addr.device_addr,
		 src_cm_nic_addr.cdm_id,
		 vc,
		 peer_vc_addr);

	ep = vc->ep;
	assert(ep != NULL);

	COND_ACQUIRE(ep->requires_lock, &ep->vc_lock);

	/*
	 * at this point vc should be in connecting state
	 */
	if (vc->conn_state != SSTMACX_VC_CONNECTING) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "vc %p not in connecting state, rather %d\n",
			  vc, vc->conn_state);
		ret = -FI_EINVAL;
		goto err;
	}

	/*
	 * build the SMSG connection
	 */

	ret = _sstmacx_vc_smsg_init(vc, peer_id, &peer_smsg_attr,
				 &tmp_mem_hndl);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			"_sstmacx_vc_smsg_init returned %s\n",
			fi_strerror(-ret));
		goto err;
	}

	/*
	 * see if we can do xpmem with this EP
	 */

	ret = _sstmacx_xpmem_accessible(ep, src_cm_nic_addr, &accessible);
	if ((ret == FI_SUCCESS) && (accessible == true)) {
		ret = _sstmacx_xpmem_get_apid(ep->xpmem_hndl,
					   peer_segid,
					   &peer_apid);
		if (ret == FI_SUCCESS) {
			vc->modes |= SSTMACX_VC_MODE_XPMEM;
			vc->peer_apid = peer_apid;
		}
	}

	/*
	 * transition the VC to connected
	 * put in to the nic's work queue for
	 * further processing
	 */

	vc->peer_caps = peer_caps;
	vc->peer_key_offset = peer_key_offset;
	vc->peer_id = peer_id;
	vc->conn_state = SSTMACX_VC_CONNECTED;
	SSTMACX_DEBUG(FI_LOG_EP_CTRL,
		   " moving vc %p to state connected\n",vc);

	ret = _sstmacx_vc_sched_new_conn(vc);
	if (ret != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "_sstmacx_vc_sched_new_conn returned %s\n",
			  fi_strerror(-ret));

	COND_RELEASE(ep->requires_lock, &ep->vc_lock);

	return ret;
err:
	vc->conn_state = SSTMACX_VC_CONN_ERROR;

	COND_RELEASE(ep->requires_lock, &ep->vc_lock);
	return ret;
}

static int __sstmacx_vc_hndl_conn_req(struct sstmacx_cm_nic *cm_nic,
				   char *msg_buffer,
				   struct sstmacx_address src_cm_nic_addr)
{
	int ret = FI_SUCCESS;
	sstmac_return_t __attribute__((unused)) status;
	struct sstmacx_fid_ep *ep = NULL;
	sstmacx_ht_key_t key;
	struct sstmacx_av_addr_entry entry;
	struct sstmacx_address src_addr, target_addr;
	struct sstmacx_vc *vc = NULL;
	struct sstmacx_work_req *work_req;
	int src_vc_id;
	sstmac_smsg_attr_t src_smsg_attr;
	uint64_t src_vc_ptr;
	uint64_t peer_caps;
	struct wq_hndl_conn_req *data = NULL;
	sstmac_mem_handle_t tmp_mem_hndl;
	int src_mapped = 0;
	fi_addr_t fi_addr;
	xpmem_segid_t peer_segid;
	xpmem_apid_t peer_apid;
	uint8_t name_type, rx_ctx_cnt;
	bool accessible;
	ssize_t __attribute__((unused)) len;
	struct sstmacx_ep_name *error_data;
	uint32_t key_offset;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	/*
	 * unpack the message
	 */

	__sstmacx_vc_unpack_conn_req(msg_buffer,
				  &target_addr,
				  &src_addr,
				  &src_vc_id,
				  &src_vc_ptr,
				  &src_smsg_attr,
				  &tmp_mem_hndl,
				  &peer_caps,
				  &peer_segid,
				  &name_type,
				  &rx_ctx_cnt,
				  &key_offset);

	SSTMACX_DEBUG(FI_LOG_EP_CTRL,
		"conn req rx: (From Aries addr 0x%x Id %d to Aries 0x%x Id %d src vc 0x%lx )\n",
		 src_addr.device_addr,
		 src_addr.cdm_id,
		 target_addr.device_addr,
		 target_addr.cdm_id,
		 src_vc_ptr);

	/*
	 * lookup the ep from the addr_to_ep_ht using the target_addr
	 * in the datagram
	 */

	__sstmacx_vc_set_ht_key(&target_addr, &key);

	ep = (struct sstmacx_fid_ep *)_sstmacx_ht_lookup(cm_nic->addr_to_ep_ht,
						   key);
	if (ep == NULL) {
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "_sstmacx_ht_lookup addr_to_ep failed\n");
		return -FI_ENOENT;
	}

	/*
	 * look to see if there is a VC already for the
	 * address of the connecting EP.
	 */

	COND_ACQUIRE(ep->requires_lock, &ep->vc_lock);

	/* If we already have an AV bound, see if sender's address is already
	 * mapped. */
	if (ep->av) {
		ret = _sstmacx_av_reverse_lookup(ep->av, src_addr, &fi_addr);
		if (ret == FI_SUCCESS) {
			src_mapped = 1;
			vc = _sstmacx_ep_vc_lookup(ep, fi_addr);
		}
	}

	/*
	 * if there is no corresponding vc in the hash,
	 * or there is an entry and it's not in connecting state
	 * go down the conn req ack route.
	 */
	if ((vc == NULL)  ||
	    (vc->conn_state == SSTMACX_VC_CONN_NONE)) {
		if (vc == NULL) {
			entry.sstmacx_addr = src_addr;
			entry.cm_nic_cdm_id = src_cm_nic_addr.cdm_id;
			ret = _sstmacx_vc_alloc(ep,
					     &entry,
					     &vc);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "_sstmacx_vc_alloc returned %s\n",
					  fi_strerror(-ret));
				goto err;
			}

			vc->conn_state = SSTMACX_VC_CONNECTING;
			vc->peer_key_offset = key_offset;

			if (src_mapped) {
				/* We have an AV which maps the incoming
				 * address.  Store the new VC in our VC lookup
				 * table. */
				ret = _sstmacx_ep_vc_store(ep, vc, fi_addr);
				if (OFI_UNLIKELY(ret != FI_SUCCESS)) {
					_sstmacx_vc_destroy(vc);
					SSTMACX_WARN(FI_LOG_EP_DATA,
						  "_sstmacx_ep_vc_store returned %s\n",
						  fi_strerror(-ret));
					goto err;
				}
			} else {
				/* We lack an AV and/or the entry to map the
				 * incoming address.  Keep VC in special table
				 * until it is mapped for a TX operation. */
				SSTMACX_INFO(FI_LOG_EP_CTRL,
					  "Received conn. request from unmapped peer EP, vc: %p addr: 0x%lx\n",
					  vc, src_addr);

				dlist_insert_tail(&vc->list, &ep->unmapped_vcs);

				/*
				 * see issue 4521 for the error_data size allocated
				 */
				if (vc->ep->caps & FI_SOURCE) {
					error_data =
						calloc(1, SSTMACX_CQ_MAX_ERR_DATA_SIZE);
					if (error_data == NULL) {
						ret = -FI_ENOMEM;
						goto err;
					}
					vc->sstmacx_ep_name = (void *) error_data;

					error_data->sstmacx_addr = src_addr;
					error_data->name_type = name_type;

					error_data->cm_nic_cdm_id =
						cm_nic->my_name.cm_nic_cdm_id;
					error_data->cookie =
						cm_nic->my_name.cookie;

					error_data->rx_ctx_cnt = rx_ctx_cnt;
				}
			}
		} else {
			vc->conn_state = SSTMACX_VC_CONNECTING;
		}

		vc->peer_caps = peer_caps;
		vc->peer_key_offset = key_offset;
		/*
		 * prepare a work request to
		 * initiate an request response
		 */

		work_req = calloc(1, sizeof(*work_req));
		if (work_req == NULL) {
			ret = -FI_ENOMEM;
			goto err;
		}

		data = calloc(1, sizeof(struct wq_hndl_conn_req));
		if (data == NULL) {
			ret = -FI_ENOMEM;
			goto err;
		}
		memcpy(&data->src_smsg_attr,
		       &src_smsg_attr,
		       sizeof(src_smsg_attr));
		data->vc = vc;
		data->src_vc_id = src_vc_id;
		data->src_vc_ptr = src_vc_ptr;
		data->irq_mem_hndl = tmp_mem_hndl;
		data->peer_segid = peer_segid;

		work_req->progress_fn = __sstmacx_vc_conn_ack_prog_fn;
		work_req->data = data;
		work_req->completer_fn = __sstmacx_vc_conn_ack_comp_fn;
		work_req->completer_data = data;

		/*
		 * add the work request to the tail of the
		 * cm_nic's work queue, progress the cm_nic.
		 */

		fastlock_acquire(&cm_nic->wq_lock);
		dlist_insert_before(&work_req->list, &cm_nic->cm_nic_wq);
		fastlock_release(&cm_nic->wq_lock);
	} else {

		/*
		 * we can only be in connecting state if we
		 * reach here.  We have all the informatinon,
		 * and the other side will get the information
		 * at some point, so go ahead and build SMSG connection.
		 */
		if (vc->conn_state != SSTMACX_VC_CONNECTING) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				 "vc %p not in connecting state nor in cm wq\n",
				  vc, vc->conn_state);
			ret = -FI_EINVAL;
			goto err;
		}

		ret = _sstmacx_vc_smsg_init(vc, src_vc_id,
					 &src_smsg_attr,
					 &tmp_mem_hndl);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "_sstmacx_vc_smsg_init returned %s\n",
				  fi_strerror(-ret));
			goto err;
		}

		ret = _sstmacx_xpmem_accessible(ep, src_cm_nic_addr, &accessible);
		if ((ret == FI_SUCCESS) && (accessible == true)) {
			ret = _sstmacx_xpmem_get_apid(ep->xpmem_hndl,
						   peer_segid,
						   &peer_apid);
			if (ret == FI_SUCCESS) {
				vc->modes |= SSTMACX_VC_MODE_XPMEM;
				vc->peer_apid = peer_apid;
			}
		}

		vc->peer_caps = peer_caps;
		vc->peer_key_offset = key_offset;
		vc->peer_id = src_vc_id;
		vc->conn_state = SSTMACX_VC_CONNECTED;
		SSTMACX_DEBUG(FI_LOG_EP_CTRL, "moving vc %p state to connected\n",
			vc);

		ret = _sstmacx_vc_sched_new_conn(vc);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_vc_sched_new_conn returned %s\n",
				  fi_strerror(-ret));
	}

err:
	COND_RELEASE(ep->requires_lock, &ep->vc_lock);

	return ret;
}

/*
 * callback function to process incoming messages
 */
static int __sstmacx_vc_recv_fn(struct sstmacx_cm_nic *cm_nic,
		      char *msg_buffer,
		      struct sstmacx_address src_cm_nic_addr)
{
	int ret = FI_SUCCESS;
	uint8_t mtype;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	__sstmacx_vc_get_msg_type(msg_buffer, &mtype);

	SSTMACX_DEBUG(FI_LOG_EP_CTRL, "got a message of type %d\n", mtype);

	switch (mtype) {
	case SSTMACX_VC_CONN_REQ:
		ret = __sstmacx_vc_hndl_conn_req(cm_nic,
					      msg_buffer,
					      src_cm_nic_addr);
		break;
	case SSTMACX_VC_CONN_RESP:
		ret = __sstmacx_vc_hndl_conn_resp(cm_nic,
					       msg_buffer,
					       src_cm_nic_addr);
		break;
	default:
		SSTMACX_FATAL(FI_LOG_EP_CTRL, "Invalid message type: %d\n",
			   mtype);
	}

	return ret;
}

/*
 * progress function for progressing a connection
 * ACK.
 */

static int __sstmacx_vc_conn_ack_prog_fn(void *data, int *complete_ptr)
{
	int ret = FI_SUCCESS;
	int complete = 0;
	struct wq_hndl_conn_req *work_req_data;
	struct sstmacx_vc *vc;
	struct sstmacx_mbox *mbox = NULL;
	sstmac_smsg_attr_t smsg_mbox_attr;
	struct sstmacx_fid_ep *ep = NULL;
	struct sstmacx_fid_domain *dom = NULL;
	struct sstmacx_cm_nic *cm_nic = NULL;
	xpmem_segid_t my_segid;
	char sbuf[SSTMACX_CM_NIC_MAX_MSG_SIZE] = {0};
	xpmem_apid_t peer_apid;
	bool accessible;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");


	work_req_data = (struct wq_hndl_conn_req *)data;

	vc = work_req_data->vc;
	if (vc == NULL)
		return -FI_EINVAL;

	ep = vc->ep;
	if (ep == NULL)
		return -FI_EINVAL;

	dom = ep->domain;
	if (dom == NULL)
		return -FI_EINVAL;

	cm_nic = ep->cm_nic;
	if (cm_nic == NULL)
		return -FI_EINVAL;

	COND_ACQUIRE(ep->requires_lock, &ep->vc_lock);

	/*
	 * we may have already been moved to connected or
	 * the datagram from an earlier conn request for this
	 * vc was posted to SSTMAC datagram state machine.  The
	 * connection will be completed in the __sstmacx_vc_hndl_conn_resp
	 * datagram callback in the latter case.
	 */
	if ((vc->conn_state == SSTMACX_VC_CONNECTED) ||
		(vc->modes & SSTMACX_VC_MODE_DG_POSTED)) {
		complete = 1;
		goto exit;
	}

	/*
	 * first see if we still need a mailbox
	 */

	if (vc->smsg_mbox == NULL) {
		ret = _sstmacx_mbox_alloc(ep->nic->mbox_hndl,
				       &mbox);
		if (ret == FI_SUCCESS)
			vc->smsg_mbox = mbox;
		else
			goto exit;
	}

	mbox = vc->smsg_mbox;

	/*
	 * prep the smsg_mbox_attr
	 */

	smsg_mbox_attr.msg_type = SSTMAC_SMSG_TYPE_MBOX_AUTO_RETRANSMIT;
	smsg_mbox_attr.msg_buffer = mbox->base;
	smsg_mbox_attr.buff_size =  ep->nic->mem_per_mbox;
	smsg_mbox_attr.mem_hndl = *mbox->memory_handle;
	smsg_mbox_attr.mbox_offset = (uint64_t)mbox->offset;
	smsg_mbox_attr.mbox_maxcredit = dom->params.mbox_maxcredit;
	smsg_mbox_attr.msg_maxsize = dom->params.mbox_msg_maxsize;

	/*
	 * serialize the resp message in the buffer
	 */

	ret = _sstmacx_xpmem_get_my_segid(ep->xpmem_hndl,
				       &my_segid);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "_sstmac_xpmem_get_my_segid returned %s\n",
			  fi_strerror(-ret));
	}

	__sstmacx_vc_pack_conn_resp(sbuf,
				 work_req_data->src_vc_ptr,
				 (uint64_t)vc,
				 vc->vc_id,
				 &smsg_mbox_attr,
				 &ep->nic->irq_mem_hndl,
				 ep->caps,
				 my_segid,
				 ep->auth_key->key_offset);

	/*
	 * try to send the message, if it succeeds,
	 * initialize mailbox and move vc to connected
	 * state.
	 */

	ret = _sstmacx_cm_nic_send(cm_nic,
				sbuf,
				SSTMACX_CM_NIC_MAX_MSG_SIZE,
				vc->peer_cm_nic_addr);
	if (ret == FI_SUCCESS) {
		ret = _sstmacx_vc_smsg_init(vc,
					 work_req_data->src_vc_id,
					 &work_req_data->src_smsg_attr,
					 &work_req_data->irq_mem_hndl);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "_sstmacx_vc_smsg_init returned %s\n",
				  fi_strerror(-ret));
			goto exit;
		}

		/*
		 * TODO: xpmem setup here
		 */

		ret = _sstmacx_xpmem_accessible(ep, vc->peer_cm_nic_addr,
					     &accessible);
		if ((ret == FI_SUCCESS) && (accessible == true)) {
			ret = _sstmacx_xpmem_get_apid(ep->xpmem_hndl,
						   work_req_data->peer_segid,
						   &peer_apid);
			if (ret == FI_SUCCESS) {
				vc->modes |= SSTMACX_VC_MODE_XPMEM;
				vc->peer_apid = peer_apid;
			}
		}

		complete = 1;
		vc->conn_state = SSTMACX_VC_CONNECTED;
		vc->peer_id = work_req_data->src_vc_id;
		SSTMACX_DEBUG(FI_LOG_EP_CTRL,
			   "moving vc %p to connected\n",vc);
		vc->modes |= SSTMACX_VC_MODE_DG_POSTED;

		ret = _sstmacx_vc_sched_new_conn(vc);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_vc_sched_new_conn returned %s\n",
				  fi_strerror(-ret));
	} else if (ret == -FI_EAGAIN) {
		ret = FI_SUCCESS;
	} else {
		SSTMACX_FATAL(FI_LOG_EP_CTRL, "_sstmacx_cm_nic_send returned %s\n",
			   fi_strerror(-ret));
	}

exit:
	COND_RELEASE(ep->requires_lock, &ep->vc_lock);

	*complete_ptr = complete;
	return ret;
}

static int __sstmacx_vc_conn_req_prog_fn(void *data, int *complete_ptr)
{
	int ret = FI_SUCCESS;
	int complete = 0;
	struct sstmacx_vc *vc = (struct sstmacx_vc *)data;
	struct sstmacx_mbox *mbox = NULL;
	sstmac_smsg_attr_t smsg_mbox_attr;
	struct sstmacx_fid_ep *ep = NULL;
	struct sstmacx_fid_domain *dom = NULL;
	struct sstmacx_cm_nic *cm_nic = NULL;
	xpmem_segid_t my_segid;
	char sbuf[SSTMACX_CM_NIC_MAX_MSG_SIZE] = {0};
	struct sstmacx_auth_key *auth_key;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	ep = vc->ep;
	if (ep == NULL)
		return -FI_EINVAL;

	dom = ep->domain;
	if (dom == NULL)
		return -FI_EINVAL;

	cm_nic = ep->cm_nic;
	if (cm_nic == NULL)
		return -FI_EINVAL;

	auth_key = ep->auth_key;
	if (auth_key == NULL)
		return -FI_EINVAL;

	assert(auth_key->enabled);

	COND_ACQUIRE(ep->requires_lock, &ep->vc_lock);

	if ((vc->conn_state == SSTMACX_VC_CONNECTING) ||
		(vc->conn_state == SSTMACX_VC_CONNECTED)) {
			complete = 1;
			goto err;
	}

	/*
	 * first see if we still need a mailbox
	 */

	if (vc->smsg_mbox == NULL) {
		ret = _sstmacx_mbox_alloc(vc->ep->nic->mbox_hndl,
				       &mbox);
		if (ret == FI_SUCCESS)
			vc->smsg_mbox = mbox;
		else
			goto err;
	}

	mbox = vc->smsg_mbox;

	/*
	 * prep the smsg_mbox_attr
	 */

	smsg_mbox_attr.msg_type = SSTMAC_SMSG_TYPE_MBOX_AUTO_RETRANSMIT;
	smsg_mbox_attr.msg_buffer = mbox->base;
	smsg_mbox_attr.buff_size =  vc->ep->nic->mem_per_mbox;
	smsg_mbox_attr.mem_hndl = *mbox->memory_handle;
	smsg_mbox_attr.mbox_offset = (uint64_t)mbox->offset;
	smsg_mbox_attr.mbox_maxcredit = dom->params.mbox_maxcredit;
	smsg_mbox_attr.msg_maxsize = dom->params.mbox_msg_maxsize;

	/*
	 * serialize the message in the buffer
	 */

	SSTMACX_DEBUG(FI_LOG_EP_CTRL,
		"conn req tx: (From Aries addr 0x%x Id %d to Aries 0x%x Id %d CM NIC Id %d vc %p)\n",
		 ep->src_addr.sstmacx_addr.device_addr,
		 ep->src_addr.sstmacx_addr.cdm_id,
		 vc->peer_addr.device_addr,
		 vc->peer_addr.cdm_id,
		 vc->peer_cm_nic_addr.cdm_id,
		 vc);

        ret = _sstmacx_xpmem_get_my_segid(ep->xpmem_hndl,
				       &my_segid);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			"_sstmacx_xpmem_get_my_segid returned %s\n",
			fi_strerror(-ret));
	}

	__sstmacx_vc_pack_conn_req(sbuf,
				&vc->peer_addr,
				&ep->src_addr.sstmacx_addr,
				vc->vc_id,
				(uint64_t)vc,
				&smsg_mbox_attr,
				&ep->nic->irq_mem_hndl,
				ep->caps,
				my_segid,
				ep->src_addr.name_type,
				ep->src_addr.rx_ctx_cnt,
				auth_key->key_offset);

	/*
	 * try to send the message, if -FI_EAGAIN is returned, okay,
	 * just don't mark complete.
	 */

	ret = _sstmacx_cm_nic_send(cm_nic,
				sbuf,
				SSTMACX_CM_NIC_MAX_MSG_SIZE,
				vc->peer_cm_nic_addr);
	if (ret == FI_SUCCESS) {
		complete = 1;
		vc->conn_state = SSTMACX_VC_CONNECTING;
		SSTMACX_DEBUG(FI_LOG_EP_CTRL, "moving vc %p state to connecting\n",
			vc);
		vc->modes |= SSTMACX_VC_MODE_DG_POSTED;
	} else if (ret == -FI_EAGAIN) {
		ret = FI_SUCCESS;
	} else {
		SSTMACX_FATAL(FI_LOG_EP_CTRL, "_sstmacx_cm_nic_send returned %s\n",
			   fi_strerror(-ret));
	}

err:
	COND_RELEASE(ep->requires_lock, &ep->vc_lock);
	*complete_ptr = complete;
	return ret;
}

/*
 * conn ack completer function for work queue element,
 * free the previously allocated wq_hndl_conn_req
 * data struct
 */
static int __sstmacx_vc_conn_ack_comp_fn(void *data)
{
	free(data);
	return FI_SUCCESS;
}

/*
 * connect completer function for work queue element,
 * sort of a NO-OP for now.
 */
static int __sstmacx_vc_conn_req_comp_fn(void *data)
{
	return FI_SUCCESS;
}

/*******************************************************************************
 * Internal API functions
 ******************************************************************************/
extern "C" int _sstmacx_vc_alloc(struct sstmacx_fid_ep *ep_priv,
		   struct sstmacx_av_addr_entry *entry, struct sstmacx_vc **vc)

{
	int ret = FI_SUCCESS;
	int remote_id;
	struct sstmacx_vc *vc_ptr = NULL;
	struct sstmacx_nic *nic = NULL;
	struct dlist_entry *de = NULL;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	nic = ep_priv->nic;
	if (nic == NULL)
		return -FI_EINVAL;

	/*
	 * allocate VC from domain's vc_freelist
	 */

	ret = _sstmacx_fl_alloc(&de, &nic->vc_freelist);
	while (ret == -FI_EAGAIN)
		ret = _sstmacx_fl_alloc(&de, &nic->vc_freelist);
	if (ret == FI_SUCCESS) {
		vc_ptr = container_of(de, struct sstmacx_vc, fr_list);
	} else
		return ret;

	vc_ptr->conn_state = SSTMACX_VC_CONN_NONE;
	if (entry) {
		memcpy(&vc_ptr->peer_addr,
			&entry->sstmacx_addr,
			sizeof(struct sstmacx_address));
		vc_ptr->peer_cm_nic_addr.device_addr =
			entry->sstmacx_addr.device_addr;
		vc_ptr->peer_cm_nic_addr.cdm_id =
			entry->cm_nic_cdm_id;
	} else {
		vc_ptr->peer_addr.device_addr = -1;
		vc_ptr->peer_addr.cdm_id = -1;
		vc_ptr->peer_cm_nic_addr.device_addr = -1;
		vc_ptr->peer_cm_nic_addr.cdm_id = -1;
	}
	vc_ptr->ep = ep_priv;

	dlist_init(&vc_ptr->prog_list);
	dlist_init(&vc_ptr->work_queue);
	dlist_init(&vc_ptr->tx_queue);

	vc_ptr->peer_fi_addr = FI_ADDR_NOTAVAIL;

	dlist_init(&vc_ptr->list);

	ofi_atomic_initialize32(&vc_ptr->outstanding_tx_reqs, 0);
	ret = _sstmacx_alloc_bitmap(&vc_ptr->flags, 1, NULL);
	assert(!ret);

	/*
	 * we need an id for the vc to allow for quick lookup
	 * based on SSTMAC_CQ_GET_INST_ID
	 */

	ret = _sstmacx_nic_get_rem_id(nic, &remote_id, vc_ptr);
	if (ret != FI_SUCCESS)
		goto err;
	vc_ptr->vc_id = remote_id;
	vc_ptr->sstmacx_ep_name = NULL;

	*vc = vc_ptr;

	return ret;

err:
	if (vc_ptr)
		free(vc_ptr);
	return ret;
}

static void __sstmacx_vc_cancel(struct sstmacx_vc *vc)
{
	struct sstmacx_nic *nic = vc->ep->nic;

	COND_ACQUIRE(nic->requires_lock, &nic->prog_vcs_lock);
	if (!dlist_empty(&vc->prog_list))
		dlist_remove_init(&vc->prog_list);
	COND_RELEASE(nic->requires_lock, &nic->prog_vcs_lock);
}

/* Destroy an unconnected VC.  More Support is needed to shutdown and destroy
 * an active VC. */
extern "C" int _sstmacx_vc_destroy(struct sstmacx_vc *vc)
{
	int ret = FI_SUCCESS;
	struct sstmacx_nic *nic = NULL;
	sstmac_return_t status = SSTMAC_RC_NOT_DONE;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (vc->ep == NULL) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "ep null\n");
		return -FI_EINVAL;
	}

	nic = vc->ep->nic;
	if (nic == NULL) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "ep nic null for vc %p\n", vc);
		return -FI_EINVAL;
	}

	/*
	 * move vc state to terminating
	 */

	vc->conn_state = SSTMACX_VC_CONN_TERMINATING;

	/*
	 * try to unbind the sstmac_ep if non-NULL.
	 * If there are SMSG or PostFMA/RDMA outstanding
	 * wait here for them to complete
	 */

	if (vc->sstmac_ep != NULL) {
		while (status == SSTMAC_RC_NOT_DONE) {

			COND_ACQUIRE(nic->requires_lock, &nic->lock);
			status = SSTMAC_EpUnbind(vc->sstmac_ep);
			COND_RELEASE(nic->requires_lock, &nic->lock);

			if ((status != SSTMAC_RC_NOT_DONE) &&
				(status != SSTMAC_RC_SUCCESS)) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					"SSTMAC_EpUnBind returned %s\n",
					  sstmac_err_str[status]);
				break;
			}

			if (status == SSTMAC_RC_NOT_DONE)
				_sstmacx_nic_progress(nic);
		}
		COND_ACQUIRE(nic->requires_lock, &nic->lock);
		status = SSTMAC_EpDestroy(vc->sstmac_ep);
		COND_RELEASE(nic->requires_lock, &nic->lock);
		if (status != SSTMAC_RC_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				"SSTMAC_EpDestroy returned %s\n",
				  sstmac_err_str[status]);
	}

	/*
	 * if the vc is in a nic's work queue, remove it
	 */
	__sstmacx_vc_cancel(vc);

	/*
	 * We may eventually want to check the state of the VC, if we
	 * implement true VC shutdown.

	if ((vc->conn_state != SSTMACX_VC_CONN_NONE)
		&& (vc->conn_state != SSTMACX_VC_CONN_TERMINATED)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			      "vc conn state  %d\n",
			       vc->conn_state);
		SSTMACX_WARN(FI_LOG_EP_CTRL, "vc conn state error\n");
		return -FI_EBUSY;
	}
	 */

	/*
	 * if send_q not empty, return -FI_EBUSY
	 * Note for FI_EP_MSG type eps, this behavior
	 * may not be correct for handling fi_shutdown.
	 */

	if (!dlist_empty(&vc->tx_queue))
		SSTMACX_FATAL(FI_LOG_EP_CTRL, "VC TX queue not empty\n");

	if (ofi_atomic_get32(&vc->outstanding_tx_reqs))
		SSTMACX_FATAL(FI_LOG_EP_CTRL,
			   "VC outstanding_tx_reqs out of sync: %d\n",
			   ofi_atomic_get32(&vc->outstanding_tx_reqs));

	if (vc->smsg_mbox != NULL) {
		ret = _sstmacx_mbox_free(vc->smsg_mbox);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_CTRL,
			      "_sstmacx_mbox_free returned %s\n",
			      fi_strerror(-ret));
		vc->smsg_mbox = NULL;
	}

	ret = _sstmacx_nic_free_rem_id(nic, vc->vc_id);
	if (ret != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_EP_CTRL,
		      "__sstmacx_vc_free_id returned %s\n",
		      fi_strerror(-ret));

	_sstmacx_free_bitmap(&vc->flags);

	if (vc->sstmacx_ep_name != NULL) {
		free(vc->sstmacx_ep_name);
		vc->sstmacx_ep_name = NULL;
	}

	/*
	 * put VC back on the freelist
	 */

	vc->conn_state = SSTMACX_VC_CONN_NONE;
	_sstmacx_fl_free(&vc->fr_list, &nic->vc_freelist);

	return ret;
}

extern "C" int _sstmacx_vc_connect(struct sstmacx_vc *vc)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_ep *ep = NULL;
	struct sstmacx_cm_nic *cm_nic = NULL;
	struct sstmacx_work_req *work_req;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	/*
	 * can happen that we are already connecting, or
	 * are connected
	 */

	if ((vc->conn_state == SSTMACX_VC_CONNECTING) ||
		(vc->conn_state == SSTMACX_VC_CONNECTED)) {
		return FI_SUCCESS;
	}

	ep = vc->ep;
	if (ep == NULL)
		return -FI_EINVAL;

	cm_nic = ep->cm_nic;
	if (cm_nic == NULL)
		return -FI_EINVAL;

	/*
	 * only endpoints of type FI_EP_RDM use this
	 * connection method
	 */
	if (!SSTMACX_EP_RDM_DGM(ep->type))
		return -FI_EINVAL;

	/*
	 * check if this EP is connecting to itself
	 */

	if (SSTMACX_ADDR_EQUAL(ep->src_addr.sstmacx_addr, vc->peer_addr)) {
		return __sstmacx_vc_connect_to_self(vc);
	}

	/*
	 * allocate a work request and put it
	 * on the cm_nic work queue.
	 */

	work_req = calloc(1, sizeof(*work_req));
	if (work_req == NULL)
		return -FI_ENOMEM;

	work_req->progress_fn = __sstmacx_vc_conn_req_prog_fn;
	work_req->data = vc;
	work_req->completer_fn = __sstmacx_vc_conn_req_comp_fn;
	work_req->completer_data = vc;

	/*
	 * add the work request to the tail of the
	 * cm_nic's work queue, progress the cm_nic.
	 */

	fastlock_acquire(&cm_nic->wq_lock);
	dlist_insert_before(&work_req->list, &cm_nic->cm_nic_wq);
	fastlock_release(&cm_nic->wq_lock);

	return ret;
}

/******************************************************************************
 *
 * VC RX progress
 *
 *****************************************************************************/

/* Process a VC's SMSG mailbox.
 *
 * Note: EP must be locked. */
extern "C" int _sstmacx_vc_dequeue_smsg(struct sstmacx_vc *vc)
{
	int ret = FI_SUCCESS;
	struct sstmacx_nic *nic;
	sstmac_return_t status;
	void *msg_ptr;
	uint8_t tag;

	SSTMACX_TRACE(FI_LOG_EP_DATA, "\n");

	nic = vc->ep->nic;
	assert(nic != NULL);

	do {
		tag = SSTMAC_SMSG_ANY_TAG;
		status = SSTMAC_SmsgGetNextWTag(vc->sstmac_ep,
					     &msg_ptr,
					     &tag);

		if (status == SSTMAC_RC_SUCCESS) {
			SSTMACX_DEBUG(FI_LOG_EP_DATA, "Found RX (%p)\n", vc);
			ret = nic->smsg_callbacks[tag](vc, msg_ptr);
			if (ret != FI_SUCCESS) {
				/* Stalled, reschedule */
				break;
			}
		} else if (status == SSTMAC_RC_NOT_DONE) {
			/* No more work. */
			ret = FI_SUCCESS;
			break;
		} else {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				"SSTMAC_SmsgGetNextWTag returned %s\n",
				sstmac_err_str[status]);
			ret = sstmacxu_to_fi_errno(status);
			break;
		}
	} while (1);

	return ret;
}

/* Progress VC RXs.  Reschedule VC if more there is more work.
 *
 * Note: EP must be locked. */
static int __sstmacx_vc_rx_progress(struct sstmacx_vc *vc)
{
	int ret;

	/* Process pending RXs */
	COND_ACQUIRE(vc->ep->nic->requires_lock, &vc->ep->nic->lock);
	ret = _sstmacx_vc_dequeue_smsg(vc);
	COND_RELEASE(vc->ep->nic->requires_lock, &vc->ep->nic->lock);

	if (ret != FI_SUCCESS) {
		/* We didn't finish processing RXs.  Low memory likely.
		 * Try again later.  Return error to abort processing
		 * other VCs. */
		_sstmacx_vc_rx_schedule(vc);
		return -FI_EAGAIN;
	}

	/* Return success to continue processing other VCs */
	return FI_SUCCESS;
}

/******************************************************************************
 *
 * VC work progress
 *
 *****************************************************************************/

/* Schedule deferred request processing.  Usually used in RX completers.
 *
 * Note: EP must be locked. */
extern "C" int _sstmacx_vc_queue_work_req(struct sstmacx_fab_req *req)
{
	struct sstmacx_vc *vc = req->vc;

	dlist_insert_tail(&req->dlist, &vc->work_queue);
	__sstmacx_vc_work_schedule(vc);

	return FI_SUCCESS;
}

/* Schedule deferred request processing.  Used in TX completers where VC lock is
 * not yet held. */
extern "C" int _sstmacx_vc_requeue_work_req(struct sstmacx_fab_req *req)
{
	int ret;

	COND_ACQUIRE(req->sstmacx_ep->requires_lock, &req->sstmacx_ep->vc_lock);
	ret = _sstmacx_vc_queue_work_req(req);
	COND_RELEASE(req->sstmacx_ep->requires_lock, &req->sstmacx_ep->vc_lock);

	return ret;
}

/* Process deferred request work on the VC.
 *
 * Note: EP must be locked. */
static int __sstmacx_vc_push_work_reqs(struct sstmacx_vc *vc)
{
	int ret, fi_rc = FI_SUCCESS;
	struct sstmacx_fab_req *req;

	while (1) {
		req = dlist_first_entry(&vc->work_queue,
					struct sstmacx_fab_req,
					dlist);
		if (!req)
			break;

		dlist_remove_init(&req->dlist);

		ret = req->work_fn(req);
		if (ret != FI_SUCCESS) {
			/* Re-schedule failed work. */
			_sstmacx_vc_queue_work_req(req);

			/* FI_ENOSPC is reserved to indicate a lack of
			 * TXDs, which are shared by all VCs on the
			 * NIC.  The other likely error is FI_EAGAIN
			 * due to a lack of SMSG credits. */
			if ((ret != -FI_ENOSPC) &&
			    (ret != -FI_EAGAIN)) {
				/*
				 * TODO: Report error (via CQ err?)
				 * Note: This error can't be reported here.
				 */
				SSTMACX_FATAL(FI_LOG_EP_DATA,
					   "Failed to push request %p: %s\n",
					   req, fi_strerror(-ret));
			}

			fi_rc = -FI_EAGAIN;
			break;
		} else {
			SSTMACX_INFO(FI_LOG_EP_DATA,
				  "Request processed: %p\n", req);
		}
	}

	return fi_rc;
}

/******************************************************************************
 *
 * VC TX progress
 *
 *****************************************************************************/

/* Attempt to initiate a TX request.  If the TX queue is blocked (due to low
 * resources or a FI_FENCE request), schedule the request to be sent later.
 *
 * Note: EP must be locked. */
extern "C" int _sstmacx_vc_queue_tx_req(struct sstmacx_fab_req *req)
{
	int rc = FI_SUCCESS, queue_tx = 0;
	struct sstmacx_vc *vc = req->vc;
	struct sstmacx_fid_ep *ep = req->sstmacx_ep;
	struct sstmacx_fab_req *more_req;
	int connected;
	struct slist_entry *sle;

	/* Check if there is an outstanding fi_more chain to initiate */
	if ((!(req->flags & FI_MORE)) && (!(slist_empty(&ep->more_write)) ||
		!(slist_empty(&ep->more_read)))) {
		if (!slist_empty(&ep->more_write)) {
			sle = ep->more_write.head;
			more_req = container_of(sle, struct sstmacx_fab_req,
						rma.sle);
			SSTMACX_DEBUG(FI_LOG_EP_DATA, "FI_MORE: got fab_request "
					"from more_write. Queuing Request\n");
			_sstmacx_vc_queue_tx_req(more_req);
			slist_init(&ep->more_write);
		}
		if (!slist_empty(&ep->more_read)) {
			sle = ep->more_read.head;
			more_req = container_of(sle, struct sstmacx_fab_req,
						rma.sle);
			SSTMACX_DEBUG(FI_LOG_EP_DATA, "FI_MORE: got fab_request "
					"from more_read. Queuing Request\n");
			_sstmacx_vc_queue_tx_req(more_req);
			slist_init(&ep->more_read);
		}
	}

	if (req->flags & FI_TRIGGER) {
		rc = _sstmacx_trigger_queue_req(req);

		/* FI_SUCCESS means the request was queued to wait for the
		 * trigger condition. */
		if (rc == FI_SUCCESS)
			return FI_SUCCESS;
	}

	connected = (vc->conn_state == SSTMACX_VC_CONNECTED);

	if ((req->flags & FI_FENCE) && ofi_atomic_get32(&vc->outstanding_tx_reqs)) {
		/* Fence request must be queued until all outstanding TX
		 * requests are completed.  Subsequent requests will be queued
		 * due to non-empty tx_queue. */
		queue_tx = 1;
		SSTMACX_DEBUG(FI_LOG_EP_DATA,
			  "Queued FI_FENCE request (%p) on VC\n",
			  req);
	} else if (connected && dlist_empty(&vc->tx_queue)) {
		ofi_atomic_inc32(&vc->outstanding_tx_reqs);

		/* try to initiate request */
		rc = req->work_fn(req);
		if (rc == FI_SUCCESS) {
			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "TX request processed: %p (OTX: %d)\n",
				  req, ofi_atomic_get32(&vc->outstanding_tx_reqs));
		} else if (rc != -FI_ECANCELED) {
			ofi_atomic_dec32(&vc->outstanding_tx_reqs);
			queue_tx = 1;
			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "Queued request (%p) on full VC\n",
				  req);
		}
	} else {
		queue_tx = 1;
		SSTMACX_DEBUG(FI_LOG_EP_DATA,
			  "Queued request (%p) on busy VC\n",
			  req);
	}

	if (OFI_UNLIKELY(queue_tx)) {
		dlist_insert_tail(&req->dlist, &vc->tx_queue);
		_sstmacx_vc_tx_schedule(vc);
	}

	return FI_SUCCESS;
}

/* Push TX requests queued on the VC.
 *
 * Note: EP must be locked. */
static int __sstmacx_vc_push_tx_reqs(struct sstmacx_vc *vc)
{
	int ret, fi_rc = FI_SUCCESS;
	struct sstmacx_fab_req *req;

	req = dlist_first_entry(&vc->tx_queue, struct sstmacx_fab_req, dlist);
	while (req) {
		if ((req->flags & FI_FENCE) &&
		    ofi_atomic_get32(&vc->outstanding_tx_reqs)) {
			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "TX request queue stalled on FI_FENCE request: %p (%d)\n",
				  req, ofi_atomic_get32(&vc->outstanding_tx_reqs));
			/* Success is returned to allow processing of more VCs.
			 * This VC will be rescheduled when the fence request
			 * is completed. */
			break;
		}

		ofi_atomic_inc32(&vc->outstanding_tx_reqs);
		dlist_remove_init(&req->dlist);

		ret = req->work_fn(req);
		if (ret == FI_SUCCESS) {
			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "TX request processed: %p (OTX: %d)\n",
				  req, ofi_atomic_get32(&vc->outstanding_tx_reqs));
		} else if (ret != -FI_ECANCELED) {
			/* Work failed.  Reschedule to put this VC
			 * back on the end of the list and return
			 * -FI_EAGAIN. */

			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "Failed to push TX request %p: %s\n",
				  req, fi_strerror(-ret));
			fi_rc = -FI_EAGAIN;

			/* FI_ENOSPC is reserved to indicate a lack of
			 * TXDs, which are shared by all VCs on the
			 * NIC.  The other likely error is FI_EAGAIN
			 * due to a lack of SMSG credits. */

			if ((ret != -FI_ENOSPC) && (ret != -FI_EAGAIN)) {
				/* TODO report error? */
				SSTMACX_WARN(FI_LOG_EP_DATA,
					  "Failed to push TX request %p: %s\n",
					  req, fi_strerror(-ret));
			}

			dlist_insert_head(&req->dlist, &vc->tx_queue);
			ofi_atomic_dec32(&vc->outstanding_tx_reqs);

			/* _sstmacx_vc_tx_schedule() must come after the request
			 * is inserted into the VC's tx_queue. */
			_sstmacx_vc_tx_schedule(vc);
			break;

		}

		req = dlist_first_entry(&vc->tx_queue,
					struct sstmacx_fab_req,
					dlist);
	}

	return fi_rc;
}

/* Return next VC needing progress on the NIC. */
static struct sstmacx_vc *__sstmacx_nic_next_pending_vc(struct sstmacx_nic *nic)
{
	struct sstmacx_vc *vc = NULL;

	COND_ACQUIRE(nic->requires_lock, &nic->prog_vcs_lock);
	vc = dlist_first_entry(&nic->prog_vcs, struct sstmacx_vc, prog_list);
	if (vc)
		dlist_remove_init(&vc->prog_list);
	COND_RELEASE(nic->requires_lock, &nic->prog_vcs_lock);

	if (vc) {
		SSTMACX_INFO(FI_LOG_EP_CTRL, "Dequeued progress VC (%p)\n", vc);
		_sstmacx_clear_bit(&vc->flags, SSTMACX_VC_FLAG_SCHEDULED);
	}

	return vc;
}

extern "C" int _sstmacx_vc_progress(struct sstmacx_vc *vc)
{
	int ret, ret_tx;

	ret = __sstmacx_vc_rx_progress(vc);
	if (ret != FI_SUCCESS)
		SSTMACX_DEBUG(FI_LOG_EP_CTRL,
			   "__sstmacx_vc_rx_progress failed: %d\n", ret);

	ret = __sstmacx_vc_push_work_reqs(vc);
	if (ret != FI_SUCCESS)
		SSTMACX_DEBUG(FI_LOG_EP_CTRL,
			   "__sstmacx_vc_push_work_reqs failed: %d\n", ret);

	ret_tx = __sstmacx_vc_push_tx_reqs(vc);
	if (ret != FI_SUCCESS)
		SSTMACX_DEBUG(FI_LOG_EP_CTRL,
			   "__sstmacx_vc_push_tx_reqs failed: %d\n", ret);

	return ret_tx;
}

/* Progress all NIC VCs needing work. */
extern "C" int _sstmacx_vc_nic_progress(struct sstmacx_nic *nic)
{
	struct sstmacx_vc *vc;
	int ret;

	/*
	 * we can't just spin and spin in this loop because
	 * none of the functions invoked below end up dequeuing
	 * SSTMAC CQE's and subsequently freeing up TX descriptors.
	 * So, if the tx reqs routine returns -FI_EAGAIN, break out.
	 */
	while ((vc = __sstmacx_nic_next_pending_vc(nic))) {
		COND_ACQUIRE(vc->ep->requires_lock, &vc->ep->vc_lock);

		if (vc->conn_state == SSTMACX_VC_CONNECTED) {
			ret = _sstmacx_vc_progress(vc);
		}

		COND_RELEASE(vc->ep->requires_lock, &vc->ep->vc_lock);

		if (ret != FI_SUCCESS)
			break;
	}

	return FI_SUCCESS;
}

/* Schedule VC for progress.
 *
 * Note: EP must be locked.
 * TODO: Better implementation for rx/work/tx VC scheduling. */
extern "C" int _sstmacx_vc_schedule(struct sstmacx_vc *vc)
{
	struct sstmacx_nic *nic = vc->ep->nic;

	if (!_sstmacx_test_and_set_bit(&vc->flags, SSTMACX_VC_FLAG_SCHEDULED)) {
		COND_ACQUIRE(nic->requires_lock, &nic->prog_vcs_lock);
		dlist_insert_tail(&vc->prog_list, &nic->prog_vcs);
		COND_RELEASE(nic->requires_lock, &nic->prog_vcs_lock);
		SSTMACX_DEBUG(FI_LOG_EP_CTRL, "Scheduled VC (%p)\n", vc);
	}

	return FI_SUCCESS;
}

/* Schedule the VC for RX progress. */
extern "C" int _sstmacx_vc_rx_schedule(struct sstmacx_vc *vc)
{
	return _sstmacx_vc_schedule(vc);
}

/* Schedule the VC for work progress. */
static int __sstmacx_vc_work_schedule(struct sstmacx_vc *vc)
{
	return _sstmacx_vc_schedule(vc);
}

/* Schedule the VC for TX progress. */
extern "C" int _sstmacx_vc_tx_schedule(struct sstmacx_vc *vc)
{
	return _sstmacx_vc_schedule(vc);
}

/* For a newly scheduled VC.  Do any queued work now that the connection is
 * complete.
 *
 * Note: EP must be locked. */
extern "C" int _sstmacx_vc_sched_new_conn(struct sstmacx_vc *vc)
{
	_sstmacx_vc_schedule(vc);
	return _sstmacx_vc_progress(vc);
}

/* Look up an EP's VC using fi_addr_t.
 *
 * Note: EP must be locked. */
extern "C" int _sstmacx_vc_ep_get_vc(struct sstmacx_fid_ep *ep, fi_addr_t dest_addr,
		       struct sstmacx_vc **vc_ptr)
{
	int ret;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (SSTMACX_EP_RDM_DGM(ep->type)) {
		ret = __sstmacx_vc_get_vc_by_fi_addr(ep, dest_addr, vc_ptr);
		if (OFI_UNLIKELY(ret != FI_SUCCESS)) {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "__sstmacx_vc_get_vc_by_fi_addr returned %s\n",
				   fi_strerror(-ret));
			return ret;
		}
	} else if (ep->type == FI_EP_MSG) {
		if (SSTMACX_EP_CONNECTED(ep)) {
			*vc_ptr = ep->vc;
		} else {
			return -FI_EINVAL;
		}
	} else {
		SSTMACX_WARN(FI_LOG_EP_DATA, "Invalid endpoint type: %d\n",
			  ep->type);
		return -FI_EINVAL;
	}

	return FI_SUCCESS;
}

fi_addr_t _sstmacx_vc_peer_fi_addr(struct sstmacx_vc *vc)
{
	int rc;

	/* If FI_SOURCE capability was requested, do a reverse lookup of a VC's
	 * FI address once.  Skip translation on connected EPs (no AV). */
	if (vc->ep->av && vc->peer_fi_addr == FI_ADDR_NOTAVAIL) {
		rc = _sstmacx_av_reverse_lookup(vc->ep->av,
					     vc->peer_addr,
					     &vc->peer_fi_addr);
		if (rc != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "_sstmacx_av_reverse_lookup() failed: %d\n",
				  rc);
	}

	return vc->peer_fi_addr;
}

extern "C" int _sstmacx_vc_cm_init(struct sstmacx_cm_nic *cm_nic)
{
	int ret = FI_SUCCESS;
	sstmacx_cm_nic_rcv_cb_func *ofunc = NULL;
	struct sstmacx_nic *nic = NULL;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	nic = cm_nic->nic;
	assert(nic != NULL);

	COND_ACQUIRE(nic->requires_lock, &nic->lock);
	ret = _sstmacx_cm_nic_reg_recv_fn(cm_nic,
					__sstmacx_vc_recv_fn,
					&ofunc);
	if ((ofunc != NULL) &&
	    (ofunc != __sstmacx_vc_recv_fn)) {
		SSTMACX_WARN(FI_LOG_EP_DATA, "callback reg failed: %s\n",
			  fi_strerror(-ret));
	}

	COND_RELEASE(nic->requires_lock, &nic->lock);

	return ret;
}


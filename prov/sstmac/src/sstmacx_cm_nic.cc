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
 * Copyright (c) 2015-2017 Los Alamos National Security, LLC.
 *                         All rights reserved.
 * Copyright (c) 2015-2017 Cray Inc. All rights reserved.
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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <assert.h>

#include "sstmacx.h"
#include "sstmacx_datagram.h"
#include "sstmacx_cm_nic.h"
#include "sstmacx_cm.h"
#include "sstmacx_nic.h"
#include "sstmacx_hashtable.h"


#define SSTMACX_CM_NIC_BND_TAG (100)
#define SSTMACX_CM_NIC_WC_TAG (99)

DLIST_HEAD(sstmacx_cm_nic_list);
pthread_mutex_t sstmacx_cm_nic_list_lock = PTHREAD_MUTEX_INITIALIZER;

/*******************************************************************************
 * Helper functions
 ******************************************************************************/

static void __dgram_set_tag(struct sstmacx_datagram *d, uint8_t tag)
{

	_sstmacx_dgram_pack_buf(d, SSTMACX_DGRAM_IN_BUF,
				    &tag, sizeof(uint8_t));
}

/*
 * we unpack the out tag instead of getting it
 * since we need to pass the partially advanced
 * out buf to the receive callback function
 * associated with the cm_nic instance.
 */
static void __dgram_unpack_out_tag(struct sstmacx_datagram *d, uint8_t *tag)
{

	_sstmacx_dgram_rewind_buf(d, SSTMACX_DGRAM_OUT_BUF);
	_sstmacx_dgram_unpack_buf(d, SSTMACX_DGRAM_OUT_BUF,
				      tag, sizeof(uint8_t));
}

static void __dgram_get_in_tag(struct sstmacx_datagram *d, uint8_t *tag)
{

	_sstmacx_dgram_rewind_buf(d, SSTMACX_DGRAM_IN_BUF);
	_sstmacx_dgram_unpack_buf(d, SSTMACX_DGRAM_IN_BUF,
				      tag, sizeof(uint8_t));
	_sstmacx_dgram_rewind_buf(d, SSTMACX_DGRAM_IN_BUF);

}

static int __process_dgram_w_error(struct sstmacx_cm_nic *cm_nic,
				   struct sstmacx_datagram *dgram,
				   struct sstmacx_address peer_address,
				   sstmac_post_state_t state)
{
	return -FI_ENOSYS;
}

static int __process_datagram(struct sstmacx_datagram *dgram,
				 struct sstmacx_address peer_address,
				 sstmac_post_state_t state)
{
	int ret = FI_SUCCESS;
	struct sstmacx_cm_nic *cm_nic = NULL;
	uint8_t in_tag = 0, out_tag = 0;
	char rcv_buf[SSTMACX_CM_NIC_MAX_MSG_SIZE];

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	cm_nic = (struct sstmacx_cm_nic *)dgram->cache;
	if (cm_nic == NULL) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			"process_datagram, null cache\n");
		goto err;
	}

	if (state != SSTMAC_POST_COMPLETED) {
		ret = __process_dgram_w_error(cm_nic,
					      dgram,
					      peer_address,
					      state);
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			"process_datagram bad post state %d\n", state);
		goto err;
	}

	__dgram_get_in_tag(dgram, &in_tag);
	if ((in_tag != SSTMACX_CM_NIC_BND_TAG) &&
		(in_tag != SSTMACX_CM_NIC_WC_TAG)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			"datagram with unknown in tag %d\n", in_tag);
		goto err;
	}

	 __dgram_unpack_out_tag(dgram, &out_tag);
	if ((out_tag != SSTMACX_CM_NIC_BND_TAG) &&
		(out_tag != SSTMACX_CM_NIC_WC_TAG)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			"datagram with unknown out tag %d\n", out_tag);
		goto err;
	}

	/*
	 * if out buf actually has data, call consumer's
	 * receive callback
	 */

	if (out_tag == SSTMACX_CM_NIC_BND_TAG) {
		_sstmacx_dgram_unpack_buf(dgram,
					SSTMACX_DGRAM_OUT_BUF,
					rcv_buf,
					SSTMACX_CM_NIC_MAX_MSG_SIZE);
		ret = cm_nic->rcv_cb_fn(cm_nic,
					rcv_buf,
					peer_address);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				"cm_nic->rcv_cb_fn returned %s\n",
				fi_strerror(-ret));
			goto err;
		}

		ret = _sstmacx_cm_nic_progress(cm_nic);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "_sstmacx_cm_nic_progress returned %s\n",
				  fi_strerror(-ret));
	}

	/*
	 * if we are processing a WC datagram, repost, otherwise
	 * just put back on the freelist.
	 */
	if (in_tag == SSTMACX_CM_NIC_WC_TAG) {
		dgram->callback_fn = __process_datagram;
		dgram->cache = cm_nic;
		 __dgram_set_tag(dgram, in_tag);
		ret = _sstmacx_dgram_wc_post(dgram);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				"_sstmacx_dgram_wc_post returned %s\n",
				fi_strerror(-ret));
			goto err;
		}
	} else {
		ret  = _sstmacx_dgram_free(dgram);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				"_sstmacx_dgram_free returned %s\n",
				fi_strerror(-ret));
	}

	return ret;

err:
	if (in_tag == SSTMACX_CM_NIC_BND_TAG)
		_sstmacx_dgram_free(dgram);
	return ret;
}

static bool __sstmacx_cm_nic_timeout_needed(void *data)
{
	struct sstmacx_cm_nic *cm_nic = (struct sstmacx_cm_nic *)data;
	return _sstmacx_cm_nic_need_progress(cm_nic);
}

static void __sstmacx_cm_nic_timeout_progress(void *data)
{
	int ret;
	struct sstmacx_cm_nic *cm_nic = (struct sstmacx_cm_nic *)data;
	ret = _sstmacx_cm_nic_progress(cm_nic);
	if (ret != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			"_sstmacx_cm_nic_progress returned %s\n",
			fi_strerror(-ret));
}


/*******************************************************************************
 * Internal API functions
 ******************************************************************************/

extern "C" int _sstmacx_cm_nic_create_cdm_id(struct sstmacx_fid_domain *domain, uint32_t *id)
{
	uint32_t cdm_id;
	int v;

	if (*id != SSTMACX_CREATE_CDM_ID) {
		return FI_SUCCESS;
	}

	/*
	 * generate a cdm_id, use the 16 LSB of base_id from domain
	 * with 16 MSBs being obtained from atomic increment of
	 * a local variable.
	 */

	v = ofi_atomic_inc32(&sstmacx_id_counter);

	cdm_id = ((domain->cdm_id_seed & 0xFFF) << 12) | v;
	*id = cdm_id;
	return FI_SUCCESS;
}

/**
 * This function will return a block of id's starting at id through nids
 *
 * @param domain  sstmacx domain
 * @param nids    number of id's
 * @param id      if -1 return an id based on the counter and seed
 */
extern "C" int _sstmacx_get_new_cdm_id_set(struct sstmacx_fid_domain *domain, int nids,
			     uint32_t *id)
{
	uint32_t cdm_id;
	int v;

	if (*id == -1) {
		v = ofi_atomic_add32(&sstmacx_id_counter, nids);
		cdm_id = ((domain->cdm_id_seed & 0xFFF) << 12) | v;
		*id = cdm_id;
	} else {
		/*
		 * asking for a block starting at a chosen base
		 * TODO: sanity check that requested base is reasonable
		 */
		if (*id <= ofi_atomic_get32(&sstmacx_id_counter))
			return -FI_ENOSPC;
		ofi_atomic_set32(&sstmacx_id_counter, (*(int *)id + nids));
	}
	return FI_SUCCESS;
}

extern "C" int _sstmacx_cm_nic_progress(void *arg)
{
	struct sstmacx_cm_nic *cm_nic = (struct sstmacx_cm_nic *)arg;
	int ret = FI_SUCCESS;
	int complete;
	struct sstmacx_work_req *p = NULL;

	/*
	 * if we're doing FI_PROGRESS_MANUAL,
	 * see what's going on inside ksstmac's datagram
	 * box...
	 */

	if (cm_nic->ctrl_progress == FI_PROGRESS_MANUAL) {
		++cm_nic->poll_cnt;
		if (((cm_nic->poll_cnt % 512) == 0)  ||
			!dlist_empty(&cm_nic->cm_nic_wq)) {
			ret = _sstmacx_dgram_poll(cm_nic->dgram_hndl,
						  SSTMACX_DGRAM_NOBLOCK);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					"_sstmacx_dgram_poll returned %s\n",
					  fi_strerror(-ret));
					goto err;
			}
		}
	}

	/*
	 * do a quick check if queue doesn't have anything yet,
	 * don't need this to be atomic
	 */

check_again:
	if (dlist_empty(&cm_nic->cm_nic_wq))
		return ret;

	/*
	 * okay, stuff to do, lock work queue,
	 * dequeue head, unlock, process work element,
	 * if it doesn't compete, put back at the tail
	 * of the queue.
	 */

	fastlock_acquire(&cm_nic->wq_lock);
	p = dlist_first_entry(&cm_nic->cm_nic_wq, struct sstmacx_work_req,
			      list);
	if (p == NULL) {
		fastlock_release(&cm_nic->wq_lock);
		return ret;
	}

	dlist_remove_init(&p->list);
	fastlock_release(&cm_nic->wq_lock);

	assert(p->progress_fn);

	ret = p->progress_fn(p->data, &complete);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "dgram prog fn returned %s\n",
			  fi_strerror(-ret));
	}

	if (complete == 1) {
		if (p->completer_fn) {
			ret = p->completer_fn(p->completer_data);
			free(p);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "dgram completer fn returned %s\n",
					  fi_strerror(-ret));
				goto err;
			}
		} else {
			free(p);
		}
		goto check_again;
	} else {
		fastlock_acquire(&cm_nic->wq_lock);
		dlist_insert_before(&p->list, &cm_nic->cm_nic_wq);
		fastlock_release(&cm_nic->wq_lock);
	}

err:
	return ret;
}

static void  __cm_nic_destruct(void *obj)
{
	int ret;
	struct sstmacx_cm_nic *cm_nic = (struct sstmacx_cm_nic *)obj;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	pthread_mutex_lock(&sstmacx_cm_nic_list_lock);
	dlist_remove(&cm_nic->cm_nic_list);
	pthread_mutex_unlock(&sstmacx_cm_nic_list_lock);

	if (cm_nic->dgram_hndl != NULL) {
		ret = _sstmacx_dgram_hndl_free(cm_nic->dgram_hndl);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "sstmacx_dgram_hndl_free returned %d\n",
				  ret);
	}

	if (cm_nic->addr_to_ep_ht != NULL) {
		ret = _sstmacx_ht_destroy(cm_nic->addr_to_ep_ht);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "sstmacx_ht_destroy returned %d\n",
				  ret);
		free(cm_nic->addr_to_ep_ht);
		cm_nic->addr_to_ep_ht = NULL;
	}

	if (cm_nic->nic != NULL) {
		_sstmacx_ref_put(cm_nic->nic);
		cm_nic->nic = NULL;
	}

	cm_nic->domain->cm_nic = NULL;
	free(cm_nic);
}

static int __sstmacx_cm_nic_intra_progress_fn(void *data, int *complete_ptr)
{
	struct sstmacx_datagram *dgram;
	struct sstmacx_cm_nic *cm_nic;
	int ret;

	SSTMACX_INFO(FI_LOG_EP_CTRL, "\n");

	dgram = (struct sstmacx_datagram *)data;
	cm_nic = (struct sstmacx_cm_nic *)dgram->cache;
	ret = __process_datagram(dgram,
				 cm_nic->my_name.sstmacx_addr,
				 SSTMAC_POST_COMPLETED);
	if (ret == FI_SUCCESS) {
		SSTMACX_INFO(FI_LOG_EP_CTRL, "Intra-CM NIC dgram completed\n");
		*complete_ptr = 1;
	}

	return FI_SUCCESS;
}

extern "C" int _sstmacx_cm_nic_send(struct sstmacx_cm_nic *cm_nic,
		      char *sbuf, size_t len,
		      struct sstmacx_address target_addr)
{
	int ret = FI_SUCCESS;
	struct sstmacx_datagram *dgram = NULL;
	ssize_t  __attribute__((unused)) plen;
	uint8_t tag;
	struct sstmacx_work_req *work_req;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if ((cm_nic == NULL) || (sbuf == NULL))
		return -FI_EINVAL;

	if (len > SSTMAC_DATAGRAM_MAXSIZE)
		return -FI_ENOSPC;

	ret = _sstmacx_dgram_alloc(cm_nic->dgram_hndl,
				SSTMACX_DGRAM_BND,
				&dgram);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "_sstmacx_dgram_alloc returned %s\n",
			  fi_strerror(-ret));
		goto exit;
	}

	dgram->target_addr = target_addr;
	dgram->callback_fn = __process_datagram;
	dgram->cache = cm_nic;

	tag = SSTMACX_CM_NIC_BND_TAG;
	 __dgram_set_tag(dgram, tag);

	plen = _sstmacx_dgram_pack_buf(dgram, SSTMACX_DGRAM_IN_BUF,
				   sbuf, len);
	assert (plen == len);

	/* If connecting with the same CM NIC, skip datagram exchange.  The
	 * caller could be holding an endpoint lock, so schedule connection
	 * completion for later. */
	if (SSTMACX_ADDR_EQUAL(target_addr, cm_nic->my_name.sstmacx_addr)) {
		char tmp_buf[SSTMACX_CM_NIC_MAX_MSG_SIZE];

		/* Pack output buffer with input data. */
		_sstmacx_dgram_unpack_buf(dgram, SSTMACX_DGRAM_IN_BUF, tmp_buf,
				       SSTMACX_CM_NIC_MAX_MSG_SIZE);
		_sstmacx_dgram_pack_buf(dgram, SSTMACX_DGRAM_OUT_BUF, tmp_buf,
				       SSTMACX_CM_NIC_MAX_MSG_SIZE);

		work_req = calloc(1, sizeof(*work_req));
		if (work_req == NULL) {
			_sstmacx_dgram_free(dgram);
			return -FI_ENOMEM;
		}

		work_req->progress_fn = __sstmacx_cm_nic_intra_progress_fn;
		work_req->data = dgram;
		work_req->completer_fn = NULL;

		fastlock_acquire(&cm_nic->wq_lock);
		dlist_insert_before(&work_req->list, &cm_nic->cm_nic_wq);
		fastlock_release(&cm_nic->wq_lock);

		SSTMACX_INFO(FI_LOG_EP_CTRL, "Initiated intra-CM NIC connect\n");
	} else {
		ret = _sstmacx_dgram_bnd_post(dgram);
		if (ret == -FI_EBUSY) {
			ret = -FI_EAGAIN;
			_sstmacx_dgram_free(dgram);
		}
	}

exit:
	return ret;
}

extern "C" int _sstmacx_cm_nic_reg_recv_fn(struct sstmacx_cm_nic *cm_nic,
			     sstmacx_cm_nic_rcv_cb_func *recv_fn,
			     sstmacx_cm_nic_rcv_cb_func **prev_fn)
{
	int ret = FI_SUCCESS;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (cm_nic == NULL)
		return -FI_EINVAL;

	*prev_fn = cm_nic->rcv_cb_fn;
	cm_nic->rcv_cb_fn = recv_fn;

	return ret;
}

extern "C" int _sstmacx_cm_nic_enable(struct sstmacx_cm_nic *cm_nic)
{
	int i, ret = FI_SUCCESS;
	struct sstmacx_fid_fabric *fabric;
	struct sstmacx_datagram *dg_ptr;
	uint8_t tag = SSTMACX_CM_NIC_WC_TAG;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (cm_nic == NULL)
		return -FI_EINVAL;

	if (cm_nic->domain == NULL) {
		SSTMACX_FATAL(FI_LOG_EP_CTRL, "domain is NULL\n");
	}

	if (cm_nic->domain->fabric == NULL) {
		SSTMACX_FATAL(FI_LOG_EP_CTRL, "fabric is NULL\n");
	}

	fabric = cm_nic->domain->fabric;

	assert(cm_nic->dgram_hndl != NULL);

	for (i = 0; i < fabric->n_wc_dgrams; i++) {
		ret = _sstmacx_dgram_alloc(cm_nic->dgram_hndl, SSTMACX_DGRAM_WC,
					&dg_ptr);

		/*
 		 * wildcards may already be posted to the cm_nic,
 		 * so just break if -FI_EAGAIN is returned by
 		 * _sstmacx_dgram_alloc
 		 */

		if (ret == -FI_EAGAIN) {
			ret = FI_SUCCESS;
			break;
		}

		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
			     "_sstmacx_dgram_alloc call returned %d\n", ret);
				goto err;
		}

		dg_ptr->callback_fn = __process_datagram;
		dg_ptr->cache = cm_nic;
		 __dgram_set_tag(dg_ptr, tag);

		ret = _sstmacx_dgram_wc_post(dg_ptr);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				"_sstmacx_dgram_wc_post returned %d\n", ret);
			_sstmacx_dgram_free(dg_ptr);
			goto err;
		}
	}

	/*
	 * TODO: better cleanup in error case
	 */
err:
	return ret;
}

extern "C" int _sstmacx_cm_nic_free(struct sstmacx_cm_nic *cm_nic)
{

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (cm_nic == NULL)
		return -FI_EINVAL;

	_sstmacx_ref_put(cm_nic);

	return FI_SUCCESS;
}

extern "C" int _sstmacx_cm_nic_alloc(struct sstmacx_fid_domain *domain,
		       struct fi_info *info,
		       uint32_t cdm_id,
			   struct sstmacx_auth_key *auth_key,
		       struct sstmacx_cm_nic **cm_nic_ptr)
{
	int ret = FI_SUCCESS;
	struct sstmacx_cm_nic *cm_nic = NULL;
	sstmacx_hashtable_attr_t sstmacx_ht_attr = {0};
	uint32_t name_type = SSTMACX_EPN_TYPE_UNBOUND;
	struct sstmacx_nic_attr nic_attr = {0};
	struct sstmacx_ep_name ep_name;
	struct sstmacx_dgram_hndl_attr dgram_hndl_attr = {0};
	struct sstmacx_dgram_hndl_attr *dgram_hndl_attr_ptr = NULL;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	*cm_nic_ptr = NULL;

	/*
	 * if app has specified a src_addr in the info
	 * argument and length matches that for sstmacx_ep_name
	 * we must allocate a cm_nic, otherwise we first
	 * check to see if there is a cm_nic already for this domain
	 * and just use it.
	 */

	if (info->src_addr) {
		/*TODO (optimization): strchr to name_type and strtol */
		_sstmacx_get_ep_name(info->src_addr, 0, &ep_name, domain);
		name_type = ep_name.name_type;
	}

	SSTMACX_INFO(FI_LOG_EP_CTRL, "creating cm_nic for %u/0x%x/%u\n",
			auth_key->ptag, auth_key->cookie, cdm_id);

	cm_nic = (struct sstmacx_cm_nic *)calloc(1, sizeof(*cm_nic));
	if (cm_nic == NULL) {
		ret = -FI_ENOMEM;
		goto err;
	}

	/*
	 * we have to force allocation of a new nic since we want
	 * an a particular cdm id
	 */
	nic_attr.must_alloc = true;
	nic_attr.use_cdm_id = true;
	nic_attr.cdm_id = cdm_id;
	nic_attr.auth_key = auth_key;

	ret = sstmacx_nic_alloc(domain, &nic_attr, &cm_nic->nic);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "sstmacx_nic_alloc returned %s\n",
			  fi_strerror(-ret));
		goto err;
	}

	cm_nic->my_name.sstmacx_addr.cdm_id = cdm_id;
	cm_nic->ptag = auth_key->ptag;
	cm_nic->my_name.cookie = auth_key->cookie;
	cm_nic->my_name.sstmacx_addr.device_addr = cm_nic->nic->device_addr;
	cm_nic->domain = domain;
	cm_nic->ctrl_progress = domain->control_progress;
	cm_nic->my_name.name_type = name_type;
	cm_nic->poll_cnt = 0;
	fastlock_init(&cm_nic->wq_lock);
	dlist_init(&cm_nic->cm_nic_wq);

	/*
	 * prep the cm nic's dgram component
	 */
	if (domain->control_progress == FI_PROGRESS_AUTO) {
		dgram_hndl_attr.timeout_needed = __sstmacx_cm_nic_timeout_needed;
		dgram_hndl_attr.timeout_progress = __sstmacx_cm_nic_timeout_progress;
		dgram_hndl_attr.timeout_data = (void *)cm_nic;
		dgram_hndl_attr.timeout = domain->params.dgram_progress_timeout;
		dgram_hndl_attr_ptr = &dgram_hndl_attr;
	};

	ret = _sstmacx_dgram_hndl_alloc(cm_nic,
				     domain->control_progress,
				     dgram_hndl_attr_ptr,
				     &cm_nic->dgram_hndl);
	if (ret != FI_SUCCESS)
		goto err;

	/*
	 * allocate hash table for translating ep addresses
	 * to ep's.
	 * This table will not be large - how many FI_EP_RDM ep's
	 * will an app create using one domain?, nor in the critical path
	 * so just use defaults.
	 */
	cm_nic->addr_to_ep_ht = calloc(1, sizeof(struct sstmacx_hashtable));
	if (cm_nic->addr_to_ep_ht == NULL)
		goto err;

	sstmacx_ht_attr.ht_initial_size = 64;
	sstmacx_ht_attr.ht_maximum_size = 1024;
	sstmacx_ht_attr.ht_increase_step = 2;
	sstmacx_ht_attr.ht_increase_type = SSTMACX_HT_INCREASE_MULT;
	sstmacx_ht_attr.ht_collision_thresh = 500;
	sstmacx_ht_attr.ht_hash_seed = 0xdeadbeefbeefdead;
	sstmacx_ht_attr.ht_internal_locking = 1;
	sstmacx_ht_attr.destructor = NULL;

	ret = _sstmacx_ht_init(cm_nic->addr_to_ep_ht, &sstmacx_ht_attr);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "sstmacx_ht_init returned %s\n",
			  fi_strerror(-ret));
		goto err;
	}

	_sstmacx_ref_init(&cm_nic->ref_cnt, 1, __cm_nic_destruct);

	*cm_nic_ptr = cm_nic;

	pthread_mutex_lock(&sstmacx_cm_nic_list_lock);
	dlist_insert_tail(&cm_nic->cm_nic_list, &sstmacx_cm_nic_list);
	pthread_mutex_unlock(&sstmacx_cm_nic_list_lock);

	return ret;

err:
	if (cm_nic->dgram_hndl)
		_sstmacx_dgram_hndl_free(cm_nic->dgram_hndl);

	if (cm_nic->nic)
		_sstmacx_nic_free(cm_nic->nic);

	if (cm_nic->addr_to_ep_ht) {
		_sstmacx_ht_destroy(cm_nic->addr_to_ep_ht);
		free(cm_nic->addr_to_ep_ht);
	}

	if (cm_nic != NULL)
		free(cm_nic);

	return ret;
}

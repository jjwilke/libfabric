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
 * Copyright (c) 2015-2018 Cray Inc. All rights reserved.
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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <signal.h>

#include "sstmacx.h"
#include "sstmacx_nic.h"
#include "sstmacx_cm_nic.h"
#include "sstmacx_vc.h"
#include "sstmacx_mbox_allocator.h"
#include "sstmacx_util.h"
#include "fi_ext_sstmac.h"

/*
 * TODO: make this a domain parameter
 */
#define SSTMACX_VC_FL_MIN_SIZE 128
#define SSTMACX_VC_FL_INIT_REFILL_SIZE 10

static extern "C" int sstmacx_nics_per_ptag[SSTMAC_PTAG_MAX];
struct dlist_entry sstmacx_nic_list_ptag[SSTMAC_PTAG_MAX];
DLIST_HEAD(sstmacx_nic_list);
pthread_mutex_t sstmacx_nic_list_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * globals
 */

uint32_t sstmacx_max_nics_per_ptag = SSTMACX_DEF_MAX_NICS_PER_PTAG;

/*
 * local variables
 */

static struct sstmacx_nic_attr default_attr = {
		.sstmac_cdm_hndl        = NULL,
		.sstmac_nic_hndl        = NULL
};

/*******************************************************************************
 * Helper functions.
 ******************************************************************************/

/*
 * this function is intended to be invoked as an argument to pthread_create,
 */
static void *__sstmacx_nic_prog_thread_fn(void *the_arg)
{
	int ret = FI_SUCCESS, prev_state;
	int retry = 0;
	uint32_t which;
	struct sstmacx_nic *nic = (struct sstmacx_nic *)the_arg;
	sigset_t  sigmask;
	sstmac_cq_handle_t cqv[2];
	sstmac_return_t status;
	sstmac_cq_entry_t cqe;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	/*
	 * temporarily disable cancelability while we set up
	 * some stuff
	 */

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prev_state);

	/*
	 * help out Cray core-spec, say we're not an app thread
	 * and can be run on core-spec cpus.
	 */

	ret = _sstmacx_task_is_not_app();
	if (ret)
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			"_sstmacx_task_is_not_app call returned %d\n",
			ret);

	/*
	 * block all signals, don't want this thread to catch
	 * signals that may be for app threads
	 */

	memset(&sigmask, 0, sizeof(sigset_t));
	ret = sigfillset(&sigmask);
	if (ret) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
		"sigfillset call returned %d\n", ret);
	} else {

		ret = pthread_sigmask(SIG_SETMASK,
					&sigmask, NULL);
		if (ret)
			SSTMACX_WARN(FI_LOG_EP_CTRL,
			"pthread_sigmask call returned %d\n", ret);
	}

	/*
	 * okay now we're ready to be cancelable.
	 */

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &prev_state);

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	cqv[0] = nic->tx_cq_blk;
	cqv[1] = nic->rx_cq_blk;

try_again:
	status = SSTMAC_CqVectorMonitor(cqv,
				     2,
				     -1,
				     &which);

	switch (status) {
	case SSTMAC_RC_SUCCESS:

		/*
		 * first dequeue RX CQEs
		 */
		if (nic->rx_cq_blk != nic->rx_cq && which == 1) {
			do {
				status = SSTMAC_CqGetEvent(nic->rx_cq_blk,
							&cqe);
			} while (status == SSTMAC_RC_SUCCESS);
		}
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prev_state);
		_sstmacx_nic_progress(nic);
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &prev_state);
		retry = 1;
		break;
	case SSTMAC_RC_TIMEOUT:
	case SSTMAC_RC_NOT_DONE:
        /* Invalid state indicates call interrupted by signal using various tools */
	case SSTMAC_RC_INVALID_STATE:
		retry = 1;
		break;
	case SSTMAC_RC_INVALID_PARAM:
	case SSTMAC_RC_ERROR_RESOURCE:
	case SSTMAC_RC_ERROR_NOMEM:
		retry = 0;
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "SSTMAC_CqGetEvent returned %s\n",
			  sstmac_err_str[status]);
		break;
	default:
		retry = 0;
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "SSTMAC_CqGetEvent returned unexpected code %s\n",
			  sstmac_err_str[status]);
		break;
	}

	if (retry)
		goto try_again;

	return NULL;
}

/*
 * setup memory registration for remote SSTMAC_PostCqWrite's to target
 */

static int __nic_setup_irq_cq(struct sstmacx_nic *nic)
{
	int ret = FI_SUCCESS;
	size_t len;
	sstmac_return_t status;
	int fd = -1;
	void *mmap_addr;
	int vmdh_index = -1;
	int flags = SSTMAC_MEM_READWRITE;
	struct sstmacx_auth_key *info;
	struct fi_sstmac_auth_key key;

	len = (size_t)sysconf(_SC_PAGESIZE);

	mmap_addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, fd, 0);
	if (mmap_addr == MAP_FAILED) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "mmap failed - %s\n",
			strerror(errno));
		ret = -errno;
		goto err;
	}

	nic->irq_mmap_addr = mmap_addr;
	nic->irq_mmap_len = len;

	/* On some systems, the page may not be zero'd from first use.
		 Memset it here */
	memset(mmap_addr, 0x0, len);

	if (nic->using_vmdh) {
		key.type = SSTMACX_AKT_RAW;
		key.raw.protection_key = nic->cookie;

		info = _sstmacx_auth_key_lookup((uint8_t *) &key, sizeof(key));
		assert(info);

		if (!nic->mdd_resources_set) {
			/* check to see if the ptag registration limit was set
			   yet or not -- becomes read-only after success */
			ret = _sstmacx_auth_key_enable(info);
			if (ret != FI_SUCCESS && ret != -FI_EBUSY) {
				SSTMACX_WARN(FI_LOG_DOMAIN,
					"failed to enable authorization key, "
					"unexpected error rc=%d\n", ret);
			}

			status = SSTMAC_SetMddResources(nic->sstmac_nic_hndl,
					(info->attr.prov_key_limit +
					info->attr.user_key_limit));
			if (status != SSTMAC_RC_SUCCESS) {
				SSTMACX_FATAL(FI_LOG_DOMAIN,
					"failed to set MDD resources, rc=%d\n",
					status);
			}

			nic->mdd_resources_set = 1;
		}
		vmdh_index = _sstmacx_get_next_reserved_key(info);
		if (vmdh_index <= 0) {
			SSTMACX_FATAL(FI_LOG_DOMAIN,
				"failed to get next reserved key, "
				"rc=%d\n", vmdh_index);
		}

		flags |= SSTMAC_MEM_USE_VMDH;
	}

	status = SSTMAC_MemRegister(nic->sstmac_nic_hndl,
				(uint64_t) nic->irq_mmap_addr,
				len,
				nic->rx_cq_blk,
				flags,
				vmdh_index,
				 &nic->irq_mem_hndl);
	if (status != SSTMAC_RC_SUCCESS) {
		ret = sstmacxu_to_fi_errno(status);
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "SSTMAC_MemRegister returned %s\n",
			  sstmac_err_str[status]);
		goto err_w_mmap;
	}

#if 0
	fprintf(stderr,"registered ireq memhndl 0x%016lx 0x%016lx\n",
		nic->irq_mem_hndl.qword1,
		nic->irq_mem_hndl.qword2);
#endif


	return ret;

err_w_mmap:
	munmap(mmap_addr, len);
err:
	return ret;
}

/*
 * release resources previously set up for remote
 * SSTMAC_PostCqWrite's to target
 */
static int __nic_teardown_irq_cq(struct sstmacx_nic *nic)
{
	int ret = FI_SUCCESS;
	sstmac_return_t status;

	if (nic == NULL)
		return ret;

	if (nic->irq_mmap_addr == NULL)
		return ret;

	if ((nic->irq_mem_hndl.qword1) ||
		(nic->irq_mem_hndl.qword2)) {
		status = SSTMAC_MemDeregister(nic->sstmac_nic_hndl,
					  &nic->irq_mem_hndl);
		if (status != SSTMAC_RC_SUCCESS) {
			ret = sstmacxu_to_fi_errno(status);
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "SSTMAC_MemDeregister returned %s\n",
				  sstmac_err_str[status]);
		}
	}

	munmap(nic->irq_mmap_addr,
		nic->irq_mmap_len);
	return ret;
}


/*
 * place holder for better attributes checker
 */
static int __sstmacx_nic_check_attr_sanity(struct sstmacx_nic_attr *attr)
{
	return FI_SUCCESS;
}

static inline struct sstmacx_tx_descriptor *
__desc_lkup_by_id(struct sstmacx_nic *nic, int desc_id)
{
	struct sstmacx_tx_descriptor *tx_desc;

	assert((desc_id >= 0) && (desc_id <= nic->max_tx_desc_id));
	tx_desc = &nic->tx_desc_base[desc_id];
	return tx_desc;
}

static int __nic_rx_overrun(struct sstmacx_nic *nic)
{
	int i, max_id, ret;
	struct sstmacx_vc *vc;
	sstmac_return_t status;
	sstmac_cq_entry_t cqe;

	SSTMACX_WARN(FI_LOG_EP_DATA, "\n");

	/* clear out the CQ */
	/*
	 * TODO:  really need to process CQEs better for error reporting,
	 * etc.
	 */
	while ((status = SSTMAC_CqGetEvent(nic->rx_cq, &cqe)) == SSTMAC_RC_SUCCESS);
	assert(status == SSTMAC_RC_NOT_DONE);

	COND_ACQUIRE(nic->requires_lock, &nic->vc_id_lock);
	max_id = nic->vc_id_table_count;
	COND_RELEASE(nic->requires_lock, &nic->vc_id_lock);
	/*
	 * TODO: optimization would
	 * be to keep track of last time
	 * this happened and where smsg msgs.
	 * were found.
	 */
	for (i = 0; i < max_id; i++) {
		ret = _sstmacx_test_bit(&nic->vc_id_bitmap, i);
		if (ret) {
			vc = __sstmacx_nic_elem_by_rem_id(nic, i);
			ret = _sstmacx_vc_rx_schedule(vc);
			assert(ret == FI_SUCCESS);
		}
	}

	return FI_SUCCESS;
}

static int __process_rx_cqe(struct sstmacx_nic *nic, sstmac_cq_entry_t cqe)
{
	int ret = FI_SUCCESS, vc_id = 0;
	struct sstmacx_vc *vc;

	vc_id =  SSTMAC_CQ_GET_INST_ID(cqe);

	/*
	 * its possible this vc has been destroyed, so may get NULL
	 * back.
	 */

	vc = __sstmacx_nic_elem_by_rem_id(nic, vc_id);
	if (vc != NULL) {
		switch (vc->conn_state) {
		case SSTMACX_VC_CONNECTING:
			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "Scheduling VC for RX processing (%p)\n",
				  vc);
			ret = _sstmacx_vc_rx_schedule(vc);
			assert(ret == FI_SUCCESS);
			break;
		case SSTMACX_VC_CONNECTED:
			SSTMACX_DEBUG(FI_LOG_EP_DATA,
				  "Processing VC RX (%p)\n",
				  vc);
			ret = _sstmacx_vc_rx_schedule(vc);
			assert(ret == FI_SUCCESS);
			break;
		default:
			break;  /* VC not in a state for scheduling or
				   SMSG processing */
		}
	}

	return ret;
}

static int __nic_rx_progress(struct sstmacx_nic *nic)
{
	int ret = FI_SUCCESS;
	sstmac_return_t status = SSTMAC_RC_NOT_DONE;
	sstmac_cq_entry_t cqe;

	status = SSTMAC_CqTestEvent(nic->rx_cq);
	if (status == SSTMAC_RC_NOT_DONE)
		return FI_SUCCESS;

	COND_ACQUIRE(nic->requires_lock, &nic->lock);

	do {
		status = SSTMAC_CqGetEvent(nic->rx_cq, &cqe);
		if (OFI_UNLIKELY(status == SSTMAC_RC_NOT_DONE)) {
			ret = FI_SUCCESS;
			break;
		}

		if (OFI_LIKELY(status == SSTMAC_RC_SUCCESS)) {
			/* Find and schedule the associated VC. */
			ret = __process_rx_cqe(nic, cqe);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_DATA,
					  "process_rx_cqe() failed: %d\n",
					  ret);
			}
		} else if (status == SSTMAC_RC_ERROR_RESOURCE) {
			/* The remote CQ was overrun.  Events related to any VC
			 * could have been missed.  Schedule each VC to be sure
			 * all messages are processed. */
			assert(SSTMAC_CQ_OVERRUN(cqe));
			__nic_rx_overrun(nic);
		} else {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "SSTMAC_CqGetEvent returned %s\n",
				  sstmac_err_str[status]);
			ret = sstmacxu_to_fi_errno(status);
			break;
		}
	} while (1);

	COND_RELEASE(nic->requires_lock, &nic->lock);

	return ret;
}

void _sstmacx_nic_txd_err_inject(struct sstmacx_nic *nic,
			      struct sstmacx_tx_descriptor *txd)
{
	slist_insert_tail(&txd->err_list, &nic->err_txds);
}

static int __sstmacx_nic_txd_err_get(struct sstmacx_nic *nic,
				  struct sstmacx_tx_descriptor **txd)
{
	struct slist_entry *list_entry;
	struct sstmacx_tx_descriptor *txd_p;

	list_entry = slist_remove_head(&nic->err_txds);
	if (list_entry) {
		txd_p = container_of(list_entry,
				     struct sstmacx_tx_descriptor,
				     err_list);
		*txd = txd_p;
		return 1;
	}

	return 0;
}

static void __nic_get_completed_txd(struct sstmacx_nic *nic,
				   sstmac_cq_handle_t hw_cq,
				   struct sstmacx_tx_descriptor **txd,
				   sstmac_return_t *tx_status)
{
	sstmac_post_descriptor_t *sstmac_desc;
	struct sstmacx_tx_descriptor *txd_p = NULL;
	struct sstmacx_fab_req *req;
	sstmac_return_t status;
	int msg_id;
	sstmac_cq_entry_t cqe;
	uint32_t recov = 1;

	if (__sstmacx_nic_txd_err_get(nic, &txd_p)) {
		*txd = txd_p;
		*tx_status = SSTMAC_RC_TRANSACTION_ERROR;
		return;
	}

	status = SSTMAC_CqGetEvent(hw_cq, &cqe);
	if (status == SSTMAC_RC_NOT_DONE) {
		*txd = NULL;
		*tx_status = SSTMAC_RC_NOT_DONE;
		return;
	}

	assert(status == SSTMAC_RC_SUCCESS ||
	       status == SSTMAC_RC_TRANSACTION_ERROR);

	if (OFI_UNLIKELY(status == SSTMAC_RC_TRANSACTION_ERROR)) {
		status = SSTMAC_CqErrorRecoverable(cqe, &recov);
		if (status == SSTMAC_RC_SUCCESS) {
			if (!recov) {
				char ebuf[512];

				SSTMAC_CqErrorStr(cqe, ebuf, sizeof(ebuf));
				SSTMACX_WARN(FI_LOG_EP_DATA,
					  "CQ error status: %s\n",
					   ebuf);
			}
		} else {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				  "SSTMAC_CqErrorRecover returned: %s\n",
				   sstmac_err_str[status]);
			recov = 0;  /* assume something bad has happened */
		}
	}

	if (SSTMAC_CQ_GET_TYPE(cqe) == SSTMAC_CQ_EVENT_TYPE_POST) {
		status = SSTMAC_GetCompleted(hw_cq, cqe, &sstmac_desc);

		assert(status == SSTMAC_RC_SUCCESS ||
		       status == SSTMAC_RC_TRANSACTION_ERROR);

		txd_p = container_of(sstmac_desc,
				   struct sstmacx_tx_descriptor,
				   sstmac_desc);
	} else if (SSTMAC_CQ_GET_TYPE(cqe) == SSTMAC_CQ_EVENT_TYPE_SMSG) {
		msg_id = SSTMAC_CQ_GET_MSG_ID(cqe);
		txd_p = __desc_lkup_by_id(nic, msg_id);
	}

	if (OFI_UNLIKELY(txd_p == NULL))
		SSTMACX_FATAL(FI_LOG_EP_DATA, "Unexpected CQE: 0x%lx", cqe);

	/*
	 * set retry count on the request to max to force
	 * delivering error'd CQ event to application
	 */
	if (!recov) {
		status = SSTMAC_RC_TRANSACTION_ERROR;
		req = txd_p->req;
		if (req)
			req->tx_failures = UINT_MAX;
	}

	*tx_status = status;
	*txd = txd_p;

}

static int __nic_tx_progress(struct sstmacx_nic *nic, sstmac_cq_handle_t cq)
{
	int ret = FI_SUCCESS;
	sstmac_return_t tx_status;
	struct sstmacx_tx_descriptor *txd;

	do {
		txd = NULL;

		COND_ACQUIRE(nic->requires_lock, &nic->lock);
		__nic_get_completed_txd(nic, cq, &txd,
					&tx_status);
		COND_RELEASE(nic->requires_lock, &nic->lock);

		if (txd && txd->completer_fn) {
			ret = txd->completer_fn(txd, tx_status);
			if (ret != FI_SUCCESS) {
				/*
				 * TODO: need to post error to CQ
				 */
				SSTMACX_WARN(FI_LOG_EP_DATA,
					  "TXD completer failed: %d", ret);
			}
		}

		if ((txd == NULL) || ret != FI_SUCCESS)
			break;
	} while (1);

	return ret;
}

extern "C" int _sstmacx_nic_progress(void *arg)
{
	struct sstmacx_nic *nic = (struct sstmacx_nic *)arg;
	int ret = FI_SUCCESS;

	ret =  __nic_tx_progress(nic, nic->tx_cq);
	if (OFI_UNLIKELY(ret != FI_SUCCESS))
		return ret;

	if (nic->tx_cq_blk && nic->tx_cq_blk != nic->tx_cq) {
		ret =  __nic_tx_progress(nic, nic->tx_cq_blk);
		if (OFI_UNLIKELY(ret != FI_SUCCESS))
			return ret;
	}

	ret = __nic_rx_progress(nic);
	if (ret != FI_SUCCESS)
		return ret;

	ret = _sstmacx_vc_nic_progress(nic);
	if (ret != FI_SUCCESS)
		return ret;

	return ret;
}

extern "C" int _sstmacx_nic_free_rem_id(struct sstmacx_nic *nic, int remote_id)
{
	assert(nic);

	if ((remote_id < 0) || (remote_id > nic->vc_id_table_count))
		return -FI_EINVAL;

	_sstmacx_clear_bit(&nic->vc_id_bitmap, remote_id);

	return FI_SUCCESS;
}

/*
 * this function is needed to allow for quick lookup of a vc based on
 * the contents of the SSTMAC CQE coming off of the SSTMAC RX CQ associated
 * with SSTMAC nic being used by this VC.  Using a bitmap to expedite
 * scanning vc's in the case of a SSTMAC CQ overrun.
 */

extern "C" int _sstmacx_nic_get_rem_id(struct sstmacx_nic *nic, int *remote_id, void *entry)
{
	int ret = FI_SUCCESS;
	void **table_base;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	/*
	 * TODO:  really need to search bitmap for clear
	 * bit before resizing the table
	 */

	COND_ACQUIRE(nic->requires_lock, &nic->vc_id_lock);
	if (nic->vc_id_table_capacity == nic->vc_id_table_count) {
		table_base = realloc(nic->vc_id_table,
				     2 * nic->vc_id_table_capacity *
				     sizeof(void *));
		if (table_base == NULL) {
			ret =  -FI_ENOMEM;
			goto err;
		}
		nic->vc_id_table_capacity *= 2;
		nic->vc_id_table = table_base;

		ret = _sstmacx_realloc_bitmap(&nic->vc_id_bitmap,
					   nic->vc_id_table_capacity);
		if (ret != FI_SUCCESS) {
			assert(ret == -FI_ENOMEM);
			goto err;
		}
	}

	nic->vc_id_table[nic->vc_id_table_count] = entry;
	*remote_id = nic->vc_id_table_count;

	/*
	 * set bit in the bitmap
	 */

	_sstmacx_set_bit(&nic->vc_id_bitmap, nic->vc_id_table_count);

	++(nic->vc_id_table_count);
err:
	COND_RELEASE(nic->requires_lock, &nic->vc_id_lock);
	return ret;
}

/*
 * allocate a free list of tx descs for a sstmacx_nic struct.
 */

static int __sstmacx_nic_tx_freelist_init(struct sstmacx_nic *nic, int n_descs)
{
	int i, ret = FI_SUCCESS;
	struct sstmacx_tx_descriptor *desc_base, *desc_ptr;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	/*
	 * set up free list of tx descriptors.
	 */

	desc_base = calloc(n_descs, sizeof(struct sstmacx_tx_descriptor));
	if (desc_base == NULL) {
		ret = -FI_ENOMEM;
		goto err;
	}

	dlist_init(&nic->tx_desc_free_list);
	dlist_init(&nic->tx_desc_active_list);

	for (i = 0, desc_ptr = desc_base; i < n_descs; i++, desc_ptr++) {
		desc_ptr->id = i;
		dlist_insert_tail(&desc_ptr->list,
				  &nic->tx_desc_free_list);
	}

	nic->max_tx_desc_id = n_descs - 1;
	nic->tx_desc_base = desc_base;

	fastlock_init(&nic->tx_desc_lock);

	return ret;

err:
	return ret;

}

/*
 * clean up the tx descs free list
 */
static void __sstmacx_nic_tx_freelist_destroy(struct sstmacx_nic *nic)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	free(nic->tx_desc_base);
	fastlock_destroy(&nic->tx_desc_lock);
}

/*
 * free a sstmacx nic and associated resources if refcnt drops to 0
 */

static void __nic_destruct(void *obj)
{
	int ret = FI_SUCCESS;
	sstmac_return_t status = SSTMAC_RC_SUCCESS;
	struct sstmacx_nic *nic = (struct sstmacx_nic *) obj;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	/* Get us out of the progression tables we are destroying the nic
	 * and we don't want the wait progression thread to progress us
	 * after our structures are destroyed.
	 */
	pthread_mutex_lock(&sstmacx_nic_list_lock);

	dlist_remove(&nic->sstmacx_nic_list);
	--sstmacx_nics_per_ptag[nic->ptag];
	dlist_remove(&nic->ptag_nic_list);

	pthread_mutex_unlock(&sstmacx_nic_list_lock);
	__sstmacx_nic_tx_freelist_destroy(nic);

	/*
	 *free irq cq related resources
	 */

	ret = __nic_teardown_irq_cq(nic);
	if (ret != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "__nic_teardown_irq_cq returned %s\n",
			  fi_strerror(-ret));

	/*
	 * kill off progress thread, if any
	 */

	if (nic->progress_thread) {

		ret = pthread_cancel(nic->progress_thread);
		if ((ret != 0) && (ret != ESRCH)) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
			"pthread_cancel returned %d\n", ret);
			goto err;
		}

		ret = pthread_join(nic->progress_thread,
				   NULL);
		if ((ret != 0) && (ret != ESRCH)) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
			"pthread_join returned %d\n", ret);
			goto err;
		}

		SSTMACX_INFO(FI_LOG_EP_CTRL, "pthread_join returned %d\n", ret);
		nic->progress_thread = 0;
	}

	/* Must free mboxes first, because the MR has a pointer to the
	 * nic handles below */
	ret = _sstmacx_mbox_allocator_destroy(nic->mbox_hndl);
	if (ret != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "_sstmacx_mbox_allocator_destroy returned %s\n",
			  fi_strerror(-ret));

	/*
	 * see comments in the nic constructor about why
	 * the following code section is currently stubbed out.
	 */
#if 0
	ret = _sstmacx_mbox_allocator_destroy(nic->s_rdma_buf_hndl);
	if (ret != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "_sstmacx_mbox_allocator_destroy returned %s\n",
			  fi_strerror(-ret));

	ret = _sstmacx_mbox_allocator_destroy(nic->r_rdma_buf_hndl);
	if (ret != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "_sstmacx_mbox_allocator_destroy returned %s\n",
			  fi_strerror(-ret));
#endif

	if (!nic->sstmac_cdm_hndl) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "No CDM attached to nic, nic=%p");
	}

	assert(nic->sstmac_cdm_hndl != NULL);

	if (nic->rx_cq != NULL && nic->rx_cq != nic->rx_cq_blk) {
		status = SSTMAC_CqDestroy(nic->rx_cq);
		if (status != SSTMAC_RC_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "SSTMAC_CqDestroy returned %s\n",
				 sstmac_err_str[status]);
			ret = sstmacxu_to_fi_errno(status);
			goto err;
		}
	}

	if (nic->rx_cq_blk != NULL) {
		status = SSTMAC_CqDestroy(nic->rx_cq_blk);
		if (status != SSTMAC_RC_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "SSTMAC_CqDestroy returned %s\n",
				 sstmac_err_str[status]);
			ret = sstmacxu_to_fi_errno(status);
			goto err;
		}
	}

	if (nic->tx_cq != NULL && nic->tx_cq != nic->tx_cq_blk) {
		status = SSTMAC_CqDestroy(nic->tx_cq);
		if (status != SSTMAC_RC_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "SSTMAC_CqDestroy returned %s\n",
				 sstmac_err_str[status]);
			ret = sstmacxu_to_fi_errno(status);
			goto err;
		}
	}

	if (nic->tx_cq_blk != NULL) {
		status = SSTMAC_CqDestroy(nic->tx_cq_blk);
		if (status != SSTMAC_RC_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "SSTMAC_CqDestroy returned %s\n",
				 sstmac_err_str[status]);
			ret = sstmacxu_to_fi_errno(status);
			goto err;
		}
	}

	if (nic->allocd_sstmac_res & SSTMACX_NIC_CDM_ALLOCD) {
		status = SSTMAC_CdmDestroy(nic->sstmac_cdm_hndl);
		if (status != SSTMAC_RC_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "SSTMAC_CdmDestroy returned %s\n",
				  sstmac_err_str[status]);
			ret = sstmacxu_to_fi_errno(status);
			goto err;
		}
	}

	if (nic->vc_id_table != NULL) {
		free(nic->vc_id_table);
	} else {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "vc_id_table was NULL\n");
	}

	/*
	 * destroy VC free list associated with this nic
	 */

	_sstmacx_fl_destroy(&nic->vc_freelist);

	/*
	 * remove the nic from the linked lists
	 * for the domain and the global nic list
	 */

err:
	_sstmacx_free_bitmap(&nic->vc_id_bitmap);

	free(nic);
}

extern "C" int _sstmacx_nic_free(struct sstmacx_nic *nic)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (nic == NULL)
		return -FI_EINVAL;

	_sstmacx_ref_put(nic);

	return FI_SUCCESS;
}

/*
 * allocate a sstmacx_nic struct using attributes of the domain
 */

extern "C" int sstmacx_nic_alloc(struct sstmacx_fid_domain *domain,
		   struct sstmacx_nic_attr *attr,
		   struct sstmacx_nic **nic_ptr)
{
	int ret = FI_SUCCESS;
	struct sstmacx_nic *nic = NULL;
	uint32_t device_addr;
	sstmac_return_t status;
	uint32_t fake_cdm_id = SSTMACX_CREATE_CDM_ID;
	sstmac_smsg_attr_t smsg_mbox_attr;
	struct sstmacx_nic_attr *nic_attr = &default_attr;
	uint32_t num_corespec_cpus = 0;
	bool must_alloc_nic = false;
	bool free_list_inited = false;
	struct sstmacx_auth_key *auth_key;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	*nic_ptr = NULL;
	nic_attr->sstmac_cdm_modes = sstmacx_cdm_modes;

	if (attr) {
		ret = __sstmacx_nic_check_attr_sanity(attr);
		if (ret != FI_SUCCESS)
			return ret;
		nic_attr = attr;
		must_alloc_nic = nic_attr->must_alloc;
	}

	auth_key = nic_attr->auth_key;

	/*
	 * If we've maxed out the number of nics for this domain/ptag,
	 * search the list of existing nics.  Take the sstmacx_nic_list_lock
	 * here since the sstmacx_nic_list will be manipulated whether or
	 * not we attach to an existing nic or create a new one.
	 *
	 * Should not matter much that this is a pretty fat critical section
	 * since endpoint setup for RDM type will typically occur near
	 * app startup, likely in a single threaded region, and for the
	 * case of MSG, where there will likely be many 100s of EPs, after
	 * a few initial slow times through this section when nics are created,
	 * max nic count for the ptag will be reached and only the first part
	 * of the critical section - iteration over existing nics - will be
	 * happening.
	 */

	pthread_mutex_lock(&sstmacx_nic_list_lock);

	/*
	 * we can reuse previously allocated nics as long as a
	 * must_alloc is not specified in the nic_attr arg.
	 */

	if ((must_alloc_nic == false) &&
	    (sstmacx_nics_per_ptag[auth_key->ptag] >= sstmacx_max_nics_per_ptag)) {
		assert(!dlist_empty(&sstmacx_nic_list_ptag[auth_key->ptag]));

		nic = dlist_first_entry(&sstmacx_nic_list_ptag[auth_key->ptag],
					struct sstmacx_nic, ptag_nic_list);
		dlist_remove(&nic->ptag_nic_list);
		dlist_insert_tail(&nic->ptag_nic_list,
				  &sstmacx_nic_list_ptag[auth_key->ptag]);
		_sstmacx_ref_get(nic);

		SSTMACX_INFO(FI_LOG_EP_CTRL, "Reusing NIC:%p\n", nic);
	}

	/*
	 * no nic found create a cdm and attach
	 */

	if (!nic) {

		nic = calloc(1, sizeof(struct sstmacx_nic));
		if (nic == NULL) {
			ret = -FI_ENOMEM;
			goto err;
		}

		nic->using_vmdh = domain->using_vmdh;

		if (nic_attr->use_cdm_id == false) {
			ret = _sstmacx_cm_nic_create_cdm_id(domain, &fake_cdm_id);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "_sstmacx_cm_nic_create_cdm_id returned %s\n",
					  fi_strerror(-ret));
				goto err;
			}
		} else
			fake_cdm_id = nic_attr->cdm_id;

		if (nic_attr->sstmac_cdm_hndl == NULL) {
			status = SSTMAC_CdmCreate(fake_cdm_id,
						auth_key->ptag,
						auth_key->cookie,
						sstmacx_cdm_modes,
						&nic->sstmac_cdm_hndl);
			if (status != SSTMAC_RC_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL, "SSTMAC_CdmCreate returned %s\n",
					 sstmac_err_str[status]);
				ret = sstmacxu_to_fi_errno(status);
				goto err1;
			}
			nic->allocd_sstmac_res |= SSTMACX_NIC_CDM_ALLOCD;
		} else {
			nic->sstmac_cdm_hndl = nic_attr->sstmac_cdm_hndl;
		}

		/*
		 * Okay, now go for the attach
		*/

		if (nic_attr->sstmac_nic_hndl == NULL) {
			status = SSTMAC_CdmAttach(nic->sstmac_cdm_hndl,
						0,
						&device_addr,
						&nic->sstmac_nic_hndl);
			if (status != SSTMAC_RC_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL, "SSTMAC_CdmAttach returned %s\n",
					 sstmac_err_str[status]);
				_sstmacx_dump_sstmac_res(auth_key->ptag);
				ret = sstmacxu_to_fi_errno(status);
				goto err1;
			}
		} else
			nic->sstmac_nic_hndl = nic_attr->sstmac_nic_hndl;

		/*
		 * create TX CQs - first polling, then blocking
		 */

		status = SSTMAC_CqCreate(nic->sstmac_nic_hndl,
					domain->params.tx_cq_size,
					0,                  /* no delay count */
					SSTMAC_CQ_BLOCKING |
						domain->sstmac_cq_modes,
					NULL,              /* useless handler */
					NULL,               /* useless handler
								context */
					&nic->tx_cq_blk);
		if (status != SSTMAC_RC_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "SSTMAC_CqCreate returned %s\n",
				  sstmac_err_str[status]);
			_sstmacx_dump_sstmac_res(auth_key->ptag);
			ret = sstmacxu_to_fi_errno(status);
			goto err1;
		}

		/* Use blocking CQs for all operations if eager_auto_progress
		 * is used.  */
		if (domain->params.eager_auto_progress) {
			nic->tx_cq = nic->tx_cq_blk;
		} else {
			status = SSTMAC_CqCreate(nic->sstmac_nic_hndl,
						domain->params.tx_cq_size,
						0, /* no delay count */
						domain->sstmac_cq_modes,
						NULL, /* useless handler */
						NULL, /* useless handler ctx */
						&nic->tx_cq);
			if (status != SSTMAC_RC_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "SSTMAC_CqCreate returned %s\n",
					  sstmac_err_str[status]);
				_sstmacx_dump_sstmac_res(auth_key->ptag);
				ret = sstmacxu_to_fi_errno(status);
				goto err1;
			}
		}


		/*
		 * create RX CQs - first polling, then blocking
		 */

		status = SSTMAC_CqCreate(nic->sstmac_nic_hndl,
					domain->params.rx_cq_size,
					0,
					SSTMAC_CQ_BLOCKING |
						domain->sstmac_cq_modes,
					NULL,
					NULL,
					&nic->rx_cq_blk);
		if (status != SSTMAC_RC_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "SSTMAC_CqCreate returned %s\n",
				  sstmac_err_str[status]);
			_sstmacx_dump_sstmac_res(auth_key->ptag);
			ret = sstmacxu_to_fi_errno(status);
			goto err1;
		}

		/* Use blocking CQs for all operations if eager_auto_progress
		 * is used.  */
		if (domain->params.eager_auto_progress) {
			nic->rx_cq = nic->rx_cq_blk;
		} else {
			status = SSTMAC_CqCreate(nic->sstmac_nic_hndl,
						domain->params.rx_cq_size,
						0,
						domain->sstmac_cq_modes,
						NULL,
						NULL,
						&nic->rx_cq);
			if (status != SSTMAC_RC_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "SSTMAC_CqCreate returned %s\n",
					  sstmac_err_str[status]);
				_sstmacx_dump_sstmac_res(auth_key->ptag);
				ret = sstmacxu_to_fi_errno(status);
				goto err1;
			}
		}

		nic->device_addr = device_addr;
		nic->ptag = auth_key->ptag;
		nic->cookie = auth_key->cookie;

		nic->vc_id_table_capacity = domain->params.vc_id_table_capacity;
		nic->vc_id_table = malloc(sizeof(void *) *
					       nic->vc_id_table_capacity);
		if (nic->vc_id_table == NULL) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "malloc of vc_id_table failed\n");
			ret = -FI_ENOMEM;
			goto err1;
		}

		ret = _sstmacx_alloc_bitmap(&nic->vc_id_bitmap,
					 nic->vc_id_table_capacity, NULL);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "alloc_bitmap returned %d\n", ret);
			goto err1;
		}
		fastlock_init(&nic->vc_id_lock);

		/*
		 * initialize free list for VC's
		 * In addition to hopefully allowing for a more compact
		 * allocation of VC structs, the free list is also import
		 * because there is a window of time when using auto progress
		 * that a thread may be going through the progress engine
		 * while one of the application threads is actively tearing
		 * down an endpoint (and hence its associated VCs) before the
		 * rem_id for the vc is removed from the vector.
		 * As a consequence, it is important that
		 * the memory allocated within the freelist allocator not be
		 * returned to the system prior to the freelist being destroyed
		 * as part of the nic destructor procedure.  The freelist is
		 * destroyed in that procedure after the progress thread
		 * has been joined.
		 */

		ret = _sstmacx_fl_init_ts(sizeof(struct sstmacx_vc),
				       offsetof(struct sstmacx_vc, fr_list),
				       SSTMACX_VC_FL_MIN_SIZE,
				       SSTMACX_VC_FL_INIT_REFILL_SIZE,
				       0,
				       0,
				       &nic->vc_freelist);
		if (ret == FI_SUCCESS) {
			free_list_inited = true;
		} else {
			SSTMACX_DEBUG(FI_LOG_EP_DATA, "_sstmacx_fl_init returned: %s\n",
				   fi_strerror(-ret));
			goto err1;
		}

		fastlock_init(&nic->lock);

		ret = __sstmacx_nic_tx_freelist_init(nic,
						  domain->params.tx_cq_size);
		if (ret != FI_SUCCESS)
			goto err1;

		fastlock_init(&nic->prog_vcs_lock);
		dlist_init(&nic->prog_vcs);

		_sstmacx_ref_init(&nic->ref_cnt, 1, __nic_destruct);

		smsg_mbox_attr.msg_type = SSTMAC_SMSG_TYPE_MBOX_AUTO_RETRANSMIT;
		smsg_mbox_attr.mbox_maxcredit = domain->params.mbox_maxcredit;
		smsg_mbox_attr.msg_maxsize =  domain->params.mbox_msg_maxsize;

		status = SSTMAC_SmsgBufferSizeNeeded(&smsg_mbox_attr,
						  &nic->mem_per_mbox);
		if (status != SSTMAC_RC_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "SSTMAC_SmsgBufferSizeNeeded returned %s\n",
				  sstmac_err_str[status]);
			ret = sstmacxu_to_fi_errno(status);
			goto err1;
		}

		/*
		 * set up mailbox allocator for SMSG mailboxes
		 */

		ret = _sstmacx_mbox_allocator_create(nic,
					  nic->rx_cq,
					  domain->params.mbox_page_size,
					  (size_t)nic->mem_per_mbox,
					  domain->params.mbox_num_per_slab,
					  &nic->mbox_hndl);

		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "_sstmacx_mbox_alloc returned %s\n",
				  fi_strerror(-ret));
			goto err1;
		}

		/*
		 * use the mailbox allocator system to set up an
		 * pre-pinned RDMA bounce buffers for longer eager
		 * messages and other cases where zero-copy
		 * can't be safely used.
		 *
		 * One set of blocks is used for the send side.
		 * A second set of blocks is used for the receive
		 * side.  Both sets of blocks are registered against
		 * the blocking RX CQ for this nic.
		 *
		 * TODO: hardwired constants, uff
		 * TODO: better to use a buddy allocator or some other
		 * allocator
		 * Disable these for now as we're not using and they
		 * chew up a lot of IOMMU space per nic.
		 */

#if 0
		ret = _sstmacx_mbox_allocator_create(nic,
						  NULL,
						  SSTMACX_PAGE_2MB,
						  65536,
						  512,
						  &nic->s_rdma_buf_hndl);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "_sstmacx_mbox_alloc returned %s\n",
				  fi_strerror(-ret));
			_sstmacx_dump_sstmac_res(domain->ptag);
			goto err1;
		}

		ret = _sstmacx_mbox_allocator_create(nic,
						  NULL,
						  SSTMACX_PAGE_2MB,
						  65536,
						  512,
						  &nic->r_rdma_buf_hndl);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "_sstmacx_mbox_alloc returned %s\n",
				  fi_strerror(-ret));
			_sstmacx_dump_sstmac_res(domain->ptag);
			goto err1;
		}
#endif

		ret =  __nic_setup_irq_cq(nic);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "__nic_setup_irq_cq returned %s\n",
				  fi_strerror(-ret));
			_sstmacx_dump_sstmac_res(auth_key->ptag);
			goto err1;
		}

		/*
 		 * if the domain is using PROGRESS_AUTO for data, set up
 		 * a progress thread.
 		 */

		if (domain->data_progress == FI_PROGRESS_AUTO) {

			/*
			 * tell CLE job container that next thread should be
			 * runnable anywhere in the cpuset, don't treat as
			 * an error if one is returned, may have perf issues
			 * though...
			 */

			ret = _sstmacx_get_num_corespec_cpus(&num_corespec_cpus);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "failed to get num corespec cpus\n");
			}
			if (num_corespec_cpus > 0) {
				ret = _sstmacx_job_disable_affinity_apply();
			} else {
				ret = _sstmacx_job_enable_unassigned_cpus();
			}
			if (ret != 0)
				SSTMACX_WARN(FI_LOG_EP_CTRL,
				"job_disable/unassigned cpus returned %d\n",
					 ret);

			ret = pthread_create(&nic->progress_thread,
					     NULL,
					     __sstmacx_nic_prog_thread_fn,
					     (void *)nic);
			if (ret)
				SSTMACX_WARN(FI_LOG_EP_CTRL,
				"pthread_create call returned %d\n", ret);
		}

		dlist_insert_tail(&nic->sstmacx_nic_list, &sstmacx_nic_list);
		dlist_insert_tail(&nic->ptag_nic_list,
				  &sstmacx_nic_list_ptag[auth_key->ptag]);

		nic->smsg_callbacks = sstmacx_ep_smsg_callbacks;

		++sstmacx_nics_per_ptag[auth_key->ptag];

		SSTMACX_INFO(FI_LOG_EP_CTRL, "Allocated NIC:%p\n", nic);
	}

	if (nic) {
		nic->requires_lock = domain->thread_model != FI_THREAD_COMPLETION;
		nic->using_vmdh = domain->using_vmdh;
	}

	*nic_ptr = nic;
	goto out;

err1:
	ofi_atomic_dec32(&sstmacx_id_counter);
err:
	if (nic != NULL) {
		__nic_teardown_irq_cq(nic);
		if (nic->r_rdma_buf_hndl != NULL)
			_sstmacx_mbox_allocator_destroy(nic->r_rdma_buf_hndl);
		if (nic->s_rdma_buf_hndl != NULL)
			_sstmacx_mbox_allocator_destroy(nic->s_rdma_buf_hndl);
		if (nic->mbox_hndl != NULL)
			_sstmacx_mbox_allocator_destroy(nic->mbox_hndl);
		if (nic->rx_cq != NULL && nic->rx_cq != nic->rx_cq_blk)
			SSTMAC_CqDestroy(nic->rx_cq);
		if (nic->rx_cq_blk != NULL)
			SSTMAC_CqDestroy(nic->rx_cq_blk);
		if (nic->tx_cq != NULL && nic->tx_cq != nic->tx_cq_blk)
			SSTMAC_CqDestroy(nic->tx_cq);
		if (nic->tx_cq_blk != NULL)
			SSTMAC_CqDestroy(nic->tx_cq_blk);
		if ((nic->sstmac_cdm_hndl != NULL) && (nic->allocd_sstmac_res &
		    SSTMACX_NIC_CDM_ALLOCD))
			SSTMAC_CdmDestroy(nic->sstmac_cdm_hndl);
		if (free_list_inited == true)
			_sstmacx_fl_destroy(&nic->vc_freelist);
		free(nic);
	}

out:
	pthread_mutex_unlock(&sstmacx_nic_list_lock);
	return ret;
}

void _sstmacx_nic_init(void)
{
	int i, rc;

	for (i = 0; i < SSTMAC_PTAG_MAX; i++) {
		dlist_init(&sstmacx_nic_list_ptag[i]);
	}

	rc = _sstmacx_nics_per_rank(&sstmacx_max_nics_per_ptag);
	if (rc == FI_SUCCESS) {
		SSTMACX_DEBUG(FI_LOG_FABRIC, "sstmacx_max_nics_per_ptag: %u\n",
			   sstmacx_max_nics_per_ptag);
	} else {
		SSTMACX_WARN(FI_LOG_FABRIC, "_sstmacx_nics_per_rank failed: %d\n",
			  rc);
	}

	if (getenv("SSTMACX_MAX_NICS") != NULL)
		sstmacx_max_nics_per_ptag = atoi(getenv("SSTMACX_MAX_NICS"));

	/*
	 * Well if we didn't get 1 nic, that means we must really be doing
	 * FMA sharing.
	 */

	if (sstmacx_max_nics_per_ptag == 0) {
		sstmacx_max_nics_per_ptag = 1;
		SSTMACX_WARN(FI_LOG_FABRIC, "Using inter-procss FMA sharing\n");
	}
}


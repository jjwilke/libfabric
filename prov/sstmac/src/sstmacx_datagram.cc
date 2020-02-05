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
 * Copyright (c) 2015-2016 Cray Inc.  All rights reserved.
 * Copyright (c) 2015-2017 Los Alamos National Security, LLC.
 *                         All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc. All rights reserved.
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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <pthread.h>
#include <signal.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

#include <rdma/providers/fi_prov.h>

#include "sstmacx.h"
#include "sstmacx_datagram.h"
#include "sstmacx_util.h"
#include "sstmacx_cm_nic.h"
#include "sstmacx_nic.h"


/*******************************************************************************
 * Helper functions.
 ******************************************************************************/

/*
 * this function is intended to be invoked as an argument to pthread_create,
 */
static void *_sstmacx_dgram_prog_thread_fn(void *the_arg)
{
	int ret = FI_SUCCESS, prev_state;
	struct sstmacx_dgram_hndl *the_hndl = (struct sstmacx_dgram_hndl *)the_arg;
	sigset_t  sigmask;

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
		"_sstmacx_task_is_not_app call returned %d\n", ret);

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

retry:
	ret = _sstmacx_dgram_poll(the_hndl, SSTMACX_DGRAM_BLOCK);
	if ((ret == -FI_ETIMEDOUT) || (ret == FI_SUCCESS))
		goto retry;

	SSTMACX_WARN(FI_LOG_EP_CTRL,
		"_sstmacx_dgram_poll returned %s\n", fi_strerror(-ret));

	/*
	 * TODO: need to be able to enqueue events on to the
	 * ep associated with the cm_nic.
	 */
	return NULL;
}

/*******************************************************************************
 * API function implementations.
 ******************************************************************************/

/*
 * function to pack data into datagram in/out buffers.
 * On success, returns number of bytes packed in to the buffer,
 * otherwise -FI errno.
 */
ssize_t _sstmacx_dgram_pack_buf(struct sstmacx_datagram *d, enum sstmacx_dgram_buf buf,
			 void *data, uint32_t nbytes)
{
	char *dptr;
	uint32_t index;

	assert(d != NULL);
	if (buf == SSTMACX_DGRAM_IN_BUF) {
		index = d->w_index_in_buf;
		dptr = &d->dgram_in_buf[index];
	} else {
		index = d->w_index_out_buf;
		dptr = &d->dgram_out_buf[index];
	}

	/*
	 * make sure there's room
	 */
	if ((index + nbytes) > SSTMAC_DATAGRAM_MAXSIZE)
		return -FI_ENOSPC;

	memcpy(dptr, data, nbytes);

	if (buf == SSTMACX_DGRAM_IN_BUF)
		d->w_index_in_buf += nbytes;
	else
		d->w_index_out_buf += nbytes;

	return nbytes;
}


/*
 * function to unpack data from datagram in/out buffers.
 * On success, returns number of bytes unpacked,
 * otherwise -FI errno.
 */
ssize_t _sstmacx_dgram_unpack_buf(struct sstmacx_datagram *d, enum sstmacx_dgram_buf buf,
			   void *data, uint32_t nbytes)
{
	char *dptr;
	uint32_t index, bytes_left;

	assert(d != NULL);
	if (buf == SSTMACX_DGRAM_IN_BUF) {
		index = d->r_index_in_buf;
		dptr = &d->dgram_in_buf[index];
	} else {
		index = d->r_index_out_buf;
		dptr = &d->dgram_out_buf[index];
	}

	/*
	 * only copy out up to SSTMAC_DATAGRAM_MAXSIZE
	 */

	bytes_left = SSTMAC_DATAGRAM_MAXSIZE - index;

	nbytes = (nbytes > bytes_left) ? bytes_left : nbytes;

	memcpy(data, dptr, nbytes);

	if (buf == SSTMACX_DGRAM_IN_BUF)
		d->r_index_in_buf += nbytes;
	else
		d->r_index_out_buf += nbytes;

	return nbytes;
}

/*
 * function to rewind the internal pointers to
 * datagram in/out buffers.
 */
extern "C" int _sstmacx_dgram_rewind_buf(struct sstmacx_datagram *d, enum sstmacx_dgram_buf buf)
{
	assert(d != NULL);
	if (buf == SSTMACX_DGRAM_IN_BUF) {
		d->r_index_in_buf = 0;
		d->w_index_in_buf = 0;
	} else {
		d->r_index_out_buf = 0;
		d->w_index_out_buf = 0;
	}
	return FI_SUCCESS;
}

extern "C" int _sstmacx_dgram_alloc(struct sstmacx_dgram_hndl *hndl, enum sstmacx_dgram_type type,
			struct sstmacx_datagram **d_ptr)
{
	int ret = -FI_EAGAIN;
	struct sstmacx_datagram *d = NULL;
	struct dlist_entry *the_free_list;
	struct dlist_entry *the_active_list;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	fastlock_acquire(&hndl->lock);

	if (type == SSTMACX_DGRAM_WC) {
		the_free_list = &hndl->wc_dgram_free_list;
		the_active_list = &hndl->wc_dgram_active_list;
	} else {
		the_free_list = &hndl->bnd_dgram_free_list;
		the_active_list = &hndl->bnd_dgram_active_list;
	}

	if (!dlist_empty(the_free_list)) {
		d = dlist_first_entry(the_free_list, struct sstmacx_datagram,
				      list);
		if (d != NULL) {
			dlist_remove_init(&d->list);
			dlist_insert_head(&d->list, the_active_list);
			d->type = type;
			ret = FI_SUCCESS;
		}

	}

	fastlock_release(&hndl->lock);

	if (d != NULL) {
		d->r_index_in_buf = 0;
		d->w_index_in_buf = 0;
		d->w_index_in_buf = 0;
		d->w_index_out_buf = 0;
	}

	*d_ptr = d;
	return ret;
}

extern "C" int _sstmacx_dgram_free(struct sstmacx_datagram *d)
{
	int ret = FI_SUCCESS;
	sstmac_return_t status;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (d->type == SSTMACX_DGRAM_BND) {
		status = SSTMAC_EpUnbind(d->sstmac_ep);
		if (status != SSTMAC_RC_SUCCESS) {
			/* TODO: have to handle this */
			SSTMACX_FATAL(FI_LOG_EP_CTRL,
				   "SSTMAC_EpUnbind returned %s (ep=%p)\n",
				   sstmac_err_str[status], d->sstmac_ep);
		}
	}

	fastlock_acquire(&d->d_hndl->lock);
	dlist_remove_init(&d->list);
	d->state = SSTMACX_DGRAM_STATE_FREE;
	dlist_insert_head(&d->list, d->free_list_head);
	fastlock_release(&d->d_hndl->lock);
	return ret;
}

extern "C" int _sstmacx_dgram_wc_post(struct sstmacx_datagram *d)
{
	int ret = FI_SUCCESS;
	sstmac_return_t status;
	struct sstmacx_nic *nic = d->cm_nic->nic;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	COND_ACQUIRE(nic->requires_lock, &nic->lock);
	status = SSTMAC_EpPostDataWId(d->sstmac_ep,
				   d->dgram_in_buf,
				   SSTMAC_DATAGRAM_MAXSIZE,
				   d->dgram_out_buf,
				   SSTMAC_DATAGRAM_MAXSIZE,
				   (uint64_t)d);
	if (status != SSTMAC_RC_SUCCESS) {
		ret = sstmacxu_to_fi_errno(status);
	} else {
		/*
		 * datagram is active now, listening
		 */
		d->state = SSTMACX_DGRAM_STATE_ACTIVE;
	}
	COND_RELEASE(nic->requires_lock, &nic->lock);

	return ret;
}

extern "C" int _sstmacx_dgram_bnd_post(struct sstmacx_datagram *d)
{
	sstmac_return_t status = SSTMAC_RC_SUCCESS;
	int ret = FI_SUCCESS;
	struct sstmacx_nic *nic = d->cm_nic->nic;
	int post = 1;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	/*
	 * bind the datagram ep
	 */

	status = SSTMAC_EpBind(d->sstmac_ep,
			    d->target_addr.device_addr,
			    d->target_addr.cdm_id);
	if (status != SSTMAC_RC_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			"SSTMAC_EpBind returned %s\n", sstmac_err_str[status]);
		ret = sstmacxu_to_fi_errno(status);
		goto err;
	}

	COND_ACQUIRE(nic->requires_lock, &nic->lock);
	if (d->pre_post_clbk_fn != NULL) {
		ret = d->pre_post_clbk_fn(d, &post);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				"pre_post_callback_fn: %d\n",
				ret);
	}

	if (post) {
		/*
		 * if we get SSTMAC_RC_ERROR_RESOURCE status return from
		 * SSTMAC_EpPostDataWId  that means that either a previously posted
		 * wildcard datagram has matched up with an incoming
		 * bound datagram or we have a previously posted bound
		 * datagram whose transfer to the target node has
		 * not yet completed.  Don't treat this case as an error.
		 */
		status = SSTMAC_EpPostDataWId(d->sstmac_ep,
					   d->dgram_in_buf,
					   SSTMAC_DATAGRAM_MAXSIZE,
					   d->dgram_out_buf,
					   SSTMAC_DATAGRAM_MAXSIZE,
					   (uint64_t)d);
		if (d->post_post_clbk_fn != NULL) {
			ret = d->post_post_clbk_fn(d, status);
			if (ret != FI_SUCCESS)
				SSTMACX_WARN(FI_LOG_EP_CTRL,
				"post_post_callback_fn: %d\n",
				ret);
		}
	}

	COND_RELEASE(nic->requires_lock, &nic->lock);

	if (post) {
		if ((status != SSTMAC_RC_SUCCESS) &&
			(status != SSTMAC_RC_ERROR_RESOURCE)) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
				    "SSTMAC_EpPostDataWId returned %s\n",
				     sstmac_err_str[status]);
				ret = sstmacxu_to_fi_errno(status);
				goto err;
		}

		if (status == SSTMAC_RC_SUCCESS) {
			/*
			 * datagram is active now, connecting
			 */
			d->state = SSTMACX_DGRAM_STATE_ACTIVE;
		} else {
			ret = -FI_EBUSY;
		}
	}

err:
	return ret;
}

int  _sstmacx_dgram_poll(struct sstmacx_dgram_hndl *hndl,
			enum sstmacx_dgram_poll_type type)
{
	int ret = FI_SUCCESS;
	sstmac_return_t status;
	sstmac_post_state_t post_state = SSTMAC_POST_PENDING;
	uint32_t responding_remote_id;
	uint32_t timeout = -1;
	unsigned int responding_remote_addr;
	struct sstmacx_datagram *dg_ptr;
	uint64_t datagram_id = 0UL;
	struct sstmacx_cm_nic *cm_nic = NULL;
	struct sstmacx_nic *nic = NULL;
	struct sstmacx_address responding_addr;

	cm_nic = hndl->cm_nic;
	assert(cm_nic != NULL);
	nic = cm_nic->nic;
	assert(nic != NULL);

	if (type == SSTMACX_DGRAM_BLOCK) {
		if (hndl->timeout_needed &&
			(hndl->timeout_needed(hndl->timeout_data) == true))
				timeout = hndl->timeout;

		status = SSTMAC_PostdataProbeWaitById(nic->sstmac_nic_hndl,
						   timeout,
						   &datagram_id);
		if ((status != SSTMAC_RC_SUCCESS) &&
			(status  != SSTMAC_RC_TIMEOUT)) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				"SSTMAC_PostdataProbeWaitById returned %s\n",
					sstmac_err_str[status]);
			ret = sstmacxu_to_fi_errno(status);
			goto err;
		}
	} else {
		status = SSTMAC_PostDataProbeById(nic->sstmac_nic_hndl,
						   &datagram_id);
		if ((status != SSTMAC_RC_SUCCESS) &&
			(status  != SSTMAC_RC_NO_MATCH)) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				"SSTMAC_PostdataProbeById returned %s\n",
					sstmac_err_str[status]);
			ret = sstmacxu_to_fi_errno(status);
			goto err;
		}
	}

	switch (status) {
	case SSTMAC_RC_SUCCESS:
		dg_ptr = (struct sstmacx_datagram *)datagram_id;
		assert(dg_ptr != NULL);

		/*
		 * do need to take lock here
		 */
		COND_ACQUIRE(nic->requires_lock, &nic->lock);

		status = SSTMAC_EpPostDataTestById(dg_ptr->sstmac_ep,
						datagram_id,
						&post_state,
						&responding_remote_addr,
						&responding_remote_id);
		if ((status != SSTMAC_RC_SUCCESS) &&
			(status !=SSTMAC_RC_NO_MATCH)) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				"SSTMAC_EpPostDataTestById:  %s\n",
					sstmac_err_str[status]);
			ret = sstmacxu_to_fi_errno(status);
			COND_RELEASE(nic->requires_lock, &nic->lock);
			goto err;
		} else {
			if ((status == SSTMAC_RC_SUCCESS) &&
			     (dg_ptr->state != SSTMACX_DGRAM_STATE_ACTIVE)) {
				SSTMACX_DEBUG(FI_LOG_EP_CTRL,
					"SSTMAC_EpPostDataTestById ",
					"returned success but dgram not active\n");
			}
		}

		COND_RELEASE(nic->requires_lock, &nic->lock);

		/*
		 * no match is okay, it means another thread
		 * won the race to get this datagram
		 */

		if (status == SSTMAC_RC_NO_MATCH) {
			ret = FI_SUCCESS;
			goto err;
		}

		/*
		 * pass COMPLETED and error post state cases to
		 * callback function if present.  If a callback funciton
		 * is not present, the error states set ret to -FI_EIO.
		 *
		 * TODO should we also pass pending,remote_data states to
		 * the callback?  maybe useful for debugging weird
		 * datagram problems?
		 */
		switch (post_state) {
		case SSTMAC_POST_TIMEOUT:
		case SSTMAC_POST_TERMINATED:
		case SSTMAC_POST_ERROR:
			ret = -FI_EIO;
			break;
		case SSTMAC_POST_COMPLETED:
			if (dg_ptr->callback_fn != NULL) {
				responding_addr.device_addr =
					responding_remote_addr;
				responding_addr.cdm_id =
					responding_remote_id;
				ret = dg_ptr->callback_fn((void *)datagram_id,
							responding_addr,
							post_state);
			}
			break;
		case SSTMAC_POST_PENDING:
		case SSTMAC_POST_REMOTE_DATA:
			break;
		default:
			SSTMACX_FATAL(FI_LOG_EP_CTRL, "Invalid post_state: %d\n",
				   post_state);
			break;
		}
		break;
	case SSTMAC_RC_TIMEOUT:
		/* call progress function */
		if (hndl->timeout_progress)
			hndl->timeout_progress(hndl->timeout_data);
		break;
	case SSTMAC_RC_NO_MATCH:
		break;
	default:
		/* an error */
		break;
	}

err:
	return ret;
}

extern "C" int _sstmacx_dgram_hndl_alloc(struct sstmacx_cm_nic *cm_nic,
			   enum fi_progress progress,
			   const struct sstmacx_dgram_hndl_attr *attr,
			   struct sstmacx_dgram_hndl **hndl_ptr)
{
	int i, ret = FI_SUCCESS;
	int n_dgrams_tot;
	struct sstmacx_datagram *dgram_base = NULL, *dg_ptr;
	struct sstmacx_dgram_hndl *the_hndl = NULL;
	struct sstmacx_fid_domain *dom = cm_nic->domain;
	struct sstmacx_fid_fabric *fabric = NULL;
	struct sstmacx_nic *nic;
	sstmac_return_t status;
	uint32_t num_corespec_cpus = 0;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	nic = cm_nic->nic;

	if (dom == NULL)
		return -FI_EINVAL;

	fabric = dom->fabric;

	the_hndl = calloc(1, sizeof(struct sstmacx_dgram_hndl));
	if (the_hndl == NULL) {
		ret = -FI_ENOMEM;
		goto err;
	}

	the_hndl->cm_nic = cm_nic;

	dlist_init(&the_hndl->bnd_dgram_free_list);
	dlist_init(&the_hndl->bnd_dgram_active_list);

	dlist_init(&the_hndl->wc_dgram_free_list);
	dlist_init(&the_hndl->wc_dgram_active_list);

	the_hndl->timeout = -1;

	/*
	 * inherit some stuff from the fabric object being
	 * used to open the domain which will use this cm nic.
	 */

	the_hndl->n_dgrams = fabric->n_bnd_dgrams;
	the_hndl->n_wc_dgrams = fabric->n_wc_dgrams;
	fastlock_init(&the_hndl->lock);

	n_dgrams_tot = the_hndl->n_dgrams + the_hndl->n_wc_dgrams;

	/*
	 * set up the free lists for datagrams
	 */

	dgram_base = calloc(n_dgrams_tot,
			    sizeof(struct sstmacx_datagram));
	if (dgram_base == NULL) {
		ret = -FI_ENOMEM;
		goto err;
	}

	dg_ptr = dgram_base;

	/*
	 * first build up the list for connection requests
	 */

	for (i = 0; i < fabric->n_bnd_dgrams; i++, dg_ptr++) {
		dg_ptr->d_hndl = the_hndl;
		dg_ptr->cm_nic = cm_nic;
		status = SSTMAC_EpCreate(nic->sstmac_nic_hndl,
					NULL,
					&dg_ptr->sstmac_ep);
		if (status != SSTMAC_RC_SUCCESS) {
			ret = sstmacxu_to_fi_errno(status);
			goto err;
		}
		dlist_node_init(&dg_ptr->list);
		dlist_insert_head(&dg_ptr->list,
				  &the_hndl->bnd_dgram_free_list);
		dg_ptr->free_list_head = &the_hndl->bnd_dgram_free_list;
	}

	/*
	 * now the wild card (WC) dgrams
	 */

	for (i = 0; i < fabric->n_wc_dgrams; i++, dg_ptr++) {
		dg_ptr->d_hndl = the_hndl;
		dg_ptr->cm_nic = cm_nic;
		status = SSTMAC_EpCreate(nic->sstmac_nic_hndl,
					NULL,
					&dg_ptr->sstmac_ep);
		if (status != SSTMAC_RC_SUCCESS) {
			ret = sstmacxu_to_fi_errno(status);
			goto err;
		}
		dlist_node_init(&dg_ptr->list);
		dlist_insert_head(&dg_ptr->list, &the_hndl->wc_dgram_free_list);
		dg_ptr->free_list_head = &the_hndl->wc_dgram_free_list;
	}

	/*
	 * check the progress model, if FI_PROGRESS_AUTO, fire off
	 * a progress thread
	 */

	if (progress == FI_PROGRESS_AUTO) {

		if (attr != NULL) {
			the_hndl->timeout_needed = attr->timeout_needed;
			the_hndl->timeout_progress = attr->timeout_progress;
			the_hndl->timeout_data = attr->timeout_data;
			the_hndl->timeout = attr->timeout;
		}

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
			"disable_affinity/unassigned_cpus call returned %d\n",
			ret);

		ret = pthread_create(&the_hndl->progress_thread,
				     NULL,
				     _sstmacx_dgram_prog_thread_fn,
				     (void *)the_hndl);
		if (ret) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
			"pthread_ceate  call returned %d\n", ret);
			goto err1;
		}
	}

	the_hndl->dgram_base = dgram_base;

	*hndl_ptr = the_hndl;

	return ret;

err1:

err:
	dg_ptr = dgram_base;
	if (dg_ptr) {

		for (i = 0; i < n_dgrams_tot; i++, dg_ptr++) {
			if (dg_ptr->sstmac_ep != NULL)
				SSTMAC_EpDestroy(dg_ptr->sstmac_ep);
		}
		free(dgram_base);
	}
	if (the_hndl)
		free(the_hndl);
	return ret;
}

extern "C" int _sstmacx_dgram_hndl_free(struct sstmacx_dgram_hndl *the_hndl)
{
	int i;
	int n_dgrams;
	int ret = FI_SUCCESS;
	struct sstmacx_datagram *p, *next, *dg_ptr;
	sstmac_return_t status;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (the_hndl->dgram_base == NULL) {
		ret = -FI_EINVAL;
		goto err;
	}

	/*
	 * cancel any active datagrams - SSTMAC_RC_NO_MATCH is okay.
	 */
	dlist_for_each_safe(&the_hndl->bnd_dgram_active_list, p, next, list) {
		dg_ptr = p;
		if (dg_ptr->state != SSTMACX_DGRAM_STATE_FREE) {
			status = SSTMAC_EpPostDataCancel(dg_ptr->sstmac_ep);
			if ((status != SSTMAC_RC_SUCCESS) &&
					(status != SSTMAC_RC_NO_MATCH)) {
				ret = sstmacxu_to_fi_errno(status);
				goto err;
			}
		}
		dlist_remove_init(&dg_ptr->list);
	}

	dlist_for_each_safe(&the_hndl->wc_dgram_active_list, p, next, list) {
		dg_ptr = p;
		if (dg_ptr->state == SSTMACX_DGRAM_STATE_FREE) {
			status = SSTMAC_EpPostDataCancel(dg_ptr->sstmac_ep);
			if ((status != SSTMAC_RC_SUCCESS) &&
					(status != SSTMAC_RC_NO_MATCH)) {
				ret = sstmacxu_to_fi_errno(status);
				goto err;
			}
		}
		dlist_remove_init(&dg_ptr->list);
	}

	/*
	 * destroy all the endpoints
	 */

	n_dgrams = the_hndl->n_dgrams + the_hndl->n_wc_dgrams;
	dg_ptr = the_hndl->dgram_base;

	for (i = 0; i < n_dgrams; i++, dg_ptr++) {
		if (dg_ptr->sstmac_ep != NULL)
			SSTMAC_EpDestroy(dg_ptr->sstmac_ep);
	}

	/*
	 * cancel the progress thread, if any
	 */

	if (the_hndl->progress_thread) {

		ret = pthread_cancel(the_hndl->progress_thread);
		if ((ret != 0) && (ret != ESRCH)) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
			"pthread_cancel returned %d\n", ret);
			goto err;
		}

		ret = pthread_join(the_hndl->progress_thread,
				   NULL);
		if ((ret != 0) && (ret != ESRCH)) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
			"pthread_join returned %d\n", ret);
			goto err;
		}

		SSTMACX_INFO(FI_LOG_EP_CTRL, "pthread_join returned %d\n", ret);
	}
err:
	if (ret != FI_SUCCESS)
		SSTMACX_INFO(FI_LOG_EP_CTRL, "returning error %d\n", ret);
	free(the_hndl->dgram_base);
	free(the_hndl);

	return ret;
}

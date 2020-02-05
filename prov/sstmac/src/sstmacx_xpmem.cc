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
 * Copyright (c) 2016 Los Alamos National Security, LLC.
 *                    All rights reserved.
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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "sstmacx.h"
#include "sstmacx_mr.h"
#include "sstmacx_hashtable.h"
#include "sstmacx_xpmem.h"


#if HAVE_XPMEM

bool sstmacx_xpmem_disabled = false;

#define XPMEM_PAGE_SIZE 4096

static  pthread_mutex_t sstmacx_xpmem_lock = PTHREAD_MUTEX_INITIALIZER;
static xpmem_segid_t sstmacx_my_segid;
static extern "C" int sstmacx_xpmem_ref_cnt;

static void *__sstmacx_xpmem_attach_seg(void *handle,
				     void *address,
				     size_t length,
				     struct _sstmacx_fi_reg_context *,
				     void *context);

static int __sstmacx_xpmem_detach_seg(void *handle,
				   void *context);

static int __sstmacx_xpmem_destroy_mr_cache(void *context);

struct sstmacx_xpmem_ht_entry {
	struct sstmacx_mr_cache *mr_cache;
	struct sstmacx_xpmem_handle *xp_hndl;
	xpmem_apid_t apid;
};

/*
 * TODO: should be adjustable from domain params
 * Note notifier is set to NULL since xpmem device driver
 * handles mmu notifiers internally so we don't need to use
 * KDREG.
 */
static sstmacx_mr_cache_attr_t _sstmacx_xpmem_default_mr_cache_attr = {
		.soft_reg_limit      = 128,
		.hard_reg_limit      = 16384,
		.hard_stale_limit    = 128,
#if HAVE_KDREG
		.lazy_deregistration = 1,
#else
		.lazy_deregistration = 0,
#endif
		.reg_callback        = __sstmacx_xpmem_attach_seg,
		.dereg_callback      = __sstmacx_xpmem_detach_seg,
		.destruct_callback   = __sstmacx_xpmem_destroy_mr_cache,
		.elem_size           = sizeof(struct sstmacx_xpmem_access_handle),
		.smrn                = NULL,
};

/*******************************************************************************
 * INTERNAL HELPER FNS
 ******************************************************************************/

static void __xpmem_hndl_destruct(void *obj)
{
	int __attribute__((unused)) ret;
	struct sstmacx_xpmem_handle *hndl = (struct sstmacx_xpmem_handle *) obj;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	ret = _sstmacx_ht_destroy(hndl->apid_ht);
	if (ret == FI_SUCCESS) {
		free(hndl->apid_ht);
		hndl->apid_ht = NULL;
	} else {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			"_sstmacx_ht_destroy returned %s\n",
			  fi_strerror(-ret));
	}

	pthread_mutex_lock(&sstmacx_xpmem_lock);

	sstmacx_xpmem_ref_cnt--;
	/*
	 * if refcnt drops to zero for entire xpmem use, remove
	 * this process' segment from xpmem.
	 */
	if (sstmacx_xpmem_ref_cnt == 0) {
		ret = xpmem_remove(sstmacx_my_segid);
		if (ret)
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				 "xpmem_remove returned error %s\n",
				 strerror(errno));
	}

	pthread_mutex_unlock(&sstmacx_xpmem_lock);

	free(hndl);
}

static void __sstmacx_xpmem_destroy_ht_entry(void *val)
{
	int __attribute__((unused)) ret;
	struct sstmacx_xpmem_ht_entry *entry = (struct sstmacx_xpmem_ht_entry *)val;

	SSTMACX_TRACE(FI_LOG_EP_DATA, "\n");

	ret = _sstmacx_mr_cache_destroy(entry->mr_cache);
	if (ret != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			 "_sstmacx_mr_cache_destroy returned error %s\n",
			 fi_strerror(-ret));

	xpmem_release(entry->apid);
	free(entry);
}

static void *__sstmacx_xpmem_attach_seg(void *handle,
				     void *address,
				     size_t length,
				     struct _sstmacx_fi_reg_context *reg_context,
				     void *context)
{
	struct sstmacx_xpmem_access_handle *access_hndl =
		(struct sstmacx_xpmem_access_handle *)handle;
	struct sstmacx_xpmem_ht_entry *entry = context;
	struct xpmem_addr xpmem_addr;
	size_t top, attach_len;

	SSTMACX_TRACE(FI_LOG_EP_DATA, "\n");

	xpmem_addr.apid   = entry->apid;

	/*
	 * xpmem requires page aligned addresses for attach operation
	 */
	xpmem_addr.offset = (off_t) FLOOR((uint64_t)address, XPMEM_PAGE_SIZE);
	top = CEILING(((uint64_t)address + length), XPMEM_PAGE_SIZE);
	attach_len = top - FLOOR((uint64_t)address, XPMEM_PAGE_SIZE);

	access_hndl->attach_addr =  xpmem_attach(xpmem_addr,
					    attach_len,
					    NULL);
	if (access_hndl->attach_addr != (void *)-1L) {
		access_hndl->xp_hndl = entry->xp_hndl;
		_sstmacx_ref_get(entry->xp_hndl);
		access_hndl->remote_base_addr = (void *)xpmem_addr.offset;
		access_hndl->access_len = attach_len;
		access_hndl->entry = entry;
		return handle;
	} else {
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "xpmem_attach returned %s xpmem_addr %ld:0x%016lx len %d\n",
			   strerror(errno), xpmem_addr.apid, xpmem_addr.offset,
			   attach_len);
		/* TODO: dump /proc/self/maps ? */
		exit(-1);
		return NULL;
	}
}

static int __sstmacx_xpmem_detach_seg(void *handle, void *context)
{
	int ret;
	struct sstmacx_xpmem_access_handle *access_hndl;

	SSTMACX_TRACE(FI_LOG_EP_DATA, "\n");

	access_hndl = (struct sstmacx_xpmem_access_handle *)handle;
	assert(access_hndl);

	ret = xpmem_detach(access_hndl->attach_addr);
	if (ret)
		SSTMACX_WARN(FI_LOG_EP_DATA, "xpmem_detach returned %s\n",
			  strerror(errno));
	_sstmacx_ref_put(access_hndl->xp_hndl);
	return ret;
}

/*
 * TODO: do we need a destructor callback for mr cache?
 */
static int __sstmacx_xpmem_destroy_mr_cache(void *context)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");
	/*
	 * use iterator over mr cache entries and invoke
	 * xpmem_detach on each
	 */
	return FI_SUCCESS;
}

/*******************************************************************************
 * the stuff
 ******************************************************************************/

extern "C" int _sstmacx_xpmem_handle_create(struct sstmacx_fid_domain *dom,
			      struct sstmacx_xpmem_handle **handle)
{
	int ret = FI_SUCCESS;
	struct sstmacx_xpmem_handle *hndl = NULL;
	struct sstmacx_hashtable_attr ht_attr = {0};

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	hndl = calloc(1, sizeof *hndl);
	if (!hndl)
		return -FI_ENOMEM;

	pthread_mutex_lock(&sstmacx_xpmem_lock);

	if (sstmacx_xpmem_ref_cnt == 0) {
		sstmacx_my_segid = xpmem_make(0, XPMEM_MAXADDR_SIZE,
					   XPMEM_PERMIT_MODE,
					   (void *)0666);
		if (sstmacx_my_segid == -1L) {
			SSTMACX_WARN(FI_LOG_DOMAIN, "xpmem make failed - %s\n",
				  strerror(errno));
			ret = -errno;
			pthread_mutex_unlock(&sstmacx_xpmem_lock);
			goto exit;
		}

		sstmacx_xpmem_ref_cnt++;
	}

	pthread_mutex_unlock(&sstmacx_xpmem_lock);

	_sstmacx_ref_init(&hndl->ref_cnt, 1,
			__xpmem_hndl_destruct);
	fastlock_init(&hndl->lock);

	/*
	 * initialize xpmem_apid_t key'd hash table for
	 * retrieving r/b tree for that apid
	 */

	hndl->apid_ht = calloc(1, sizeof(struct sstmacx_hashtable));
	if (hndl->apid_ht == NULL)
		goto exit;

	/*
	 * TODO: use domain parameters to adjust these
	 */

	ht_attr.ht_initial_size = 1024; /* will we ever have more than
					   this many local processes? */
	ht_attr.ht_maximum_size = 1024 * 1024;
	ht_attr.ht_increase_step = 1024;
	ht_attr.ht_increase_type = SSTMACX_HT_INCREASE_MULT;
	ht_attr.ht_collision_thresh = 500;
	ht_attr.ht_hash_seed = 0xdeadbeefbeefdead;
	ht_attr.ht_internal_locking = 0;
	ht_attr.destructor = __sstmacx_xpmem_destroy_ht_entry;

	ret = _sstmacx_ht_init(hndl->apid_ht,
			    &ht_attr);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "_sstmacx_ht_init returned %s\n",
			  fi_strerror(-ret));
		goto exit;
	}

	*handle = hndl;
	return ret;

exit:
	if (hndl != NULL) {
		if (hndl->apid_ht != NULL)
			free(hndl->apid_ht);
		free(hndl);
	}

	return ret;
}

extern "C" int _sstmacx_xpmem_handle_destroy(struct sstmacx_xpmem_handle *hndl)
{
	int ret = FI_SUCCESS;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	_sstmacx_ref_put(hndl);

	return ret;
}


extern "C" int _sstmacx_xpmem_access_hndl_get(struct sstmacx_xpmem_handle *xp_hndl,
			     xpmem_apid_t peer_apid,
			     uint64_t remote_vaddr,
			     size_t len,
			     struct sstmacx_xpmem_access_handle  **access_hndl)
{
	int ret = FI_SUCCESS;
	struct sstmacx_xpmem_ht_entry *entry;
        sstmacx_mr_cache_attr_t mr_cache_attr = {0};

	SSTMACX_TRACE(FI_LOG_EP_DATA, "\n");

	/*
	 * use peer_apid to look up the reg cache
	 *  - if not in the hash, create and insert
	 */

	fastlock_acquire(&xp_hndl->lock);

	entry = _sstmacx_ht_lookup(xp_hndl->apid_ht,
			      (sstmacx_ht_key_t)peer_apid);

	/*
	 * okay need to create an mr_cache for this apid
	 */
	if (OFI_UNLIKELY(entry == NULL)) {

		entry = calloc(1, sizeof *entry);
		if (entry == NULL) {
			ret = -FI_ENOMEM;
			goto exit_w_lock;
		}

		entry->apid = peer_apid;
		entry->xp_hndl = xp_hndl;

		memcpy(&mr_cache_attr, &_sstmacx_xpmem_default_mr_cache_attr,
			sizeof(sstmacx_mr_cache_attr_t));
		mr_cache_attr.reg_context = entry;
		mr_cache_attr.dereg_context = entry;
		mr_cache_attr.destruct_context = entry;
		ret = _sstmacx_mr_cache_init(&entry->mr_cache,
					  &mr_cache_attr);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				 "_sstmacx_mr_cache_init returned %s\n",
				fi_strerror(-ret));
			goto exit_w_lock;
		}
		ret = _sstmacx_ht_insert(xp_hndl->apid_ht,
				      (sstmacx_ht_key_t)peer_apid,
				      entry);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_DATA,
				 "_sstmacx_ht_insert returned %s\n",
				fi_strerror(-ret));
			goto exit_w_lock;
		}
	}

	ret = _sstmacx_mr_cache_register(entry->mr_cache,
				      remote_vaddr,
				      len,
				      NULL,
				      (void **)access_hndl);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_DATA,
			  "_sstmacx_mr_cache_register returned %s\n",
			   fi_strerror(-ret));
		goto exit_w_lock;
	}

exit_w_lock:
	fastlock_release(&xp_hndl->lock);
	return ret;

}

extern "C" int _sstmacx_xpmem_access_hndl_put(struct sstmacx_xpmem_access_handle *access_hndl)
{
	int ret = FI_SUCCESS;
	struct sstmacx_xpmem_ht_entry *entry;
	struct sstmacx_xpmem_handle *xp_hndl;

	SSTMACX_TRACE(FI_LOG_EP_DATA, "\n");

	entry = access_hndl->entry;
	if (!entry) {
		SSTMACX_WARN(FI_LOG_EP_DATA, "entry is null\n");
		return -FI_EINVAL;
	}

	xp_hndl = entry->xp_hndl;
	if (!xp_hndl) {
		SSTMACX_WARN(FI_LOG_EP_DATA, "entry->xp_hndl is null\n");
		return -FI_EINVAL;
	}

	fastlock_acquire(&xp_hndl->lock);

	ret = _sstmacx_mr_cache_deregister(entry->mr_cache,
					access_hndl);
	if (ret != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_EP_DATA, "_sstmacx_mr_cache_deregister returned %s\n",
			  fi_strerror(-ret));

	fastlock_release(&xp_hndl->lock);

	return ret;
}

extern "C" int _sstmacx_xpmem_accessible(struct sstmacx_fid_ep *ep,
			   struct sstmacx_address addr,
			   bool *accessible)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (!ep || !accessible)
		return -FI_EINVAL;

	if (sstmacx_xpmem_disabled == true) {
		*accessible = false;
		return FI_SUCCESS;
	}

	if (ep->domain->params.xpmem_enabled == false) {
		*accessible = false;
		return FI_SUCCESS;
	}

	/*
	 * if the endpoint's device_addr is the same as tht
	 * of the supplied address, return true, else false
	 */

	*accessible = (ep->src_addr.sstmacx_addr.device_addr ==
			addr.device_addr) ? true : false;

	return FI_SUCCESS;
}

extern "C" int _sstmacx_xpmem_copy(struct sstmacx_xpmem_access_handle *access_hndl,
		     void *dst_addr,
		     void *remote_start_addr,
		     size_t len)
{
	void *local_start_addr, *remote_base_addr;
	uint64_t attach_addr, reg_len;

	SSTMACX_TRACE(FI_LOG_EP_DATA, "\n");

	if (!access_hndl)
		return -FI_EINVAL;

	attach_addr = (uint64_t)access_hndl->attach_addr;
	remote_base_addr = access_hndl->remote_base_addr;
	reg_len = access_hndl->access_len;

	/*
	 * check that the access handle limits and the
	 * copy request are consistent
	 */

	if (((uint64_t)remote_start_addr < (uint64_t)remote_base_addr) ||
		((uint64_t)remote_start_addr >=
			((uint64_t)remote_base_addr + reg_len)))
		return -FI_EINVAL;

	if (((uint64_t)remote_start_addr + len) >
			((uint64_t)remote_base_addr + reg_len))
		return -FI_EINVAL;

	local_start_addr = (void *)((uint8_t *)attach_addr +
				    ((uint8_t *)remote_start_addr -
				     (uint8_t *)remote_base_addr));
	SSTMACX_DEBUG(FI_LOG_EP_DATA,
		  "xpmem copy dst addr 0x%016lx start addr 0x%016lx, len %ld\n",
		    (uint64_t)dst_addr, (uint64_t)local_start_addr, len);
	memcpy(dst_addr, local_start_addr, len);

	return FI_SUCCESS;
}

extern "C" int _sstmacx_xpmem_get_my_segid(struct sstmacx_xpmem_handle *xp_hndl,
			     xpmem_segid_t *seg_id)
{
	int ret = FI_SUCCESS;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	*seg_id = sstmacx_my_segid;
	return ret;

}

extern "C" int _sstmacx_xpmem_get_apid(struct sstmacx_xpmem_handle *xp_hndl,
			 xpmem_segid_t segid,
			 xpmem_apid_t *peer_apid)
{
	int ret = FI_SUCCESS;
	xpmem_apid_t apid;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	apid = xpmem_get(segid, XPMEM_RDWR, XPMEM_PERMIT_MODE,
			 (void *)0666);
	if (apid == -1L) {
		SSTMACX_WARN(FI_LOG_DOMAIN, "xpmem_get returned %s\n",
			  strerror(errno));
		ret = -errno;
	} else {
		*peer_apid = apid;
	}

	return ret;
}

#else

bool sstmacx_xpmem_disabled = true;

/*******************************************************************************
 * almost stub functions when xpmem configuration is disabled
 ******************************************************************************/

extern "C" int _sstmacx_xpmem_handle_create(struct sstmacx_fid_domain *dom,
			      struct sstmacx_xpmem_handle **handle)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");
	return FI_SUCCESS;
}

extern "C" int _sstmacx_xpmem_handle_destroy(struct sstmacx_xpmem_handle *hndl)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");
	return FI_SUCCESS;
}


extern "C" int _sstmacx_xpmem_access_hndl_get(struct sstmacx_xpmem_handle *xp_hndl,
			     xpmem_apid_t peer_apid,
			     uint64_t remote_vaddr,
			     size_t len,
			     struct sstmacx_xpmem_access_handle  **access_hndl)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");
	return FI_SUCCESS;
}

extern "C" int _sstmacx_xpmem_access_hndl_put(struct sstmacx_xpmem_access_handle *access_hndl)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");
	return FI_SUCCESS;
}

extern "C" int _sstmacx_xpmem_accessible(struct sstmacx_fid_ep *ep,
			   struct sstmacx_address addr,
			   bool *accessible)
{

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (accessible == NULL)
		return -FI_EINVAL;

	*accessible = false;

	return FI_SUCCESS;
}

extern "C" int _sstmacx_xpmem_copy(struct sstmacx_xpmem_access_handle *access_hndl,
		     void *dst_addr,
		     void *remote_start_addr,
		     size_t len)
{
	return -FI_ENOSYS;
}

extern "C" int _sstmacx_xpmem_get_my_segid(struct sstmacx_xpmem_handle *xp_hndl,
			     xpmem_segid_t *seg_id)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");
	return FI_SUCCESS;
}

extern "C" int _sstmacx_xpmem_get_apid(struct sstmacx_xpmem_handle *xp_hndl,
			 xpmem_segid_t segid,
			 xpmem_apid_t *peer_apid)
{
	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");
	return FI_SUCCESS;
}

#endif /* HAVE_XPMEM */

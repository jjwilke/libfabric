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
 * Copyright (c) 2015-2018 Los Alamos National Security, LLC.
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
#include "sstmacx_nic.h"
#include "sstmacx_util.h"
#include "sstmacx_xpmem.h"
#include "sstmacx_hashtable.h"
#include "sstmacx_auth_key.h"
#include "sstmacx_smrn.h"

#define SSTMACX_MR_MODE_DEFAULT FI_MR_BASIC
#define SSTMACX_NUM_PTAGS 256

sstmac_cq_mode_t sstmacx_def_sstmac_cq_modes = SSTMAC_CQ_PHYS_PAGES;

static char *__sstmacx_mr_type_to_str[SSTMACX_MR_MAX_TYPE] = {
		[SSTMACX_MR_TYPE_INTERNAL] = "internal",
		[SSTMACX_MR_TYPE_UDREG] = "udreg",
		[SSTMACX_MR_TYPE_NONE] = "none",
};

/*******************************************************************************
 * Forward declaration for ops structures.
 ******************************************************************************/

static struct fi_ops sstmacx_stx_ops;
static struct fi_ops sstmacx_domain_fi_ops;
static struct fi_ops_mr sstmacx_domain_mr_ops;
static struct fi_ops_domain sstmacx_domain_ops;

static void __domain_destruct(void *obj)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_domain *domain = (struct sstmacx_fid_domain *) obj;
	struct sstmacx_mr_cache_info *info;
	int i;

	SSTMACX_TRACE(FI_LOG_DOMAIN, "\n");

	for (i = 0; i < SSTMACX_NUM_PTAGS; i++) {
		info = &domain->mr_cache_info[i];

		fastlock_acquire(&info->mr_cache_lock);
		ret = _sstmacx_close_cache(domain, info);
		fastlock_release(&info->mr_cache_lock);

		if (ret != FI_SUCCESS)
			SSTMACX_FATAL(FI_LOG_MR,
					"failed to close memory "
					"registration cache\n");
	}

	free(domain->mr_cache_info);

	ret = _sstmacx_smrn_close(domain->mr_cache_attr.smrn);
	if (ret != FI_SUCCESS)
		SSTMACX_FATAL(FI_LOG_MR, "failed to close MR notifier\n");

	/*
	 * remove from the list of cdms attached to fabric
	 */
	dlist_remove_init(&domain->list);

	_sstmacx_ref_put(domain->fabric);

	memset(domain, 0, sizeof *domain);
	free(domain);
}

static void __stx_destruct(void *obj)
{
	int ret;
	struct sstmacx_fid_stx *stx = (struct sstmacx_fid_stx *) obj;

	SSTMACX_TRACE(FI_LOG_DOMAIN, "\n");

	if (stx->nic) {
		ret = _sstmacx_nic_free(stx->nic);
		if (ret != FI_SUCCESS)
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				    "_sstmacx_nic_free call returned %s\n",
			     fi_strerror(-ret));
	}

	memset(stx, 0, sizeof(*stx));
	free(stx);
}

/*******************************************************************************
 * API function implementations.
 ******************************************************************************/

/**
 * Creates a shared transmit context.
 *
 * @param[in]  val  value to be sign extended
 * @param[in]  len  length to sign extend the value
 * @return     FI_SUCCESS if shared tx context successfully created
 * @return     -FI_EINVAL if invalid arg(s) supplied
 * @return     -FI_ENOMEM insufficient memory
 */
DIRECT_FN STATIC extern "C" int sstmacx_stx_open(struct fid_domain *dom,
				   struct fi_tx_attr *tx_attr,
				   struct fid_stx **stx, void *context)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_domain *domain;
	struct sstmacx_fid_stx *stx_priv;

	SSTMACX_TRACE(FI_LOG_DOMAIN, "\n");

	domain = container_of(dom, struct sstmacx_fid_domain, domain_fid.fid);
	if (domain->domain_fid.fid.fclass != FI_CLASS_DOMAIN) {
		ret = -FI_EINVAL;
		goto err;
	}

	stx_priv = calloc(1, sizeof(*stx_priv));
	if (!stx_priv) {
		ret = -FI_ENOMEM;
		goto err;
	}

	stx_priv->domain = domain;
	stx_priv->auth_key = NULL;
	stx_priv->nic = NULL;

	_sstmacx_ref_init(&stx_priv->ref_cnt, 1, __stx_destruct);

	_sstmacx_ref_get(stx_priv->domain);

	stx_priv->stx_fid.fid.fclass = FI_CLASS_STX_CTX;
	stx_priv->stx_fid.fid.context = context;
	stx_priv->stx_fid.fid.ops = &sstmacx_stx_ops;
	stx_priv->stx_fid.ops = NULL;
	domain->num_allocd_stxs++;

	*stx = &stx_priv->stx_fid;

err:
	return ret;
}

/**
 * Destroy a shared transmit context.
 *
 * @param[in]  fid  fid for previously allocated sstmacx_fid_stx
 *                  structure
 * @return     FI_SUCCESS if shared tx context successfully closed
 * @return     -FI_EINVAL if invalid arg(s) supplied
 *
 * @note - the structure will actually not be freed till all
 *         references to the structure have released their references
 *         to the stx structure.
 */
static extern "C" int sstmacx_stx_close(fid_t fid)
{
	struct sstmacx_fid_stx *stx;

	SSTMACX_TRACE(FI_LOG_DOMAIN, "\n");

	stx = container_of(fid, struct sstmacx_fid_stx, stx_fid.fid);
	if (stx->stx_fid.fid.fclass != FI_CLASS_STX_CTX)
		return -FI_EINVAL;

	_sstmacx_ref_put(stx->domain);
	_sstmacx_ref_put(stx);

	return FI_SUCCESS;
}

static extern "C" int sstmacx_domain_close(fid_t fid)
{
	int ret = FI_SUCCESS, references_held;
	struct sstmacx_fid_domain *domain;
	int i;
	struct sstmacx_mr_cache_info *info;

	SSTMACX_TRACE(FI_LOG_DOMAIN, "\n");

	domain = container_of(fid, struct sstmacx_fid_domain, domain_fid.fid);
	if (domain->domain_fid.fid.fclass != FI_CLASS_DOMAIN) {
		ret = -FI_EINVAL;
		goto err;
	}

	for (i = 0; i < SSTMACX_NUM_PTAGS; i++) {
		info = &domain->mr_cache_info[i];

		if (!domain->mr_cache_info[i].inuse)
			continue;

		/* before checking the refcnt,
		 * flush the memory registration cache
		 */
		if (info->mr_cache_ro) {
			fastlock_acquire(&info->mr_cache_lock);
			ret = _sstmacx_mr_cache_flush(info->mr_cache_ro);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_DOMAIN,
					  "failed to flush memory cache on domain close\n");
				fastlock_release(&info->mr_cache_lock);
				goto err;
			}
			fastlock_release(&info->mr_cache_lock);
		}

		if (info->mr_cache_rw) {
			fastlock_acquire(&info->mr_cache_lock);
			ret = _sstmacx_mr_cache_flush(info->mr_cache_rw);
			if (ret != FI_SUCCESS) {
				SSTMACX_WARN(FI_LOG_DOMAIN,
					  "failed to flush memory cache on domain close\n");
				fastlock_release(&info->mr_cache_lock);
				goto err;
			}
			fastlock_release(&info->mr_cache_lock);
		}
	}

	/*
	 * if non-zero refcnt, there are eps, mrs, and/or an eq associated
	 * with this domain which have not been closed.
	 */

	references_held = _sstmacx_ref_put(domain);

	if (references_held) {
		SSTMACX_INFO(FI_LOG_DOMAIN, "failed to fully close domain due to "
			  "lingering references. references=%i dom=%p\n",
			  references_held, domain);
	}

	SSTMACX_INFO(FI_LOG_DOMAIN, "sstmacx_domain_close invoked returning %d\n",
		  ret);
err:
	return ret;
}

/*
 * sstmacx_domain_ops provides a means for an application to better
 * control allocation of underlying aries resources associated with
 * the domain.  Examples will include controlling size of underlying
 * hardware CQ sizes, max size of RX ring buffers, etc.
 */

static const uint32_t default_msg_rendezvous_thresh = 16*1024;
static const uint32_t default_rma_rdma_thresh = 8*1024;
static const uint32_t default_ct_init_size = 64;
static const uint32_t default_ct_max_size = 16384;
static const uint32_t default_ct_step = 2;
static const uint32_t default_vc_id_table_capacity = 128;
static const uint32_t default_mbox_page_size = SSTMACX_PAGE_2MB;
static const uint32_t default_mbox_num_per_slab = 2048;
static const uint32_t default_mbox_maxcredit = 64;
static const uint32_t default_mbox_msg_maxsize = 16384;
/* rx cq bigger to avoid having to deal with rx overruns so much */
static const uint32_t default_rx_cq_size = 16384;
static const uint32_t default_tx_cq_size = 2048;
static const uint32_t default_max_retransmits = 5;
static const int32_t default_err_inject_count; /* static var is zeroed */
static const uint32_t default_dgram_progress_timeout = 100;
static const uint32_t default_eager_auto_progress = 0;

static int __sstmacx_string_to_mr_type(const char *name)
{
	int i;
	for (i = 0; i < SSTMACX_MR_MAX_TYPE; i++)
		if (strncmp(name, __sstmacx_mr_type_to_str[i],
				strlen(__sstmacx_mr_type_to_str[i])) == 0)
			return i;

	return -1;
}

static int
__sstmacx_dom_ops_flush_cache(struct fid *fid)
{
	struct sstmacx_fid_domain *domain;

	SSTMACX_TRACE(FI_LOG_DOMAIN, "\n");

	domain = container_of(fid, struct sstmacx_fid_domain, domain_fid.fid);
	if (domain->domain_fid.fid.fclass != FI_CLASS_DOMAIN) {
		SSTMACX_WARN(FI_LOG_DOMAIN, ("Invalid domain\n"));
		return -FI_EINVAL;
	}

	return _sstmacx_flush_registration_cache(domain);
}

static int
__sstmacx_dom_ops_get_val(struct fid *fid, dom_ops_val_t t, void *val)
{
	struct sstmacx_fid_domain *domain;

	SSTMACX_TRACE(FI_LOG_DOMAIN, "\n");

	assert(val);

	domain = container_of(fid, struct sstmacx_fid_domain, domain_fid.fid);
	if (domain->domain_fid.fid.fclass != FI_CLASS_DOMAIN) {
		SSTMACX_WARN(FI_LOG_DOMAIN, ("Invalid domain\n"));
		return -FI_EINVAL;
	}

	switch (t) {
	case SSTMAC_MSG_RENDEZVOUS_THRESHOLD:
		*(uint32_t *)val = domain->params.msg_rendezvous_thresh;
		break;
	case SSTMAC_RMA_RDMA_THRESHOLD:
		*(uint32_t *)val = domain->params.rma_rdma_thresh;
		break;
	case SSTMAC_CONN_TABLE_INITIAL_SIZE:
		*(uint32_t *)val = domain->params.ct_init_size;
		break;
	case SSTMAC_CONN_TABLE_MAX_SIZE:
		*(uint32_t *)val = domain->params.ct_max_size;
		break;
	case SSTMAC_CONN_TABLE_STEP_SIZE:
		*(uint32_t *)val = domain->params.ct_step;
		break;
	case SSTMAC_VC_ID_TABLE_CAPACITY:
		*(uint32_t *)val = domain->params.vc_id_table_capacity;
		break;
	case SSTMAC_MBOX_PAGE_SIZE:
		*(uint32_t *)val = domain->params.mbox_page_size;
		break;
	case SSTMAC_MBOX_NUM_PER_SLAB:
		*(uint32_t *)val = domain->params.mbox_num_per_slab;
		break;
	case SSTMAC_MBOX_MAX_CREDIT:
		*(uint32_t *)val = domain->params.mbox_maxcredit;
		break;
	case SSTMAC_MBOX_MSG_MAX_SIZE:
		*(uint32_t *)val = domain->params.mbox_msg_maxsize;
		break;
	case SSTMAC_RX_CQ_SIZE:
		*(uint32_t *)val = domain->params.rx_cq_size;
		break;
	case SSTMAC_TX_CQ_SIZE:
		*(uint32_t *)val = domain->params.tx_cq_size;
		break;
	case SSTMAC_MAX_RETRANSMITS:
		*(uint32_t *)val = domain->params.max_retransmits;
		break;
	case SSTMAC_ERR_INJECT_COUNT:
		*(int32_t *)val = domain->params.err_inject_count;
		break;
	case SSTMAC_MR_CACHE_LAZY_DEREG:
		*(int32_t *)val = domain->mr_cache_attr.lazy_deregistration;
		break;
	case SSTMAC_MR_CACHE:
		*(char **) val = __sstmacx_mr_type_to_str[domain->mr_cache_type];
		break;
	case SSTMAC_MR_UDREG_REG_LIMIT:
		*(int32_t *)val = domain->udreg_reg_limit;
		break;
	case SSTMAC_MR_HARD_REG_LIMIT:
		*(int32_t *)val = domain->mr_cache_attr.hard_reg_limit;
		break;
	case SSTMAC_MR_SOFT_REG_LIMIT:
		*(int32_t *)val = domain->mr_cache_attr.soft_reg_limit;
		break;
	case SSTMAC_MR_HARD_STALE_REG_LIMIT:
		*(int32_t *)val = domain->mr_cache_attr.hard_stale_limit;
		break;
	case SSTMAC_XPMEM_ENABLE:
		*(bool *)val = domain->params.xpmem_enabled;
#if !HAVE_XPMEM
		SSTMACX_WARN(FI_LOG_DOMAIN,
			  "SSTMAC provider XPMEM support not configured\n");
#endif
		break;
	case SSTMAC_DGRAM_PROGRESS_TIMEOUT:
		*(uint32_t *)val = domain->params.dgram_progress_timeout;
		break;
	case SSTMAC_EAGER_AUTO_PROGRESS:
		*(uint32_t *)val = domain->params.eager_auto_progress;
		break;
	default:
		SSTMACX_WARN(FI_LOG_DOMAIN, ("Invalid dom_ops_val\n"));
		return -FI_EINVAL;
	}

	return FI_SUCCESS;
}

static int
__sstmacx_dom_ops_set_val(struct fid *fid, dom_ops_val_t t, void *val)
{
	struct sstmacx_fid_domain *domain;
	int ret, type;

	SSTMACX_TRACE(FI_LOG_DOMAIN, "\n");

	assert(val);

	domain = container_of(fid, struct sstmacx_fid_domain, domain_fid.fid);
	if (domain->domain_fid.fid.fclass != FI_CLASS_DOMAIN) {
		SSTMACX_WARN(FI_LOG_DOMAIN, ("Invalid domain\n"));
		return -FI_EINVAL;
	}

	switch (t) {
	case SSTMAC_MSG_RENDEZVOUS_THRESHOLD:
		domain->params.msg_rendezvous_thresh = *(uint32_t *)val;
		break;
	case SSTMAC_RMA_RDMA_THRESHOLD:
		domain->params.rma_rdma_thresh = *(uint32_t *)val;
		break;
	case SSTMAC_CONN_TABLE_INITIAL_SIZE:
		domain->params.ct_init_size = *(uint32_t *)val;
		break;
	case SSTMAC_CONN_TABLE_MAX_SIZE:
		domain->params.ct_max_size = *(uint32_t *)val;
		break;
	case SSTMAC_CONN_TABLE_STEP_SIZE:
		domain->params.ct_step = *(uint32_t *)val;
		break;
	case SSTMAC_VC_ID_TABLE_CAPACITY:
		domain->params.vc_id_table_capacity = *(uint32_t *)val;
		break;
	case SSTMAC_MBOX_PAGE_SIZE:
		domain->params.mbox_page_size = *(uint32_t *)val;
		break;
	case SSTMAC_MBOX_NUM_PER_SLAB:
		domain->params.mbox_num_per_slab = *(uint32_t *)val;
		break;
	case SSTMAC_MBOX_MAX_CREDIT:
		domain->params.mbox_maxcredit = *(uint32_t *)val;
		break;
	case SSTMAC_MBOX_MSG_MAX_SIZE:
		domain->params.mbox_msg_maxsize = *(uint32_t *)val;
		break;
	case SSTMAC_RX_CQ_SIZE:
		domain->params.rx_cq_size = *(uint32_t *)val;
		break;
	case SSTMAC_TX_CQ_SIZE:
		domain->params.tx_cq_size = *(uint32_t *)val;
		break;
	case SSTMAC_MAX_RETRANSMITS:
		domain->params.max_retransmits = *(uint32_t *)val;
		break;
	case SSTMAC_ERR_INJECT_COUNT:
		domain->params.err_inject_count = *(int32_t *)val;
		break;
	case SSTMAC_MR_CACHE_LAZY_DEREG:
		domain->mr_cache_attr.lazy_deregistration = *(int32_t *)val;
		break;
	case SSTMAC_MR_CACHE:
		if (val != NULL) {
			SSTMACX_DEBUG(FI_LOG_DOMAIN, "user provided value=%s\n",
					*(char **) val);

			type = __sstmacx_string_to_mr_type(*(const char **) val);
			if (type < 0 || type >= SSTMACX_MR_MAX_TYPE)
				return -FI_EINVAL;

			SSTMACX_DEBUG(FI_LOG_DOMAIN, "setting domain mr type to %s\n",
					__sstmacx_mr_type_to_str[type]);

			ret = _sstmacx_open_cache(domain, type);
			if (ret != FI_SUCCESS)
				return -FI_EINVAL;
		}
		break;
	case SSTMAC_MR_HARD_REG_LIMIT:
		domain->mr_cache_attr.hard_reg_limit = *(int32_t *) val;
		break;
	case SSTMAC_MR_SOFT_REG_LIMIT:
		domain->mr_cache_attr.soft_reg_limit = *(int32_t *) val;
		break;
	case SSTMAC_MR_HARD_STALE_REG_LIMIT:
		domain->mr_cache_attr.hard_stale_limit = *(int32_t *) val;
		break;
	case SSTMAC_MR_UDREG_REG_LIMIT:
		if (*(int32_t *) val < 0)
			return -FI_EINVAL;
		domain->udreg_reg_limit = *(int32_t *) val;
		break;
	case SSTMAC_XPMEM_ENABLE:
#if HAVE_XPMEM
		domain->params.xpmem_enabled = *(bool *)val;
#else
		SSTMACX_WARN(FI_LOG_DOMAIN,
			  "SSTMAC provider XPMEM support not configured\n");
#endif
		break;
	case SSTMAC_DGRAM_PROGRESS_TIMEOUT:
		domain->params.dgram_progress_timeout = *(uint32_t *)val;
		break;
	case SSTMAC_EAGER_AUTO_PROGRESS:
		domain->params.eager_auto_progress = *(uint32_t *)val;
		break;
	default:
		SSTMACX_WARN(FI_LOG_DOMAIN, ("Invalid dom_ops_val\n"));
		return -FI_EINVAL;
	}

	return FI_SUCCESS;
}

static struct fi_sstmac_ops_domain sstmacx_ops_domain = {
	.set_val = __sstmacx_dom_ops_set_val,
	.get_val = __sstmacx_dom_ops_get_val,
	.flush_cache = __sstmacx_dom_ops_flush_cache,
};

DIRECT_FN extern "C" int sstmacx_domain_bind(struct fid_domain *domain, struct fid *fid,
			       uint64_t flags)
{
	return -FI_ENOSYS;
}

static int
sstmacx_domain_ops_open(struct fid *fid, const char *ops_name, uint64_t flags,
		     void **ops, void *context)
{
	int ret = FI_SUCCESS;

	if (strcmp(ops_name, FI_SSTMAC_DOMAIN_OPS_1) == 0)
		*ops = &sstmacx_ops_domain;
	else
		ret = -FI_EINVAL;

	return ret;
}

DIRECT_FN extern "C" int sstmacx_domain_open(struct fid_fabric *fabric, struct fi_info *info,
			       struct fid_domain **dom, void *context)
{
	struct sstmacx_fid_domain *domain = NULL;
	int ret = FI_SUCCESS;
	struct sstmacx_fid_fabric *fabric_priv;
	struct sstmacx_auth_key *auth_key = NULL;
	int i;
	int requesting_vmdh = 0;

	SSTMACX_TRACE(FI_LOG_DOMAIN, "\n");

	fabric_priv = container_of(fabric, struct sstmacx_fid_fabric, fab_fid);

	if (FI_VERSION_LT(fabric->api_version, FI_VERSION(1, 5)) &&
		(info->domain_attr->auth_key_size || info->domain_attr->auth_key))
			return -FI_EINVAL;

	requesting_vmdh = !(info->domain_attr->mr_mode &
			(FI_MR_BASIC | FI_MR_VIRT_ADDR));

	auth_key = SSTMACX_GET_AUTH_KEY(info->domain_attr->auth_key,
			info->domain_attr->auth_key_size, requesting_vmdh);
	if (!auth_key)
		return -FI_EINVAL;

	SSTMACX_INFO(FI_LOG_DOMAIN,
		  "authorization key=%p ptag %u cookie 0x%x\n",
		  auth_key, auth_key->ptag, auth_key->cookie);

	if (auth_key->using_vmdh != requesting_vmdh) {
		SSTMACX_WARN(FI_LOG_DOMAIN,
			"SSTMACX provider cannot support multiple "
			"FI_MR_BASIC and FI_MR_SCALABLE for the same ptag. "
			"ptag=%d current_mode=%x requested_mode=%x\n",
			auth_key->ptag,
			auth_key->using_vmdh, info->domain_attr->mr_mode);
		return -FI_EINVAL;
	}

	domain = calloc(1, sizeof *domain);
	if (domain == NULL) {
		ret = -FI_ENOMEM;
		goto err;
	}

	domain->mr_cache_info = calloc(sizeof(*domain->mr_cache_info),
		SSTMACX_NUM_PTAGS);
	if (!domain->mr_cache_info) {
		ret = -FI_ENOMEM;
		goto err;
	}

	domain->auth_key = auth_key;

	domain->mr_cache_attr = _sstmacx_default_mr_cache_attr;
	domain->mr_cache_attr.reg_context = (void *) domain;
	domain->mr_cache_attr.dereg_context = NULL;
	domain->mr_cache_attr.destruct_context = NULL;

	ret = _sstmacx_smrn_open(&domain->mr_cache_attr.smrn);
	if (ret != FI_SUCCESS)
		goto err;

	fastlock_init(&domain->mr_cache_lock);
	for (i = 0; i < SSTMACX_NUM_PTAGS; i++) {
		domain->mr_cache_info[i].inuse = 0;
		domain->mr_cache_info[i].domain = domain;
		fastlock_init(&domain->mr_cache_info[i].mr_cache_lock);
	}

	/*
	 * we are likely sharing udreg entries with Craypich if we're using udreg
	 * cache, so ask for only half the entries by default.
	 */
	domain->udreg_reg_limit = 2048;

	dlist_init(&domain->nic_list);
	dlist_init(&domain->list);

	dlist_insert_after(&domain->list, &fabric_priv->domain_list);

	domain->fabric = fabric_priv;
	_sstmacx_ref_get(domain->fabric);

	domain->cdm_id_seed = getpid();  /* TODO: direct syscall better */
	domain->addr_format = info->addr_format;

	/* user tunables */
	domain->params.msg_rendezvous_thresh = default_msg_rendezvous_thresh;
	domain->params.rma_rdma_thresh = default_rma_rdma_thresh;
	domain->params.ct_init_size = default_ct_init_size;
	domain->params.ct_max_size = default_ct_max_size;
	domain->params.ct_step = default_ct_step;
	domain->params.vc_id_table_capacity = default_vc_id_table_capacity;
	domain->params.mbox_page_size = default_mbox_page_size;
	domain->params.mbox_num_per_slab = default_mbox_num_per_slab;
	domain->params.mbox_maxcredit = default_mbox_maxcredit;
	domain->params.mbox_msg_maxsize = default_mbox_msg_maxsize;
	domain->params.rx_cq_size = default_rx_cq_size;
	domain->params.tx_cq_size = default_tx_cq_size;
	domain->params.max_retransmits = default_max_retransmits;
	domain->params.err_inject_count = default_err_inject_count;
#if HAVE_XPMEM
	domain->params.xpmem_enabled = true;
#else
	domain->params.xpmem_enabled = false;
#endif
	domain->params.dgram_progress_timeout = default_dgram_progress_timeout;
	domain->params.eager_auto_progress = default_eager_auto_progress;

	domain->sstmac_cq_modes = sstmacx_def_sstmac_cq_modes;
	_sstmacx_ref_init(&domain->ref_cnt, 1, __domain_destruct);

	domain->domain_fid.fid.fclass = FI_CLASS_DOMAIN;
	domain->domain_fid.fid.context = context;
	domain->domain_fid.fid.ops = &sstmacx_domain_fi_ops;
	domain->domain_fid.ops = &sstmacx_domain_ops;
	domain->domain_fid.mr = &sstmacx_domain_mr_ops;

	domain->control_progress = info->domain_attr->control_progress;
	domain->data_progress = info->domain_attr->data_progress;
	domain->thread_model = info->domain_attr->threading;
	domain->mr_is_init = 0;
	domain->mr_iov_limit = info->domain_attr->mr_iov_limit;

	fastlock_init(&domain->cm_nic_lock);

	domain->using_vmdh = requesting_vmdh;

	auth_key->using_vmdh = domain->using_vmdh;
	_sstmacx_auth_key_enable(auth_key);
	domain->auth_key = auth_key;

	if (!requesting_vmdh) {
		_sstmacx_open_cache(domain, SSTMACX_DEFAULT_CACHE_TYPE);
	} else {
		domain->mr_cache_type = SSTMACX_MR_TYPE_NONE;
		_sstmacx_open_cache(domain, SSTMACX_MR_TYPE_NONE);
	}

	*dom = &domain->domain_fid;
	return FI_SUCCESS;

err:
	if (domain && domain->mr_cache_info)
		free(domain->mr_cache_info);

	if (domain != NULL) {
		free(domain);
	}
	return ret;
}

DIRECT_FN extern "C" int sstmacx_srx_context(struct fid_domain *domain,
			       struct fi_rx_attr *attr,
			       struct fid_ep **rx_ep, void *context)
{
	return -FI_ENOSYS;
}

/*******************************************************************************
 * FI_OPS_* data structures.
 ******************************************************************************/

static struct fi_ops sstmacx_stx_ops = {
	.close = sstmacx_stx_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open
};

static struct fi_ops sstmacx_domain_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sstmacx_domain_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = sstmacx_domain_ops_open
};

static struct fi_ops_mr sstmacx_domain_mr_ops = {
	.size = sizeof(struct fi_ops_mr),
	.reg = sstmacx_mr_reg,
	.regv = sstmacx_mr_regv,
	.regattr = sstmacx_mr_regattr,
};

static struct fi_ops_domain sstmacx_domain_ops = {
	.size = sizeof(struct fi_ops_domain),
	.av_open = sstmacx_av_open,
	.cq_open = sstmacx_cq_open,
	.endpoint = sstmacx_ep_open,
	.scalable_ep = sstmacx_sep_open,
	.cntr_open = sstmacx_cntr_open,
	.poll_open = fi_no_poll_open,
	.stx_ctx = sstmacx_stx_open,
	.srx_ctx = fi_no_srx_context
};

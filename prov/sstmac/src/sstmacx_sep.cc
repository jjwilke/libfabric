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
 * Copyright (c) 2016-2018 Los Alamos National Security, LLC.
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

/*
 * Endpoint common code
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sstmacx.h"
#include "sstmacx_cm_nic.h"
#include "sstmacx_ep.h"
#include "sstmacx_vc.h"
#include "sstmacx_util.h"
#include "sstmacx_msg.h"
#include "sstmacx_cntr.h"
#include "sstmacx_rma.h"
#include "sstmacx_atomic.h"

/******************************************************************************
 * Forward declaration for ops structures.
 ******************************************************************************/

static struct fi_ops sstmacx_sep_fi_ops;
static struct fi_ops_ep sstmacx_sep_ops;
/*
static struct fi_ops sstmacx_tx_fi_ops;
static struct fi_ops_ep sstmacx_tx_ops;
*/
static struct fi_ops_cm sstmacx_sep_rxtx_cm_ops;
static struct fi_ops_msg sstmacx_sep_msg_ops;
static struct fi_ops_rma sstmacx_sep_rma_ops;
static struct fi_ops_tagged sstmacx_sep_tagged_ops;
static struct fi_ops_atomic sstmacx_sep_atomic_ops;

/*******************************************************************************
 * SEP(EP) OPS API function implementations.
 ******************************************************************************/
/* TODO:
	initialize capabilities for tx_priv?
	initialize attr?
*/

static void __trx_destruct(void *obj)
{
	int index, n_ids;
	int __attribute__((unused)) ret;
	struct sstmacx_fid_trx *trx = (struct sstmacx_fid_trx *) obj;
	struct sstmacx_fid_ep *ep_priv;
	struct sstmacx_fid_sep *sep_priv;
	int refs_held;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	ep_priv = trx->ep;
	assert(ep_priv != NULL);
	sep_priv = trx->sep;
	assert(sep_priv != NULL);

	/* These assignments must be done before we free ep_priv */
	index = ep_priv->src_addr.sstmacx_addr.cdm_id -
		sep_priv->cdm_id_base;

	n_ids = MAX(sep_priv->info->ep_attr->tx_ctx_cnt,
		    sep_priv->info->ep_attr->rx_ctx_cnt);

	refs_held = _sstmacx_ref_put(ep_priv);

	if (refs_held == 0) {
		_sstmacx_ref_put(sep_priv->cm_nic);
		/* Remove the context from the sep's list */
		if ((index >= 0) && (index < n_ids)) {
			if (sep_priv->ep_table[index]) {
				sep_priv->ep_table[index] = NULL;
			} else {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "rx/tx context already freed\n");
			}
		} else {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "rx/tx context index out of range\n");
		}
	}

	_sstmacx_ref_put(sep_priv);

	free(trx);
}

static extern "C" int sstmacx_sep_tx_ctx(struct fid_ep *sep, int index,
			   struct fi_tx_attr *attr,
			   struct fid_ep **tx_ep, void *context)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_sep *sep_priv;
	struct sstmacx_fid_ep *ep_priv = NULL;
	struct sstmacx_fid_trx *tx_priv = NULL;
	struct fid_ep *ep_ptr;
	struct sstmacx_ep_attr ep_attr = {0};

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	sep_priv = container_of(sep, struct sstmacx_fid_sep, ep_fid);

	if (!sep_priv) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "endpoint is not initialized\n");
		return -FI_EINVAL;
	}

	if ((sep_priv->ep_fid.fid.fclass != FI_CLASS_SEP) ||
		(index >= sep_priv->info->ep_attr->tx_ctx_cnt))
		return -FI_EINVAL;

	if (attr && attr->op_flags & ~SSTMACX_EP_OP_FLAGS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "invalid op_flags\n");
		return -FI_EINVAL;
	}

	/* caps and mode bits are required to be a subset of info */
	if (attr && attr->caps && (attr->caps & ~sep_priv->info->caps)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "invalid capabilities\n");
		return -FI_EINVAL;
	}

	if (attr && attr->mode && (attr->mode & ~sep_priv->info->mode)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "invalid mode\n");
		return -FI_EINVAL;
	}

	/*
	 * check to see if the tx context was already
	 * allocated
	 */

	fastlock_acquire(&sep_priv->sep_lock);

	if (sep_priv->tx_ep_table[index] != NULL) {
		ret = -FI_EBUSY;
		goto err;
	}

	tx_priv = calloc(1, sizeof(struct sstmacx_fid_trx));
	if (!tx_priv) {
		ret = -FI_ENOMEM;
		goto err;
	}

	tx_priv->ep_fid.fid.fclass = FI_CLASS_TX_CTX;
	tx_priv->ep_fid.fid.context = context;
	tx_priv->ep_fid.fid.ops = &sstmacx_sep_fi_ops;
	tx_priv->ep_fid.ops = &sstmacx_sep_ops;
	tx_priv->ep_fid.msg = &sstmacx_sep_msg_ops;
	tx_priv->ep_fid.rma = &sstmacx_sep_rma_ops;
	tx_priv->ep_fid.tagged = &sstmacx_sep_tagged_ops;
	tx_priv->ep_fid.atomic = &sstmacx_sep_atomic_ops;
	tx_priv->ep_fid.cm = &sstmacx_sep_rxtx_cm_ops;
	tx_priv->index = index;

	/* if an EP already allocated for this index, use it */
	if (sep_priv->ep_table[index] != NULL) {
		ep_priv = container_of(sep_priv->ep_table[index],
				       struct sstmacx_fid_ep, ep_fid);
		sep_priv->tx_ep_table[index] = sep_priv->ep_table[index];
		_sstmacx_ref_get(ep_priv);

	} else {

		/*
		 * allocate the underlying sstmacx_fid_ep struct
		 */

		ep_attr.use_cdm_id = true;
		ep_attr.cdm_id = sep_priv->cdm_id_base + index;
		ep_attr.cm_nic = sep_priv->cm_nic;
		ep_attr.cm_ops = &sstmacx_sep_rxtx_cm_ops;
		/* TODO: clean up this cm_nic */
		_sstmacx_ref_get(sep_priv->cm_nic);
		ret = _sstmacx_ep_alloc(sep_priv->domain,
				     sep_priv->info,
				     &ep_attr,
				     &ep_ptr, context);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "sstmacx_ep_alloc returned %s\n",
				  fi_strerror(-ret));
			goto err;
		}

		sep_priv->ep_table[index] = ep_ptr;
		sep_priv->tx_ep_table[index] = ep_ptr;
		ep_priv = container_of(ep_ptr, struct sstmacx_fid_ep, ep_fid);
		if (sep_priv->av != NULL) {
			ep_priv->av = sep_priv->av;
			_sstmacx_ref_get(ep_priv->av);
			_sstmacx_ep_init_vc(ep_priv);
		}
	}

	_sstmacx_ref_init(&tx_priv->ref_cnt, 1, __trx_destruct);
	tx_priv->ep = ep_priv;
	tx_priv->sep = sep_priv;
	_sstmacx_ref_get(sep_priv);
	tx_priv->caps = ep_priv->caps;
	*tx_ep = &tx_priv->ep_fid;
	tx_priv->op_flags = ep_priv->op_flags;

	if (attr) {
		tx_priv->op_flags |= attr->op_flags;
		memcpy(attr, sep_priv->info->tx_attr,
		       sizeof(struct fi_tx_attr));
		attr->op_flags = tx_priv->op_flags;
	}
err:
	fastlock_release(&sep_priv->sep_lock);

	return ret;
}

static extern "C" int sstmacx_sep_rx_ctx(struct fid_ep *sep, int index,
			   struct fi_rx_attr *attr,
			   struct fid_ep **rx_ep, void *context)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_sep *sep_priv;
	struct sstmacx_fid_ep *ep_priv = NULL;
	struct sstmacx_fid_trx *rx_priv = NULL;
	struct fid_ep *ep_ptr;
	struct sstmacx_ep_attr ep_attr = {0};

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	sep_priv = container_of(sep, struct sstmacx_fid_sep, ep_fid);

	if (!sep_priv) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "endpoint is not initialized\n");
		return -FI_EINVAL;
	}

	if ((sep_priv->ep_fid.fid.fclass != FI_CLASS_SEP) ||
		(index >= sep_priv->info->ep_attr->rx_ctx_cnt))
		return -FI_EINVAL;

	if (attr && attr->op_flags & ~SSTMACX_EP_OP_FLAGS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "invalid op_flags\n");
		return -FI_EINVAL;
	}

	/* caps and mode bits are required to be a subset of info */
	if (attr && attr->caps && (attr->caps & ~sep_priv->info->caps)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "invalid capabilities\n");
		return -FI_EINVAL;
	}

	if (attr && attr->mode && (attr->mode & ~sep_priv->info->mode)) {
		SSTMACX_WARN(FI_LOG_EP_CTRL, "invalid mode\n");
		return -FI_EINVAL;
	}

	/*
	 * check to see if the rx context was already
	 * allocated
	 */

	fastlock_acquire(&sep_priv->sep_lock);

	if (sep_priv->rx_ep_table[index] != NULL) {
		ret = -FI_EBUSY;
		goto err;
	}

	rx_priv = calloc(1, sizeof(struct sstmacx_fid_trx));
	if (!rx_priv) {
		ret = -FI_ENOMEM;
		goto err;
	}

	rx_priv->ep_fid.fid.fclass = FI_CLASS_RX_CTX;
	rx_priv->ep_fid.fid.context = context;
	rx_priv->ep_fid.fid.ops = &sstmacx_sep_fi_ops;
	rx_priv->ep_fid.ops = &sstmacx_sep_ops;
	rx_priv->ep_fid.msg = &sstmacx_sep_msg_ops;
	rx_priv->ep_fid.rma = &sstmacx_sep_rma_ops;
	rx_priv->ep_fid.tagged = &sstmacx_sep_tagged_ops;
	rx_priv->ep_fid.atomic = &sstmacx_sep_atomic_ops;
	rx_priv->ep_fid.cm = &sstmacx_sep_rxtx_cm_ops;
	rx_priv->index = index;

	/* if an EP already allocated for this index, use it */
	if (sep_priv->ep_table[index] != NULL) {
		ep_priv = container_of(sep_priv->ep_table[index],
				       struct sstmacx_fid_ep, ep_fid);
		sep_priv->rx_ep_table[index] = sep_priv->ep_table[index];
		_sstmacx_ref_get(ep_priv);
	} else {

		/*
		 * compute cdm_id and allocate an EP.
		 */

		ep_attr.use_cdm_id = true;
		ep_attr.cdm_id = sep_priv->cdm_id_base + index;
		ep_attr.cm_nic = sep_priv->cm_nic;
		ep_attr.cm_ops = &sstmacx_sep_rxtx_cm_ops;
		_sstmacx_ref_get(sep_priv->cm_nic);
		ret = _sstmacx_ep_alloc(sep_priv->domain,
				     sep_priv->info,
				     &ep_attr,
				     &ep_ptr, context);
		if (ret != FI_SUCCESS) {
			SSTMACX_WARN(FI_LOG_EP_CTRL,
				  "sstmacx_ep_alloc returned %s\n",
				  fi_strerror(-ret));
			goto err;
		}

		sep_priv->ep_table[index] = ep_ptr;
		sep_priv->rx_ep_table[index] = ep_ptr;
		ep_priv = container_of(ep_ptr, struct sstmacx_fid_ep, ep_fid);
		if (sep_priv->av != NULL) {
			ep_priv->av = sep_priv->av;
			_sstmacx_ref_get(ep_priv->av);
			_sstmacx_ep_init_vc(ep_priv);
		}
	}

	_sstmacx_ref_init(&rx_priv->ref_cnt, 1, __trx_destruct);
	rx_priv->ep = ep_priv;
	rx_priv->sep = sep_priv;
	_sstmacx_ref_get(sep_priv);
	rx_priv->caps = ep_priv->caps;
	*rx_ep = &rx_priv->ep_fid;
	rx_priv->op_flags = ep_priv->op_flags;

	if (attr) {
		rx_priv->op_flags |= attr->op_flags;
		memcpy(attr, sep_priv->info->rx_attr,
		       sizeof(struct fi_rx_attr));
		attr->op_flags = rx_priv->op_flags;
	}
err:
	fastlock_release(&sep_priv->sep_lock);

	return ret;
}

DIRECT_FN STATIC extern "C" int sstmacx_sep_bind(fid_t fid, struct fid *bfid, uint64_t flags)
{
	int i, ret, n_ids;
	struct sstmacx_fid_ep  *ep;
	struct sstmacx_fid_av  *av;
	struct sstmacx_fid_sep *sep;
	struct sstmacx_fid_domain *domain_priv;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	switch (fid->fclass) {
	case FI_CLASS_SEP:
		break;
	case FI_CLASS_TX_CTX:
	case FI_CLASS_RX_CTX:
		return sstmacx_ep_bind(fid, bfid, flags);
	default:
		return -FI_ENOSYS;
	}

	sep = container_of(fid, struct sstmacx_fid_sep, ep_fid);
	domain_priv = container_of(sep->domain, struct sstmacx_fid_domain,
				   domain_fid);

	ret = ofi_ep_bind_valid(&sstmacx_prov, bfid, flags);
	if (ret)
		return ret;

	switch (bfid->fclass) {
	case FI_CLASS_AV:

		n_ids = MAX(sep->info->ep_attr->tx_ctx_cnt,
			    sep->info->ep_attr->rx_ctx_cnt);

		av = container_of(bfid, struct sstmacx_fid_av, av_fid.fid);
		if (domain_priv != av->domain) {
			return -FI_EINVAL;
		}

		/*
		 * can't bind more than one AV
		 */

		if (sep->av != NULL)
			return -FI_EINVAL;

		sep->av = av;
		_sstmacx_ref_get(sep->av);

		for (i = 0; i < n_ids; i++) {
			ep = container_of(sep->ep_table[i],
					  struct sstmacx_fid_ep, ep_fid);
			if (ep != NULL && ep->av == NULL) {
				ep->av = av;
				_sstmacx_ep_init_vc(ep);
				_sstmacx_ref_get(ep->av);
			}
		}

		break;

	default:
		ret = -FI_ENOSYS;
		break;
	}

	return ret;
}

/*******************************************************************************
 * Base SEP API function implementations.
 ******************************************************************************/
static extern "C" int sstmacx_sep_control(fid_t fid, int command, void *arg)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_ep *ep;
	struct sstmacx_fid_sep *sep;
	struct sstmacx_fid_trx *trx_priv;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	switch (fid->fclass) {
	case FI_CLASS_SEP:
		/* nothing to do for scalable endpoints */
		return FI_SUCCESS;
	case FI_CLASS_TX_CTX:
	case FI_CLASS_RX_CTX:
		trx_priv = container_of(fid, struct sstmacx_fid_trx, ep_fid);
		ep = trx_priv->ep;
		sep = trx_priv->sep;
		break;
	default:
		return -FI_EINVAL;
	}

	if (!ep) {
		return -FI_EINVAL;
	}

	switch (command) {
	case FI_ENABLE:
		if (SSTMACX_EP_RDM_DGM(ep->type)) {
			if (ep->cm_nic == NULL) {
				ret = -FI_EOPBADSTATE;
				goto err;
			}

			if (sep->enabled[trx_priv->index] == false) {
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

				ret = _sstmacx_ep_int_tx_pool_init(ep);
				if (ret != FI_SUCCESS) {
					SSTMACX_WARN(FI_LOG_EP_CTRL,
					     "_sstmacx_ep_int_tx_pool_init call returned %d\n",
						ret);
					goto err;
				}

				sep->enabled[trx_priv->index] = true;
			}

			/*
			 * enable the EP
			 */

			if (fid->fclass == FI_CLASS_TX_CTX) {
				ret = _sstmacx_ep_tx_enable(ep);
				if (ret != FI_SUCCESS) {
					SSTMACX_WARN(FI_LOG_EP_CTRL,
					     "_sstmacx_ep_tx_enable call returned %d\n",
						ret);
					goto err;
				}
			}

			if (fid->fclass == FI_CLASS_RX_CTX) {
				ret = _sstmacx_ep_rx_enable(ep);
				if (ret != FI_SUCCESS) {
					SSTMACX_WARN(FI_LOG_EP_CTRL,
					     "_sstmacx_ep_rx_enable call returned %d\n",
						ret);
					goto err;
				}
			}

		}

		break;
	case FI_GETFIDFLAG:
	case FI_SETFIDFLAG:
	case FI_ALIAS:
	default:
		return -FI_ENOSYS;
	}
err:
	return ret;
}

static void __sep_destruct(void *obj)
{
	int i;
	struct fid_domain *domain;
	struct sstmacx_fid_ep *ep;
	struct sstmacx_fid_domain *domain_priv;
	struct sstmacx_fid_sep *sep = (struct sstmacx_fid_sep *) obj;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	domain = sep->domain;
	assert(domain != NULL);
	domain_priv = container_of(domain, struct sstmacx_fid_domain, domain_fid);

	_sstmacx_ref_put(domain_priv);

	/*
	 * For now SSTMAC provider doesn't require that an AV have been bound
	 * to the SEP itself.
	 */
	if (sep->av != NULL) {
		_sstmacx_ref_put(sep->av);
		sep->av = NULL;
	}

	if (sep->ep_table) {
		for (i = 0; i < sep->info->ep_attr->tx_ctx_cnt; i++) {
			ep = container_of(sep->ep_table[i],
					  struct sstmacx_fid_ep, ep_fid);
			if (ep == NULL) {
				continue;
			}

			/* tx/rx contexts still open.  This should
			 * warn in sstmacx_sep_close, but we will still
			 * try to clean up a bit. */
			if (ep->av) {
				_sstmacx_ref_put(ep->av);
				ep->av = NULL;
			}
		}

		free(sep->ep_table);
	}

	if (sep->tx_ep_table)
		free(sep->tx_ep_table);
	if (sep->rx_ep_table)
		free(sep->rx_ep_table);
	if (sep->enabled)
		free(sep->enabled);

	fi_freeinfo(sep->info);
	free(sep);
}

static extern "C" int sstmacx_sep_close(fid_t fid)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_sep *sep;
	struct sstmacx_fid_trx *trx_priv;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	switch (fid->fclass) {
	case FI_CLASS_SEP:
		sep = container_of(fid, struct sstmacx_fid_sep, ep_fid.fid);
		if (ofi_atomic_get32(&sep->ref_cnt.references) > 1) {
			SSTMACX_WARN(FI_LOG_EP_CTRL, "Contexts associated with "
				  "this endpoint are still open\n");
			return -FI_EBUSY;
		}
		_sstmacx_ref_put(sep);
		break;
	case FI_CLASS_TX_CTX:
	case FI_CLASS_RX_CTX:
		trx_priv = container_of(fid, struct sstmacx_fid_trx, ep_fid);
		_sstmacx_ref_put(trx_priv);
		break;
	default:
		return -FI_EINVAL;
	}

	return ret;
}

extern "C" int sstmacx_sep_open(struct fid_domain *domain, struct fi_info *info,
		 struct fid_ep **sep, void *context)
{
	struct sstmacx_fid_sep *sep_priv = NULL;
	struct sstmacx_fid_domain *domain_priv = NULL;
	int ret = FI_SUCCESS;
	int n_ids = SSTMACX_SEP_MAX_CNT;
	uint32_t cdm_id, cdm_id_base;
	struct sstmacx_ep_name *name;
	struct sstmacx_auth_key *auth_key;
	uint32_t name_type = SSTMACX_EPN_TYPE_UNBOUND;

	SSTMACX_TRACE(FI_LOG_EP_CTRL, "\n");

	if ((domain == NULL) || (info == NULL) || (sep == NULL) ||
	    (info->ep_attr == NULL))
		return -FI_EINVAL;

	if (!SSTMACX_EP_RDM_DGM(info->ep_attr->type))
		return -FI_ENOSYS;

	/*
	 * check limits for rx and tx ctx's
	 */

	if ((info->ep_attr->tx_ctx_cnt > n_ids) ||
	    (info->ep_attr->rx_ctx_cnt > n_ids))
		return -FI_EINVAL;

	n_ids = MAX(info->ep_attr->tx_ctx_cnt, info->ep_attr->rx_ctx_cnt);

	domain_priv = container_of(domain, struct sstmacx_fid_domain, domain_fid);

	if (info->ep_attr->auth_key_size) {
		auth_key = SSTMACX_GET_AUTH_KEY(info->ep_attr->auth_key,
			info->ep_attr->auth_key_size, domain_priv->using_vmdh);
		if (!auth_key)
			return -FI_EINVAL;
	} else {
		auth_key = domain_priv->auth_key;
		assert(auth_key);
	}

	sep_priv = calloc(1, sizeof(*sep_priv));
	if (!sep_priv)
		return -FI_ENOMEM;

	sep_priv->auth_key = auth_key;
	sep_priv->type = info->ep_attr->type;
	sep_priv->ep_fid.fid.fclass = FI_CLASS_SEP;
	sep_priv->ep_fid.fid.context = context;

	sep_priv->ep_fid.fid.ops = &sstmacx_sep_fi_ops;
	sep_priv->ep_fid.ops = &sstmacx_sep_ops;
	sep_priv->ep_fid.cm = &sstmacx_ep_ops_cm;
	sep_priv->domain = domain;

	sep_priv->info = fi_dupinfo(info);
	sep_priv->info->addr_format = info->addr_format;
	if (!sep_priv->info) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			    "fi_dupinfo NULL\n");
		ret = -FI_ENOMEM;
		goto err;
	}

	_sstmacx_ref_init(&sep_priv->ref_cnt, 1, __sep_destruct);

	sep_priv->caps = info->caps & SSTMACX_EP_PRIMARY_CAPS;

	sep_priv->ep_table = calloc(n_ids, sizeof(struct sstmacx_fid_ep *));
	if (sep_priv->ep_table == NULL) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			    "call returned NULL\n");
		ret = -FI_ENOMEM;
		goto err;
	}

	sep_priv->tx_ep_table = calloc(n_ids, sizeof(struct sstmacx_fid_ep *));
	if (sep_priv->tx_ep_table == NULL) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			    "call returned NULL\n");
		ret = -FI_ENOMEM;
		goto err;
	}

	sep_priv->rx_ep_table = calloc(n_ids, sizeof(struct sstmacx_fid_ep *));
	if (sep_priv->rx_ep_table == NULL) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			    "call returned NULL\n");
		ret = -FI_ENOMEM;
		goto err;
	}

	sep_priv->enabled = calloc(n_ids, sizeof(bool));
	if (sep_priv->enabled == NULL) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			    "call returned NULL\n");
		ret = -FI_ENOMEM;
		goto err;
	}

	/*
	 * allocate a block of cm nic ids for both tx/rx ctx - first
	 * checking to see if the application has specified a base
	 * via a node/service option to fi_getinfo
	 */

	if (info->src_addr != NULL) {
		name = (struct sstmacx_ep_name *) info->src_addr;

		if (name->name_type & SSTMACX_EPN_TYPE_BOUND) {
			cdm_id_base = name->sstmacx_addr.cdm_id;
			name_type = name->name_type;
		}
	}

	name_type |= SSTMACX_EPN_TYPE_SEP;

	cdm_id = (name_type & SSTMACX_EPN_TYPE_UNBOUND) ? -1 : cdm_id_base;

	ret = _sstmacx_get_new_cdm_id_set(domain_priv, n_ids, &cdm_id);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			  "_sstmacx_get_new_cdm_id_set call returned %s\n",
			  fi_strerror(-ret));
		goto err;
	}

	sep_priv->cdm_id_base = cdm_id;

	/*
	 * allocate cm_nic for this SEP
	 */
	ret = _sstmacx_cm_nic_alloc(domain_priv,
				 sep_priv->info,
				 cdm_id,
				 sep_priv->auth_key,
				 &sep_priv->cm_nic);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_EP_CTRL,
			    "sstmacx_cm_nic_alloc call returned %s\n",
			     fi_strerror(-ret));
		goto err;
	}

	/*
	 * ep name of SEP is the same as the cm_nic
	 * since there's a one-to-one relationship
	 * between a given SEP and its cm_nic.
	 */
	sep_priv->my_name = sep_priv->cm_nic->my_name;
	sep_priv->my_name.cm_nic_cdm_id =
				sep_priv->cm_nic->my_name.sstmacx_addr.cdm_id;
	sep_priv->my_name.rx_ctx_cnt = info->ep_attr->rx_ctx_cnt;
	sep_priv->my_name.name_type = name_type;

	fastlock_init(&sep_priv->sep_lock);
	_sstmacx_ref_get(domain_priv);

	*sep = &sep_priv->ep_fid;
	return ret;

err:
	if (sep_priv->ep_table)
		free(sep_priv->ep_table);
	if (sep_priv->tx_ep_table)
		free(sep_priv->tx_ep_table);
	if (sep_priv->rx_ep_table)
		free(sep_priv->rx_ep_table);
	if (sep_priv)
		free(sep_priv);
	return ret;

}

/*******************************************************************************
ssize_t (*recv)(struct fid_ep *ep, void *buf, size_t len, void *desc,
		fi_addr_t src_addr, void *context);
ssize_t (*send)(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		fi_addr_t dest_addr, void *context);
 ******************************************************************************/

/*
 * TODO: need to define the other msg/rma/amo methods for tx/rx contexts
 */

DIRECT_FN STATIC ssize_t sstmacx_sep_recv(struct fid_ep *ep, void *buf,
				       size_t len, void *desc,
				       fi_addr_t src_addr, void *context)
{
	struct sstmacx_fid_trx *rx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_recv(&rx_ep->ep->ep_fid, buf, len, desc, src_addr,
			context, 0, 0, 0);
}

DIRECT_FN STATIC ssize_t sstmacx_sep_recvv(struct fid_ep *ep,
					const struct iovec *iov,
					void **desc, size_t count,
					fi_addr_t src_addr,
					void *context)
{
	struct sstmacx_fid_trx *rx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_recvv(&rx_ep->ep->ep_fid, iov, desc, count, src_addr,
			 context, 0, 0, 0);
}

DIRECT_FN STATIC ssize_t sstmacx_sep_recvmsg(struct fid_ep *ep,
					 const struct fi_msg *msg,
					 uint64_t flags)
{
	struct sstmacx_fid_trx *rx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_recvmsg(&rx_ep->ep->ep_fid, msg, flags & SSTMACX_RECVMSG_FLAGS,
			   0, 0);
}

DIRECT_FN STATIC ssize_t sstmacx_sep_send(struct fid_ep *ep, const void *buf,
				       size_t len, void *desc,
				       fi_addr_t dest_addr, void *context)
{
	struct sstmacx_fid_trx *tx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_send(&tx_ep->ep->ep_fid, buf, len, desc, dest_addr,
			context, 0, 0);
}

DIRECT_FN ssize_t sstmacx_sep_sendv(struct fid_ep *ep,
				 const struct iovec *iov,
				 void **desc, size_t count,
				 fi_addr_t dest_addr,
				 void *context)
{
	struct sstmacx_fid_trx *tx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_sendv(&tx_ep->ep->ep_fid, iov, desc, count, dest_addr,
			 context, 0, 0);
}

DIRECT_FN ssize_t sstmacx_sep_sendmsg(struct fid_ep *ep,
				  const struct fi_msg *msg,
				  uint64_t flags)
{
	struct sstmacx_fid_trx *tx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_sendmsg(&tx_ep->ep->ep_fid, msg,
			   flags & SSTMACX_SENDMSG_FLAGS, 0);
}

DIRECT_FN ssize_t sstmacx_sep_msg_inject(struct fid_ep *ep, const void *buf,
				      size_t len, fi_addr_t dest_addr)
{
	struct sstmacx_fid_trx *tx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_inject(&tx_ep->ep->ep_fid, buf, len, 0, dest_addr, 0, 0);
}

DIRECT_FN ssize_t sstmacx_sep_senddata(struct fid_ep *ep, const void *buf,
				    size_t len, void *desc, uint64_t data,
				    fi_addr_t dest_addr, void *context)
{
	struct sstmacx_fid_trx *tx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_senddata(&tx_ep->ep->ep_fid, buf, len, desc, data,
			    dest_addr, context, 0, 0);
}

DIRECT_FN ssize_t
sstmacx_sep_msg_injectdata(struct fid_ep *ep, const void *buf, size_t len,
			uint64_t data, fi_addr_t dest_addr)
{
	uint64_t flags;
	struct sstmacx_fid_trx *tx_ep;

	if (!ep) {
		return -FI_EINVAL;
	}

	tx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(tx_ep->ep->type));

	flags = tx_ep->op_flags | FI_INJECT | FI_REMOTE_CQ_DATA |
		SSTMACX_SUPPRESS_COMPLETION;

	return _sstmacx_send(tx_ep->ep, (uint64_t)buf, len, NULL, dest_addr,
			  NULL, flags, data, 0);
}

DIRECT_FN STATIC ssize_t sstmacx_sep_trecv(struct fid_ep *ep, void *buf,
					size_t len,
					void *desc, fi_addr_t src_addr,
					uint64_t tag, uint64_t ignore,
					void *context)
{
	struct sstmacx_fid_trx *rx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_recv(&rx_ep->ep->ep_fid, buf, len, desc, src_addr, context,
			FI_TAGGED, tag, ignore);
}

DIRECT_FN STATIC ssize_t sstmacx_sep_trecvv(struct fid_ep *ep,
					 const struct iovec *iov,
					 void **desc, size_t count,
					 fi_addr_t src_addr,
					 uint64_t tag, uint64_t ignore,
					 void *context)
{
	struct sstmacx_fid_trx *rx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_recvv(&rx_ep->ep->ep_fid, iov, desc, count, src_addr,
			 context, FI_TAGGED, tag, ignore);
}

DIRECT_FN STATIC ssize_t sstmacx_sep_trecvmsg(struct fid_ep *ep,
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

	if ((flags & FI_CLAIM) && _msg.context == NULL)
		return -FI_EINVAL;

	if ((flags & FI_DISCARD) && !(flags & (FI_PEEK | FI_CLAIM)))
		return -FI_EINVAL;

	struct sstmacx_fid_trx *rx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_recvmsg(&rx_ep->ep->ep_fid, &_msg, flags | FI_TAGGED,
			   msg->tag, msg->ignore);
}

DIRECT_FN STATIC ssize_t sstmacx_sep_tsend(struct fid_ep *ep, const void *buf,
					size_t len, void *desc,
					fi_addr_t dest_addr, uint64_t tag,
					void *context)
{
	struct sstmacx_fid_trx *tx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_send(&tx_ep->ep->ep_fid, buf, len, desc, dest_addr,
			context, FI_TAGGED, tag);
}

DIRECT_FN STATIC ssize_t sstmacx_sep_tsendv(struct fid_ep *ep,
					 const struct iovec *iov,
					 void **desc, size_t count,
					 fi_addr_t dest_addr,
					 uint64_t tag, void *context)
{
	struct sstmacx_fid_trx *tx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_sendv(&tx_ep->ep->ep_fid, iov, desc, count, dest_addr,
			 context, FI_TAGGED, tag);
}

DIRECT_FN STATIC ssize_t sstmacx_sep_tsendmsg(struct fid_ep *ep,
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

	if (flags & ~SSTMACX_SENDMSG_FLAGS)
		return -FI_EINVAL;

	struct sstmacx_fid_trx *tx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_sendmsg(&tx_ep->ep->ep_fid, &_msg, flags | FI_TAGGED,
			   msg->tag);
}

DIRECT_FN STATIC ssize_t sstmacx_sep_tinject(struct fid_ep *ep, const void *buf,
					  size_t len, fi_addr_t dest_addr,
					  uint64_t tag)
{
	struct sstmacx_fid_trx *tx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_inject(&tx_ep->ep->ep_fid, buf, len, 0, dest_addr, FI_TAGGED,
			  tag);
}

DIRECT_FN STATIC ssize_t sstmacx_sep_tsenddata(struct fid_ep *ep, const void *buf,
					    size_t len, void *desc,
					    uint64_t data, fi_addr_t dest_addr,
					    uint64_t tag, void *context)
{
	struct sstmacx_fid_trx *tx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_senddata(&tx_ep->ep->ep_fid, buf, len, desc, data,
			    dest_addr, context, FI_TAGGED, tag);
}

DIRECT_FN STATIC ssize_t sstmacx_sep_tinjectdata(struct fid_ep *ep,
					      const void *buf,
					      size_t len, uint64_t data,
					      fi_addr_t dest_addr, uint64_t tag)
{
	struct sstmacx_fid_trx *tx_ep = container_of(ep, struct sstmacx_fid_trx,
						  ep_fid);

	return _ep_inject(&tx_ep->ep->ep_fid, buf, len, data, dest_addr,
			  FI_TAGGED | FI_REMOTE_CQ_DATA, tag);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_read(struct fid_ep *ep, void *buf, size_t len,
	      void *desc, fi_addr_t src_addr, uint64_t addr,
	      uint64_t key, void *context)
{
	uint64_t flags;
	struct sstmacx_fid_trx *rx_ep;

	if (!ep) {
		return -FI_EINVAL;
	}

	rx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(rx_ep->ep->type));
	flags = rx_ep->op_flags | SSTMACX_RMA_READ_FLAGS_DEF;

	return _sstmacx_rma(rx_ep->ep, SSTMACX_FAB_RQ_RDMA_READ,
			 (uint64_t)buf, len, desc,
			 src_addr, addr, key,
			 context, flags, 0);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_readv(struct fid_ep *ep, const struct iovec *iov, void **desc,
	       size_t count, fi_addr_t src_addr, uint64_t addr, uint64_t key,
	       void *context)
{
	uint64_t flags;
	struct sstmacx_fid_trx *rx_ep;

	if (!ep || !iov || !desc || count > SSTMACX_MAX_RMA_IOV_LIMIT) {
		return -FI_EINVAL;
	}

	rx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(rx_ep->ep->type));
	flags = rx_ep->op_flags | SSTMACX_RMA_READ_FLAGS_DEF;

	return _sstmacx_rma(rx_ep->ep, SSTMACX_FAB_RQ_RDMA_READ,
			 (uint64_t)iov[0].iov_base, iov[0].iov_len, desc[0],
			 src_addr, addr, key,
			 context, flags, 0);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_readmsg(struct fid_ep *ep, const struct fi_msg_rma *msg,
		 uint64_t flags)
{
	struct sstmacx_fid_trx *rx_ep;

	if (!ep || !msg || !msg->msg_iov || !msg->rma_iov || !msg->desc ||
	    msg->iov_count != 1 || msg->rma_iov_count != 1 ||
	    msg->rma_iov[0].len > msg->msg_iov[0].iov_len) {
		return -FI_EINVAL;
	}

	rx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(rx_ep->ep->type));

	flags = (flags & SSTMACX_READMSG_FLAGS) | SSTMACX_RMA_READ_FLAGS_DEF;

	return _sstmacx_rma(rx_ep->ep, SSTMACX_FAB_RQ_RDMA_READ,
			 (uint64_t)msg->msg_iov[0].iov_base,
			 msg->msg_iov[0].iov_len, msg->desc[0],
			 msg->addr, msg->rma_iov[0].addr, msg->rma_iov[0].key,
			 msg->context, flags, msg->data);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_write(struct fid_ep *ep, const void *buf, size_t len, void *desc,
	       fi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context)
{
	uint64_t flags;
	struct sstmacx_fid_trx *tx_ep;

	if (!ep) {
		return -FI_EINVAL;
	}

	tx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(tx_ep->ep->type));
	flags = tx_ep->op_flags | SSTMACX_RMA_WRITE_FLAGS_DEF;

	return _sstmacx_rma(tx_ep->ep, SSTMACX_FAB_RQ_RDMA_WRITE,
			 (uint64_t)buf, len, desc, dest_addr, addr, key,
			 context, flags, 0);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_writev(struct fid_ep *ep, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		void *context)
{
	uint64_t flags;
	struct sstmacx_fid_trx *tx_ep;

	if (!ep || !iov || !desc || count > SSTMACX_MAX_RMA_IOV_LIMIT) {
		return -FI_EINVAL;
	}

	tx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(tx_ep->ep->type));
	flags = tx_ep->op_flags | SSTMACX_RMA_WRITE_FLAGS_DEF;

	return _sstmacx_rma(tx_ep->ep, SSTMACX_FAB_RQ_RDMA_WRITE,
			 (uint64_t)iov[0].iov_base, iov[0].iov_len, desc[0],
			 dest_addr, addr, key, context, flags, 0);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_writemsg(struct fid_ep *ep, const struct fi_msg_rma *msg,
		  uint64_t flags)
{
	struct sstmacx_fid_trx *trx_ep;

	if (!ep || !msg || !msg->msg_iov || !msg->rma_iov ||
	    msg->iov_count != 1 ||
		msg->rma_iov_count > SSTMACX_MAX_RMA_IOV_LIMIT ||
	    msg->rma_iov[0].len > msg->msg_iov[0].iov_len) {
		return -FI_EINVAL;
	}

	trx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(trx_ep->ep->type));

	flags = (flags & SSTMACX_WRITEMSG_FLAGS) | SSTMACX_RMA_WRITE_FLAGS_DEF;

	return _sstmacx_rma(trx_ep->ep, SSTMACX_FAB_RQ_RDMA_WRITE,
			 (uint64_t)msg->msg_iov[0].iov_base,
			 msg->msg_iov[0].iov_len,
			 msg->desc ? msg->desc[0] : NULL,
			 msg->addr, msg->rma_iov[0].addr, msg->rma_iov[0].key,
			 msg->context, flags, msg->data);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_rma_inject(struct fid_ep *ep, const void *buf,
		    size_t len, fi_addr_t dest_addr,
		    uint64_t addr, uint64_t key)
{
	uint64_t flags;
	struct sstmacx_fid_trx *trx_ep;

	if (!ep) {
		return -FI_EINVAL;
	}

	trx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(trx_ep->ep->type));

	flags = trx_ep->op_flags | FI_INJECT | SSTMACX_SUPPRESS_COMPLETION |
			SSTMACX_RMA_WRITE_FLAGS_DEF;

	return _sstmacx_rma(trx_ep->ep, SSTMACX_FAB_RQ_RDMA_WRITE,
			 (uint64_t)buf, len, NULL,
			 dest_addr, addr, key,
			 NULL, flags, 0);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_writedata(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		   uint64_t data, fi_addr_t dest_addr, uint64_t addr,
		   uint64_t key, void *context)
{
	uint64_t flags;
	struct sstmacx_fid_trx *trx_ep;

	if (!ep) {
		return -FI_EINVAL;
	}

	trx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(trx_ep->ep->type));

	flags = trx_ep->op_flags | FI_REMOTE_CQ_DATA | SSTMACX_RMA_WRITE_FLAGS_DEF;

	return _sstmacx_rma(trx_ep->ep, SSTMACX_FAB_RQ_RDMA_WRITE,
			 (uint64_t)buf, len, desc,
			 dest_addr, addr, key,
			 context, flags, data);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_rma_injectdata(struct fid_ep *ep, const void *buf, size_t len,
			uint64_t data, fi_addr_t dest_addr, uint64_t addr,
			uint64_t key)
{
	uint64_t flags;
	struct sstmacx_fid_trx *trx_ep;

	if (!ep) {
		return -FI_EINVAL;
	}

	trx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(trx_ep->ep->type));

	flags = trx_ep->op_flags | FI_INJECT | FI_REMOTE_CQ_DATA |
			SSTMACX_SUPPRESS_COMPLETION | SSTMACX_RMA_WRITE_FLAGS_DEF;

	return _sstmacx_rma(trx_ep->ep, SSTMACX_FAB_RQ_RDMA_WRITE,
			 (uint64_t)buf, len, NULL,
			 dest_addr, addr, key,
			 NULL, flags, data);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_atomic_write(struct fid_ep *ep, const void *buf, size_t count,
		      void *desc, fi_addr_t dest_addr, uint64_t addr,
		      uint64_t key, enum fi_datatype datatype, enum fi_op op,
		      void *context)
{
	struct sstmacx_fid_trx *trx_ep;

	struct fi_msg_atomic msg;
	struct fi_ioc msg_iov;
	struct fi_rma_ioc rma_iov;
	uint64_t flags;

	if (!ep)
		return -FI_EINVAL;

	if (_sstmacx_atomic_cmd(datatype, op, SSTMACX_FAB_RQ_AMO) < 0)
		return -FI_EOPNOTSUPP;

	trx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(trx_ep->ep->type));

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

	flags = trx_ep->op_flags | SSTMACX_ATOMIC_WRITE_FLAGS_DEF;

	return _sstmacx_atomic(trx_ep->ep, SSTMACX_FAB_RQ_AMO, &msg,
			    NULL, NULL, 0, NULL, NULL, 0, flags);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_atomic_writev(struct fid_ep *ep, const struct fi_ioc *iov, void **desc,
		      size_t count, fi_addr_t dest_addr, uint64_t addr,
		      uint64_t key, enum fi_datatype datatype, enum fi_op op,
		      void *context)
{
	if (!ep || !iov || count > 1)
		return -FI_EINVAL;

	return sstmacx_sep_atomic_write(ep, iov[0].addr,
				     iov[0].count, desc ? desc[0] : NULL,
				     dest_addr, addr, key, datatype, op,
				     context);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_atomic_writemsg(struct fid_ep *ep, const struct fi_msg_atomic *msg,
			uint64_t flags)
{
	struct sstmacx_fid_trx *trx_ep;

	if (!ep)
		return -FI_EINVAL;

	if (_sstmacx_atomic_cmd(msg->datatype, msg->op, SSTMACX_FAB_RQ_AMO) < 0)
		return -FI_EOPNOTSUPP;

	trx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(trx_ep->ep->type));

	flags = (flags & SSTMACX_ATOMICMSG_FLAGS) | SSTMACX_ATOMIC_WRITE_FLAGS_DEF;

	return _sstmacx_atomic(trx_ep->ep, SSTMACX_FAB_RQ_AMO, msg,
			    NULL, NULL, 0, NULL, NULL, 0, flags);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_atomic_inject(struct fid_ep *ep, const void *buf, size_t count,
		       fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		       enum fi_datatype datatype, enum fi_op op)
{
	struct sstmacx_fid_trx *trx_ep;
	struct fi_msg_atomic msg;
	struct fi_ioc msg_iov;
	struct fi_rma_ioc rma_iov;
	uint64_t flags;

	if (!ep)
		return -FI_EINVAL;

	if (_sstmacx_atomic_cmd(datatype, op, SSTMACX_FAB_RQ_AMO) < 0)
		return -FI_EOPNOTSUPP;

	trx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(trx_ep->ep->type));

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

	flags = trx_ep->op_flags | FI_INJECT | SSTMACX_SUPPRESS_COMPLETION |
			SSTMACX_ATOMIC_WRITE_FLAGS_DEF;

	return _sstmacx_atomic(trx_ep->ep, SSTMACX_FAB_RQ_AMO, &msg,
			    NULL, NULL, 0, NULL, NULL, 0, flags);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_atomic_readwrite(struct fid_ep *ep, const void *buf, size_t count,
			 void *desc, void *result, void *result_desc,
			 fi_addr_t dest_addr, uint64_t addr, uint64_t key,
			 enum fi_datatype datatype, enum fi_op op,
			 void *context)
{
	struct sstmacx_fid_trx *trx_ep;
	struct fi_msg_atomic msg;
	struct fi_ioc msg_iov;
	struct fi_rma_ioc rma_iov;
	struct fi_ioc result_iov;
	uint64_t flags;

	if (_sstmacx_atomic_cmd(datatype, op, SSTMACX_FAB_RQ_FAMO) < 0)
		return -FI_EOPNOTSUPP;

	if (!ep)
		return -FI_EINVAL;

	trx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(trx_ep->ep->type));

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

	flags = trx_ep->op_flags | SSTMACX_ATOMIC_READ_FLAGS_DEF;

	return _sstmacx_atomic(trx_ep->ep, SSTMACX_FAB_RQ_FAMO, &msg,
			    NULL, NULL, 0,
			    &result_iov, &result_desc, 1,
			    flags);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_atomic_readwritev(struct fid_ep *ep, const struct fi_ioc *iov,
			  void **desc, size_t count, struct fi_ioc *resultv,
			  void **result_desc, size_t result_count,
			  fi_addr_t dest_addr, uint64_t addr, uint64_t key,
			  enum fi_datatype datatype, enum fi_op op,
			  void *context)
{
	if (!iov || count > 1 || !resultv)
		return -FI_EINVAL;

	return sstmacx_sep_atomic_readwrite(ep, iov[0].addr, iov[0].count,
					desc ? desc[0] : NULL,
					resultv[0].addr,
					result_desc ? result_desc[0] : NULL,
					dest_addr, addr, key, datatype, op,
					context);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_atomic_readwritemsg(struct fid_ep *ep, const struct fi_msg_atomic *msg,
			    struct fi_ioc *resultv, void **result_desc,
			    size_t result_count, uint64_t flags)
{
	struct sstmacx_fid_trx *trx_ep;

	if (!ep)
		return -FI_EINVAL;

	if (_sstmacx_atomic_cmd(msg->datatype, msg->op, SSTMACX_FAB_RQ_FAMO) < 0)
		return -FI_EOPNOTSUPP;

	trx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(trx_ep->ep->type));

	flags = (flags & SSTMACX_FATOMICMSG_FLAGS) | SSTMACX_ATOMIC_READ_FLAGS_DEF;

	return _sstmacx_atomic(trx_ep->ep, SSTMACX_FAB_RQ_FAMO, msg, NULL, NULL, 0,
			    resultv, result_desc, result_count, flags);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_atomic_compwrite(struct fid_ep *ep, const void *buf, size_t count,
			  void *desc, const void *compare, void *compare_desc,
			  void *result, void *result_desc, fi_addr_t dest_addr,
			  uint64_t addr, uint64_t key,
			  enum fi_datatype datatype, enum fi_op op,
			  void *context)
{
	struct sstmacx_fid_trx *trx_ep;
	struct fi_msg_atomic msg;
	struct fi_ioc msg_iov;
	struct fi_rma_ioc rma_iov;
	struct fi_ioc result_iov;
	struct fi_ioc compare_iov;
	uint64_t flags;

	if (!ep)
		return -FI_EINVAL;

	if (_sstmacx_atomic_cmd(datatype, op, SSTMACX_FAB_RQ_CAMO) < 0)
		return -FI_EOPNOTSUPP;

	trx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(trx_ep->ep->type));

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

	flags = trx_ep->op_flags | SSTMACX_ATOMIC_READ_FLAGS_DEF;

	return _sstmacx_atomic(trx_ep->ep, SSTMACX_FAB_RQ_CAMO, &msg,
			    &compare_iov, &compare_desc, 1,
			    &result_iov, &result_desc, 1,
			    flags);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_atomic_compwritev(struct fid_ep *ep, const struct fi_ioc *iov,
			   void **desc, size_t count,
			   const struct fi_ioc *comparev,
			   void **compare_desc, size_t compare_count,
			   struct fi_ioc *resultv, void **result_desc,
			   size_t result_count, fi_addr_t dest_addr,
			   uint64_t addr, uint64_t key,
			   enum fi_datatype datatype, enum fi_op op,
			   void *context)
{
	if (!iov || count > 1 || !resultv || !comparev)
		return -FI_EINVAL;

	return sstmacx_sep_atomic_compwrite(ep, iov[0].addr, iov[0].count,
					 desc ? desc[0] : NULL,
					 comparev[0].addr,
					 compare_desc ? compare_desc[0] : NULL,
					 resultv[0].addr,
					 result_desc ? result_desc[0] : NULL,
					 dest_addr, addr, key, datatype, op,
					 context);
}

DIRECT_FN STATIC ssize_t
sstmacx_sep_atomic_compwritemsg(struct fid_ep *ep, const struct fi_msg_atomic *msg,
			     const struct fi_ioc *comparev, void **compare_desc,
			     size_t compare_count, struct fi_ioc *resultv,
			     void **result_desc, size_t result_count,
			     uint64_t flags)
{
	struct sstmacx_fid_trx *trx_ep;

	if (!ep)
		return -FI_EINVAL;

	if (_sstmacx_atomic_cmd(msg->datatype, msg->op, SSTMACX_FAB_RQ_CAMO) < 0)
		return -FI_EOPNOTSUPP;

	trx_ep = container_of(ep, struct sstmacx_fid_trx, ep_fid);
	assert(SSTMACX_EP_RDM_DGM_MSG(trx_ep->ep->type));

	flags = (flags & SSTMACX_CATOMICMSG_FLAGS) | SSTMACX_ATOMIC_READ_FLAGS_DEF;

	return _sstmacx_atomic(trx_ep->ep, SSTMACX_FAB_RQ_CAMO, msg,
			    comparev, compare_desc, compare_count,
			    resultv, result_desc, result_count,
			    flags);
}

/*******************************************************************************
 * FI_OPS_* data structures.
 ******************************************************************************/

static struct fi_ops sstmacx_sep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sstmacx_sep_close,
	.bind = sstmacx_sep_bind,
	.control = sstmacx_sep_control,
	.ops_open = fi_no_ops_open
};

static struct fi_ops_ep sstmacx_sep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = sstmacx_cancel,
	.getopt = sstmacx_getopt,
	.setopt = sstmacx_setopt,
	.tx_ctx = sstmacx_sep_tx_ctx,
	.rx_ctx = sstmacx_sep_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static struct fi_ops_msg sstmacx_sep_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = sstmacx_sep_recv,
	.recvv = sstmacx_sep_recvv,
	.recvmsg = sstmacx_sep_recvmsg,
	.send = sstmacx_sep_send,
	.sendv = sstmacx_sep_sendv,
	.sendmsg = sstmacx_sep_sendmsg,
	.inject = sstmacx_sep_msg_inject,
	.senddata = sstmacx_sep_senddata,
	.injectdata = sstmacx_sep_msg_injectdata,
};

static struct fi_ops_rma sstmacx_sep_rma_ops = {
	.size = sizeof(struct fi_ops_rma),
	.read = sstmacx_sep_read,
	.readv = sstmacx_sep_readv,
	.readmsg = sstmacx_sep_readmsg,
	.write = sstmacx_sep_write,
	.writev = sstmacx_sep_writev,
	.writemsg = sstmacx_sep_writemsg,
	.inject = sstmacx_sep_rma_inject,
	.writedata = sstmacx_sep_writedata,
	.injectdata = sstmacx_sep_rma_injectdata,
};

static struct fi_ops_tagged sstmacx_sep_tagged_ops = {
	.size = sizeof(struct fi_ops_tagged),
	.recv = sstmacx_sep_trecv,
	.recvv = sstmacx_sep_trecvv,
	.recvmsg = sstmacx_sep_trecvmsg,
	.send = sstmacx_sep_tsend,
	.sendv = sstmacx_sep_tsendv,
	.sendmsg = sstmacx_sep_tsendmsg,
	.inject = sstmacx_sep_tinject,
	.senddata = sstmacx_sep_tsenddata,
	.injectdata = sstmacx_sep_tinjectdata,
};

static struct fi_ops_atomic sstmacx_sep_atomic_ops = {
	.size = sizeof(struct fi_ops_atomic),
	.write = sstmacx_sep_atomic_write,
	.writev = sstmacx_sep_atomic_writev,
	.writemsg = sstmacx_sep_atomic_writemsg,
	.inject = sstmacx_sep_atomic_inject,
	.readwrite = sstmacx_sep_atomic_readwrite,
	.readwritev = sstmacx_sep_atomic_readwritev,
	.readwritemsg = sstmacx_sep_atomic_readwritemsg,
	.compwrite = sstmacx_sep_atomic_compwrite,
	.compwritev = sstmacx_sep_atomic_compwritev,
	.compwritemsg = sstmacx_sep_atomic_compwritemsg,
	.writevalid = sstmacx_ep_atomic_valid,
	.readwritevalid = sstmacx_ep_fetch_atomic_valid,
	.compwritevalid = sstmacx_ep_cmp_atomic_valid,
};

/*
 * rx/tx contexts don't do any connection management,
 * nor does the underlying sstmacx_fid_ep struct
 */
static struct fi_ops_cm sstmacx_sep_rxtx_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = fi_no_setname,
	.getname = fi_no_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
	.join = fi_no_join,
};

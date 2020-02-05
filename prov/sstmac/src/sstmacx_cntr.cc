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
 * CNTR common code
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sstmacx.h"
#include "sstmacx_cntr.h"
#include "sstmacx_nic.h"
#include "sstmacx_trigger.h"

/*******************************************************************************
 * Forward declarations for filling functions.
 ******************************************************************************/

/*******************************************************************************
 * Forward declarations for ops structures.
 ******************************************************************************/
static struct fi_ops sstmacx_cntr_fi_ops;
static struct fi_ops_cntr sstmacx_cntr_ops;

/*******************************************************************************
 * Internal helper functions
 ******************************************************************************/

static int __verify_cntr_attr(struct fi_cntr_attr *attr)
{
	int ret = FI_SUCCESS;

	SSTMACX_TRACE(FI_LOG_CQ, "\n");

	if (!attr)
		return -FI_EINVAL;

	if (attr->events != FI_CNTR_EVENTS_COMP) {
		SSTMACX_WARN(FI_LOG_CQ, "cntr event type: %d unsupported.\n",
			  attr->events);
		return -FI_EINVAL;
	}

	switch (attr->wait_obj) {
	case FI_WAIT_UNSPEC:
	case FI_WAIT_NONE:
	case FI_WAIT_SET:
		break;
	case FI_WAIT_FD:
	case FI_WAIT_MUTEX_COND:
	default:
		SSTMACX_WARN(FI_LOG_CQ, "wait type: %d unsupported.\n",
			  attr->wait_obj);
		return -FI_EINVAL;
	}

	return ret;
}

static extern "C" int sstmacx_cntr_set_wait(struct sstmacx_fid_cntr *cntr)
{
	int ret = FI_SUCCESS;

	SSTMACX_TRACE(FI_LOG_EQ, "\n");

	struct fi_wait_attr requested = {
		.wait_obj = cntr->attr.wait_obj,
		.flags = 0
	};

	switch (cntr->attr.wait_obj) {
	case FI_WAIT_UNSPEC:
		ret = sstmacx_wait_open(&cntr->domain->fabric->fab_fid,
				&requested, &cntr->wait);
		break;
	case FI_WAIT_SET:
		ret = _sstmacx_wait_set_add(cntr->attr.wait_set,
					 &cntr->cntr_fid.fid);

		if (!ret)
			cntr->wait = cntr->attr.wait_set;
		break;
	default:
		break;
	}

	return ret;
}

static int __sstmacx_cntr_progress(struct sstmacx_fid_cntr *cntr)
{
	return _sstmacx_prog_progress(&cntr->pset);
}

/*******************************************************************************
 * Exposed helper functions
 ******************************************************************************/

extern "C" int _sstmacx_cntr_inc(struct sstmacx_fid_cntr *cntr)
{
	if (cntr == NULL)
		return -FI_EINVAL;

	ofi_atomic_inc32(&cntr->cnt);

	if (cntr->wait)
		_sstmacx_signal_wait_obj(cntr->wait);

	if (_sstmacx_trigger_pending(cntr))
		_sstmacx_trigger_check_cntr(cntr);

	return FI_SUCCESS;
}

extern "C" int _sstmacx_cntr_inc_err(struct sstmacx_fid_cntr *cntr)
{
	if (cntr == NULL)
		return -FI_EINVAL;

	ofi_atomic_inc32(&cntr->cnt_err);

	if (cntr->wait)
		_sstmacx_signal_wait_obj(cntr->wait);

	return FI_SUCCESS;
}

extern "C" int _sstmacx_cntr_poll_obj_add(struct sstmacx_fid_cntr *cntr, void *obj,
			    int (*prog_fn)(void *data))
{
	return _sstmacx_prog_obj_add(&cntr->pset, obj, prog_fn);
}

extern "C" int _sstmacx_cntr_poll_obj_rem(struct sstmacx_fid_cntr *cntr, void *obj,
			    int (*prog_fn)(void *data))
{
	return _sstmacx_prog_obj_rem(&cntr->pset, obj, prog_fn);
}

/*******************************************************************************
 * API functions.
 ******************************************************************************/

static extern "C" int sstmacx_cntr_wait_sleep(struct sstmacx_fid_cntr *cntr_priv,
				uint64_t threshold, int timeout)
{
	int ret = FI_SUCCESS;
	struct timespec ts0, ts;
	int msec_passed = 0;

	clock_gettime(CLOCK_REALTIME, &ts0);
	while (ofi_atomic_get32(&cntr_priv->cnt) < threshold &&
	       ofi_atomic_get32(&cntr_priv->cnt_err) == 0) {

		ret = sstmacx_wait_wait((struct fid_wait *)cntr_priv->wait,
					timeout - msec_passed);
		if (ret == -FI_ETIMEDOUT)
			break;

		if (ret) {
			SSTMACX_WARN(FI_LOG_CQ,
				" fi_wait returned %d.\n",
				  ret);
			break;
		}

		if (ofi_atomic_get32(&cntr_priv->cnt) >= threshold)
			break;

		if (timeout < 0)
			continue;

		clock_gettime(CLOCK_REALTIME, &ts);
		msec_passed = (ts.tv_sec - ts0.tv_sec) * 1000 +
			      (ts.tv_nsec - ts0.tv_nsec) / 100000;

		if (msec_passed >= timeout) {
			ret = -FI_ETIMEDOUT;
			break;
		}
	}

	return (ofi_atomic_get32(&cntr_priv->cnt_err)) ? -FI_EAVAIL : ret;
}


DIRECT_FN STATIC extern "C" int sstmacx_cntr_wait(struct fid_cntr *cntr, uint64_t threshold,
				    int timeout)
{
	struct sstmacx_fid_cntr *cntr_priv;

	cntr_priv = container_of(cntr, struct sstmacx_fid_cntr, cntr_fid);
	if (!cntr_priv->wait)
		return -FI_EINVAL;

	if (cntr_priv->attr.wait_obj == FI_WAIT_SET ||
	    cntr_priv->attr.wait_obj == FI_WAIT_NONE)
		return -FI_EINVAL;

	return sstmacx_cntr_wait_sleep(cntr_priv, threshold, timeout);
}

DIRECT_FN STATIC extern "C" int sstmacx_cntr_adderr(struct fid_cntr *cntr, uint64_t value)
{
	struct sstmacx_fid_cntr *cntr_priv;

	cntr_priv = container_of(cntr, struct sstmacx_fid_cntr, cntr_fid);
	if (FI_VERSION_LT(cntr_priv->domain->fabric->fab_fid.api_version, FI_VERSION(1, 5)))
		return -FI_EOPNOTSUPP;

	ofi_atomic_add32(&cntr_priv->cnt_err, (int)value);

	if (cntr_priv->wait)
		_sstmacx_signal_wait_obj(cntr_priv->wait);

	return FI_SUCCESS;
}

DIRECT_FN STATIC extern "C" int sstmacx_cntr_seterr(struct fid_cntr *cntr, uint64_t value)
{
	struct sstmacx_fid_cntr *cntr_priv;

	cntr_priv = container_of(cntr, struct sstmacx_fid_cntr, cntr_fid);

	if (FI_VERSION_LT(cntr_priv->domain->fabric->fab_fid.api_version, FI_VERSION(1, 5)))
		return -FI_EOPNOTSUPP;

	ofi_atomic_set32(&cntr_priv->cnt_err, (int)value);

	if (cntr_priv->wait)
		_sstmacx_signal_wait_obj(cntr_priv->wait);

	return FI_SUCCESS;
}

static void __cntr_destruct(void *obj)
{
	struct sstmacx_fid_cntr *cntr = (struct sstmacx_fid_cntr *) obj;

	_sstmacx_ref_put(cntr->domain);

	switch (cntr->attr.wait_obj) {
	case FI_WAIT_NONE:
		break;
	case FI_WAIT_SET:
		_sstmacx_wait_set_remove(cntr->wait, &cntr->cntr_fid.fid);
		break;
	case FI_WAIT_UNSPEC:
	case FI_WAIT_FD:
	case FI_WAIT_MUTEX_COND:
		assert(cntr->wait);
		sstmacx_wait_close(&cntr->wait->fid);
		break;
	default:
		SSTMACX_WARN(FI_LOG_CQ, "format: %d unsupported.\n",
			  cntr->attr.wait_obj);
		break;
	}

	_sstmacx_prog_fini(&cntr->pset);

	free(cntr);
}

static extern "C" int sstmacx_cntr_close(fid_t fid)
{
	struct sstmacx_fid_cntr *cntr;
	int references_held;

	SSTMACX_TRACE(FI_LOG_CQ, "\n");

	cntr = container_of(fid, struct sstmacx_fid_cntr, cntr_fid.fid);

	/* applications should never call close more than once. */
	references_held = _sstmacx_ref_put(cntr);
	if (references_held) {
		SSTMACX_INFO(FI_LOG_CQ, "failed to fully close cntr due to lingering "
			  "references. references=%i cntr=%p\n",
			  references_held, cntr);
	}

	return FI_SUCCESS;
}

DIRECT_FN STATIC uint64_t sstmacx_cntr_readerr(struct fid_cntr *cntr)
{
	int v, ret;
	struct sstmacx_fid_cntr *cntr_priv;

	if (cntr == NULL)
		return -FI_EINVAL;

	cntr_priv = container_of(cntr, struct sstmacx_fid_cntr, cntr_fid);
	v = ofi_atomic_get32(&cntr_priv->cnt_err);

	ret = __sstmacx_cntr_progress(cntr_priv);
	if (ret != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_CQ, " __sstmacx_cntr_progress returned %d.\n",
			  ret);

	return (uint64_t)v;
}

DIRECT_FN STATIC uint64_t sstmacx_cntr_read(struct fid_cntr *cntr)
{
	int v, ret;
	struct sstmacx_fid_cntr *cntr_priv;

	if (cntr == NULL)
		return -FI_EINVAL;

	cntr_priv = container_of(cntr, struct sstmacx_fid_cntr, cntr_fid);

	if (cntr_priv->wait)
		sstmacx_wait_wait((struct fid_wait *)cntr_priv->wait, 0);

	ret = __sstmacx_cntr_progress(cntr_priv);
	if (ret != FI_SUCCESS)
		SSTMACX_WARN(FI_LOG_CQ, " __sstmacx_cntr_progress returned %d.\n",
			  ret);

	v = ofi_atomic_get32(&cntr_priv->cnt);

	return (uint64_t)v;
}

DIRECT_FN STATIC extern "C" int sstmacx_cntr_add(struct fid_cntr *cntr, uint64_t value)
{
	struct sstmacx_fid_cntr *cntr_priv;

	if (cntr == NULL)
		return -FI_EINVAL;

	cntr_priv = container_of(cntr, struct sstmacx_fid_cntr, cntr_fid);
	ofi_atomic_add32(&cntr_priv->cnt, (int)value);

	if (cntr_priv->wait)
		_sstmacx_signal_wait_obj(cntr_priv->wait);

	_sstmacx_trigger_check_cntr(cntr_priv);

	return FI_SUCCESS;
}

DIRECT_FN STATIC extern "C" int sstmacx_cntr_set(struct fid_cntr *cntr, uint64_t value)
{
	struct sstmacx_fid_cntr *cntr_priv;

	if (cntr == NULL)
		return -FI_EINVAL;

	cntr_priv = container_of(cntr, struct sstmacx_fid_cntr, cntr_fid);
	ofi_atomic_set32(&cntr_priv->cnt, (int)value);

	if (cntr_priv->wait)
		_sstmacx_signal_wait_obj(cntr_priv->wait);

	_sstmacx_trigger_check_cntr(cntr_priv);

	return FI_SUCCESS;
}

static extern "C" int sstmacx_cntr_control(struct fid *cntr, int command, void *arg)
{
	struct sstmacx_fid_cntr *cntr_priv;

	if (cntr == NULL)
		return -FI_EINVAL;

	cntr_priv = container_of(cntr, struct sstmacx_fid_cntr, cntr_fid);

	switch (command) {
	case FI_SETOPSFLAG:
		cntr_priv->attr.flags = *(uint64_t *)arg;
		break;
	case FI_GETOPSFLAG:
		if (!arg)
			return -FI_EINVAL;
		*(uint64_t *)arg = cntr_priv->attr.flags;
		break;
	case FI_GETWAIT:
		/* return _sstmacx_get_wait_obj(cntr_priv->wait, arg); */
		return -FI_ENOSYS;
	default:
		return -FI_EINVAL;
	}

	return FI_SUCCESS;

}


DIRECT_FN extern "C" int sstmacx_cntr_open(struct fid_domain *domain,
			     struct fi_cntr_attr *attr,
			     struct fid_cntr **cntr, void *context)
{
	int ret = FI_SUCCESS;
	struct sstmacx_fid_domain *domain_priv;
	struct sstmacx_fid_cntr *cntr_priv;

	SSTMACX_TRACE(FI_LOG_CQ, "\n");

	ret = __verify_cntr_attr(attr);
	if (ret)
		goto err;

	domain_priv = container_of(domain, struct sstmacx_fid_domain, domain_fid);
	if (!domain_priv) {
		ret = -FI_EINVAL;
		goto err;
	}

	cntr_priv = calloc(1, sizeof(*cntr_priv));
	if (!cntr_priv) {
		ret = -FI_ENOMEM;
		goto err;
	}

	cntr_priv->requires_lock = (domain_priv->thread_model !=
			FI_THREAD_COMPLETION);

	cntr_priv->domain = domain_priv;
	cntr_priv->attr = *attr;
	/* ref count is initialized to one to show that the counter exists */
	_sstmacx_ref_init(&cntr_priv->ref_cnt, 1, __cntr_destruct);

	/* initialize atomics */
	ofi_atomic_initialize32(&cntr_priv->cnt, 0);
	ofi_atomic_initialize32(&cntr_priv->cnt_err, 0);

	_sstmacx_ref_get(cntr_priv->domain);

	_sstmacx_prog_init(&cntr_priv->pset);

	dlist_init(&cntr_priv->trigger_list);
	fastlock_init(&cntr_priv->trigger_lock);

	ret = sstmacx_cntr_set_wait(cntr_priv);
	if (ret)
		goto err_wait;

	cntr_priv->cntr_fid.fid.fclass = FI_CLASS_CNTR;
	cntr_priv->cntr_fid.fid.context = context;
	cntr_priv->cntr_fid.fid.ops = &sstmacx_cntr_fi_ops;
	cntr_priv->cntr_fid.ops = &sstmacx_cntr_ops;

	*cntr = &cntr_priv->cntr_fid;
	return ret;

err_wait:
	_sstmacx_ref_put(cntr_priv->domain);
	free(cntr_priv);
err:
	return ret;
}


/*******************************************************************************
 * FI_OPS_* data structures.
 ******************************************************************************/
static struct fi_ops sstmacx_cntr_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sstmacx_cntr_close,
	.bind = fi_no_bind,
	.control = sstmacx_cntr_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_cntr sstmacx_cntr_ops = {
	.size = sizeof(struct fi_ops_cntr),
	.readerr = sstmacx_cntr_readerr,
	.read = sstmacx_cntr_read,
	.add = sstmacx_cntr_add,
	.set = sstmacx_cntr_set,
	.wait = sstmacx_cntr_wait,
	.adderr = sstmacx_cntr_adderr,
	.seterr = sstmacx_cntr_seterr
};

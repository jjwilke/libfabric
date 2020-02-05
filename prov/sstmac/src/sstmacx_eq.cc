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
 * Copyright (c) 2015 Los Alamos National Security, LLC. All rights reserved.
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

#include <assert.h>

#include <stdlib.h>

#include "sstmacx.h"
#include "sstmacx_eq.h"
#include "sstmacx_util.h"
#include "sstmacx_cm.h"

/*******************************************************************************
 * Global declarations
 ******************************************************************************/
DLIST_HEAD(sstmacx_eq_list);
pthread_mutex_t sstmacx_eq_list_lock = PTHREAD_MUTEX_INITIALIZER;

/*******************************************************************************
 * Forward declaration for ops structures.
 ******************************************************************************/
static struct fi_ops_eq sstmacx_eq_ops;
static struct fi_ops sstmacx_fi_eq_ops;


/*******************************************************************************
 * Helper functions.
 ******************************************************************************/

static void sstmacx_eq_cleanup_err_bufs(struct sstmacx_fid_eq *eq, int free_all)
{
	struct sstmacx_eq_err_buf *ebuf, *tmp;

	dlist_for_each_safe(&eq->err_bufs, ebuf, tmp, dlist) {
		if (free_all || ebuf->do_free) {
			dlist_remove(&ebuf->dlist);
			free(ebuf);
		}
	}
}

static extern "C" int sstmacx_eq_set_wait(struct sstmacx_fid_eq *eq)
{
	int ret = FI_SUCCESS;

	SSTMACX_TRACE(FI_LOG_EQ, "\n");

	struct fi_wait_attr requested = {
		.wait_obj = eq->attr.wait_obj,
		.flags = 0
	};

	switch (eq->attr.wait_obj) {
	case FI_WAIT_UNSPEC:
		ret = sstmacx_wait_open(&eq->fabric->fab_fid, &requested,
				     &eq->wait);
		break;
	case FI_WAIT_SET:
		ret = _sstmacx_wait_set_add(eq->attr.wait_set, &eq->eq_fid.fid);
		if (!ret)
			eq->wait = eq->attr.wait_set;
		break;
	default:
		break;
	}

	return ret;
}

static extern "C" int sstmacx_verify_eq_attr(struct fi_eq_attr *attr)
{

	SSTMACX_TRACE(FI_LOG_EQ, "\n");

	if (!attr)
		return -FI_EINVAL;

	if (!attr->size)
		attr->size = SSTMACX_EQ_DEFAULT_SIZE;

	/*
	 * We only support FI_WAIT_SET and FI_WAIT_UNSPEC
	 */
	switch (attr->wait_obj) {
	case FI_WAIT_NONE:
		break;
	case FI_WAIT_SET:
		if (!attr->wait_set) {
			SSTMACX_WARN(FI_LOG_EQ,
				  "FI_WAIT_SET is set, but wait_set field doesn't reference a wait object.\n");
			return -FI_EINVAL;
		}
		break;
	case FI_WAIT_UNSPEC:
		break;
	case FI_WAIT_FD:
	case FI_WAIT_MUTEX_COND:
	default:
		SSTMACX_WARN(FI_LOG_EQ, "wait type: %d unsupported.\n",
			  attr->wait_obj);
		return -FI_ENOSYS;
	}

	return FI_SUCCESS;
}

static void free_eq_entry(struct slist_entry *item)
{
	struct sstmacx_eq_entry *entry;

	entry = container_of(item, struct sstmacx_eq_entry, item);

	free(entry->the_entry);
	free(entry);
}

static struct slist_entry *alloc_eq_entry(size_t size)
{
	struct sstmacx_eq_entry *entry = calloc(1, sizeof(*entry));

	if (!entry) {
		SSTMACX_WARN(FI_LOG_EQ, "out of memory\n");
		goto err;
	}

	if (size) {
		entry->the_entry = malloc(size);
		if (!entry->the_entry) {
			SSTMACX_WARN(FI_LOG_EQ, "out of memory\n");
			goto cleanup;
		}
	}

	return &entry->item;

cleanup:
	free(entry);
err:
	return NULL;
}

ssize_t _sstmacx_eq_write_error(struct sstmacx_fid_eq *eq, fid_t fid,
			     void *context, uint64_t index, int err,
			     int prov_errno, void *err_data,
			     size_t err_size)
{
	struct fi_eq_err_entry *error;
	struct sstmacx_eq_entry *event;
	struct slist_entry *item;
	struct sstmacx_eq_err_buf *err_buf;

	ssize_t ret = FI_SUCCESS;

	if (!eq)
		return -FI_EINVAL;

	fastlock_acquire(&eq->lock);

	item = _sstmacx_queue_get_free(eq->errors);
	if (!item) {
		SSTMACX_WARN(FI_LOG_EQ, "error creating error entry\n");
		ret = -FI_ENOMEM;
		goto err;
	}

	event = container_of(item, struct sstmacx_eq_entry, item);

	error = event->the_entry;

	error->fid = fid;
	error->context = context;
	error->data = index;
	error->err = err;
	error->prov_errno = prov_errno;

	if (err_size) {
		err_buf = malloc(sizeof(struct sstmacx_eq_err_buf) + err_size);
		if (!err_buf) {
			_sstmacx_queue_enqueue_free(eq->errors, &event->item);
			ret = -FI_ENOMEM;
			goto err;
		}
		err_buf->do_free = 0;

		memcpy(err_buf->buf, err_data, err_size);
		error->err_data = err_buf->buf;
		error->err_data_size = err_size;

		dlist_insert_tail(&err_buf->dlist, &eq->err_bufs);
	} else {
		error->err_data = NULL;
		error->err_data_size = 0;
	}

	_sstmacx_queue_enqueue(eq->errors, &event->item);

	if (eq->wait)
		_sstmacx_signal_wait_obj(eq->wait);

err:
	fastlock_release(&eq->lock);

	return ret;
}

static void __eq_destruct(void *obj)
{
	struct sstmacx_fid_eq *eq = (struct sstmacx_fid_eq *) obj;
	pthread_mutex_lock(&sstmacx_eq_list_lock);
	dlist_remove(&eq->sstmacx_fid_eq_list);
	pthread_mutex_unlock(&sstmacx_eq_list_lock);

	_sstmacx_ref_put(eq->fabric);

	fastlock_destroy(&eq->lock);

	switch (eq->attr.wait_obj) {
	case FI_WAIT_NONE:
		break;
	case FI_WAIT_SET:
		_sstmacx_wait_set_remove(eq->wait, &eq->eq_fid.fid);
		break;
	case FI_WAIT_UNSPEC:
	case FI_WAIT_FD:
	case FI_WAIT_MUTEX_COND:
		assert(eq->wait);
		sstmacx_wait_close(&eq->wait->fid);
		break;
	default:
		SSTMACX_WARN(FI_LOG_EQ, "format: %d unsupported\n.",
			  eq->attr.wait_obj);
		break;
	}

	_sstmacx_queue_destroy(eq->events);
	_sstmacx_queue_destroy(eq->errors);

	sstmacx_eq_cleanup_err_bufs(eq, 1);

	free(eq);
}

extern "C" int _sstmacx_eq_poll_obj_add(struct sstmacx_fid_eq *eq, struct fid *obj_fid)
{
	struct sstmacx_eq_poll_obj *pobj;

	COND_WRITE_ACQUIRE(eq->requires_lock, &eq->poll_obj_lock);

	pobj = malloc(sizeof(struct sstmacx_eq_poll_obj));
	if (!pobj) {
		SSTMACX_WARN(FI_LOG_EQ, "Failed to add object to EQ poll list.\n");
		COND_RW_RELEASE(eq->requires_lock, &eq->poll_obj_lock);
		return -FI_ENOMEM;
	}

	pobj->obj_fid = obj_fid;
	dlist_init(&pobj->list);
	dlist_insert_tail(&pobj->list, &eq->poll_objs);

	COND_RW_RELEASE(eq->requires_lock, &eq->poll_obj_lock);

	SSTMACX_INFO(FI_LOG_EQ, "Added object(%d, %p) to EQ(%p) poll list\n",
		  obj_fid->fclass, obj_fid, eq);

	return FI_SUCCESS;
}

extern "C" int _sstmacx_eq_poll_obj_rem(struct sstmacx_fid_eq *eq, struct fid *obj_fid)
{
	struct sstmacx_eq_poll_obj *pobj, *tmp;

	COND_WRITE_ACQUIRE(eq->requires_lock, &eq->poll_obj_lock);

	dlist_for_each_safe(&eq->poll_objs, pobj, tmp, list) {
		if (pobj->obj_fid == obj_fid) {
			dlist_remove(&pobj->list);
			free(pobj);
			SSTMACX_INFO(FI_LOG_EQ,
				  "Removed object(%d, %p) from EQ(%p) poll list\n",
				  pobj->obj_fid->fclass, pobj, eq);
			COND_RW_RELEASE(eq->requires_lock, &eq->poll_obj_lock);
			return FI_SUCCESS;
		}
	}

	COND_RW_RELEASE(eq->requires_lock, &eq->poll_obj_lock);

	SSTMACX_WARN(FI_LOG_EQ, "object not found on EQ poll list.\n");
	return -FI_EINVAL;
}

extern "C" int _sstmacx_eq_progress(struct sstmacx_fid_eq *eq)
{
	struct sstmacx_eq_poll_obj *pobj, *tmp;
	int rc;
	struct sstmacx_fid_pep *pep;
	struct sstmacx_fid_ep *ep;

	COND_READ_ACQUIRE(eq->requires_lock, &eq->poll_obj_lock);

	dlist_for_each_safe(&eq->poll_objs, pobj, tmp, list) {
		switch (pobj->obj_fid->fclass) {
		case FI_CLASS_PEP:
			pep = container_of(pobj->obj_fid, struct sstmacx_fid_pep,
					   pep_fid.fid);
			rc = _sstmacx_pep_progress(pep);
			if (rc) {
				SSTMACX_WARN(FI_LOG_EQ,
					  "_sstmacx_pep_progress failed: %d\n",
					  rc);
			}
			break;
		case FI_CLASS_EP:
			ep = container_of(pobj->obj_fid, struct sstmacx_fid_ep,
					  ep_fid.fid);
			rc = _sstmacx_ep_progress(ep);
			if (rc) {
				SSTMACX_WARN(FI_LOG_EP_CTRL,
					  "_sstmacx_ep_progress failed: %d\n",
					  rc);
			}
			break;
		default:
			SSTMACX_WARN(FI_LOG_EQ,
				  "invalid poll object: %d %p\n",
				  pobj->obj_fid->fclass, pobj);
			break;
		}
	}

	COND_RW_RELEASE(eq->requires_lock, &eq->poll_obj_lock);

	return FI_SUCCESS;
}

/*******************************************************************************
 * API function implementations.
 ******************************************************************************/
/*
 * - Handle FI_WRITE flag. When not included, replace write function with
 *   fi_no_eq_write.
 */
DIRECT_FN extern "C" int sstmacx_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
			   struct fid_eq **eq, void *context)
{
	struct sstmacx_fid_eq *eq_priv;

	int ret = FI_SUCCESS;

	SSTMACX_TRACE(FI_LOG_EQ, "\n");

	if (!fabric)
		return -FI_EINVAL;

	eq_priv = calloc(1, sizeof(*eq_priv));
	if (!eq_priv)
		return -FI_ENOMEM;

	ret = sstmacx_verify_eq_attr(attr);
	if (ret)
		goto err;

	eq_priv->fabric = container_of(fabric, struct sstmacx_fid_fabric,
					  fab_fid);

	_sstmacx_ref_init(&eq_priv->ref_cnt, 1, __eq_destruct);

	_sstmacx_ref_get(eq_priv->fabric);

	eq_priv->eq_fid.fid.fclass = FI_CLASS_EQ;
	eq_priv->eq_fid.fid.context = context;
	eq_priv->eq_fid.fid.ops = &sstmacx_fi_eq_ops;
	eq_priv->eq_fid.ops = &sstmacx_eq_ops;
	eq_priv->requires_lock = 1;
	eq_priv->attr = *attr;

	fastlock_init(&eq_priv->lock);

	rwlock_init(&eq_priv->poll_obj_lock);
	dlist_init(&eq_priv->poll_objs);

	dlist_init(&eq_priv->err_bufs);

	ret = sstmacx_eq_set_wait(eq_priv);
	if (ret)
		goto err1;

	ret = _sstmacx_queue_create(&eq_priv->events, alloc_eq_entry,
				 free_eq_entry, 0, eq_priv->attr.size);
	if (ret)
		goto err1;

	ret = _sstmacx_queue_create(&eq_priv->errors, alloc_eq_entry,
				 free_eq_entry, sizeof(struct fi_eq_err_entry),
				 0);
	if (ret)
		goto err2;

	*eq = &eq_priv->eq_fid;

	pthread_mutex_lock(&sstmacx_eq_list_lock);
	dlist_insert_tail(&eq_priv->sstmacx_fid_eq_list, &sstmacx_eq_list);
	pthread_mutex_unlock(&sstmacx_eq_list_lock);

	return ret;

err2:
	_sstmacx_queue_destroy(eq_priv->events);
err1:
	_sstmacx_ref_put(eq_priv->fabric);
	fastlock_destroy(&eq_priv->lock);
err:
	free(eq_priv);
	return ret;
}

DIRECT_FN STATIC extern "C" int sstmacx_eq_close(struct fid *fid)
{
	struct sstmacx_fid_eq *eq;
	int references_held;

	SSTMACX_TRACE(FI_LOG_EQ, "\n");

	if (!fid)
		return -FI_EINVAL;

	eq = container_of(fid, struct sstmacx_fid_eq, eq_fid);

	references_held = _sstmacx_ref_put(eq);
	if (references_held) {
		SSTMACX_INFO(FI_LOG_EQ, "failed to fully close eq due "
				"to lingering references. references=%i eq=%p\n",
				references_held, eq);
	}

	return FI_SUCCESS;
}

static ssize_t __sstmacx_eq_sread(int blocking, struct fid_eq *eq,
			       uint32_t *event, void *buf, size_t len,
			       uint64_t flags, int timeout)
{
	struct sstmacx_fid_eq *eq_priv;
	struct sstmacx_eq_entry *entry;
	struct slist_entry *item;
	ssize_t read_size;

	if (!eq || !event || (len && !buf))
		return -FI_EINVAL;

	eq_priv = container_of(eq, struct sstmacx_fid_eq, eq_fid);

	if ((blocking && !eq_priv->wait) ||
	    (blocking && eq_priv->attr.wait_obj == FI_WAIT_SET)) {
		SSTMACX_WARN(FI_LOG_EQ, "Invalid wait type\n");
		return -FI_EINVAL;
	}

	sstmacx_eq_cleanup_err_bufs(eq_priv, 0);

	_sstmacx_eq_progress(eq_priv);

	if (_sstmacx_queue_peek(eq_priv->errors))
		return -FI_EAVAIL;

	if (eq_priv->wait)
		sstmacx_wait_wait((struct fid_wait *) eq_priv->wait, timeout);

	fastlock_acquire(&eq_priv->lock);

	if (_sstmacx_queue_peek(eq_priv->errors)) {
		read_size = -FI_EAVAIL;
		goto err;
	}

	item = _sstmacx_queue_peek(eq_priv->events);

	if (!item) {
		read_size = -FI_EAGAIN;
		goto err;
	}

	entry = container_of(item, struct sstmacx_eq_entry, item);

	if (len < entry->len) {
		read_size = -FI_ETOOSMALL;
		goto err;
	}

	*event = entry->type;

	read_size = entry->len;
	memcpy(buf, entry->the_entry, read_size);

	if (!(flags & FI_PEEK)) {
		item = _sstmacx_queue_dequeue(eq_priv->events);

		free(entry->the_entry);
		entry->the_entry = NULL;

		_sstmacx_queue_enqueue_free(eq_priv->events, &entry->item);
	}

err:
	fastlock_release(&eq_priv->lock);

	return read_size;
}

DIRECT_FN STATIC ssize_t sstmacx_eq_read(struct fid_eq *eq, uint32_t *event,
				      void *buf, size_t len, uint64_t flags)
{
	return __sstmacx_eq_sread(0, eq, event, buf, len, flags, 0);
}

DIRECT_FN STATIC ssize_t sstmacx_eq_sread(struct fid_eq *eq, uint32_t *event,
				       void *buf, size_t len, int timeout,
				       uint64_t flags)
{
	return __sstmacx_eq_sread(1, eq, event, buf, len, flags, timeout);
}

DIRECT_FN STATIC extern "C" int sstmacx_eq_control(struct fid *eq, int command, void *arg)
{
	/* disabled until new trywait interface is implemented
	struct sstmacx_fid_eq *eq_priv;

	eq_priv = container_of(eq, struct sstmacx_fid_eq, eq_fid);
	*/
	switch (command) {
	case FI_GETWAIT:
		/* return _sstmacx_get_wait_obj(eq_priv->wait, arg); */
		return -FI_ENOSYS;
	default:
		return -FI_EINVAL;
	}
}

DIRECT_FN STATIC ssize_t sstmacx_eq_readerr(struct fid_eq *eq,
					 struct fi_eq_err_entry *buf,
					 uint64_t flags)
{
	struct sstmacx_fid_eq *eq_priv;
	struct sstmacx_eq_entry *entry;
	struct slist_entry *item;
	struct sstmacx_eq_err_buf *err_buf;
	struct fi_eq_err_entry *fi_err;

	ssize_t read_size = sizeof(*buf);

	eq_priv = container_of(eq, struct sstmacx_fid_eq, eq_fid);

	fastlock_acquire(&eq_priv->lock);

	if (flags & FI_PEEK)
		item = _sstmacx_queue_peek(eq_priv->errors);
	else
		item = _sstmacx_queue_dequeue(eq_priv->errors);

	if (!item) {
		read_size = -FI_EAGAIN;
		goto err;
	}

	entry = container_of(item, struct sstmacx_eq_entry, item);
	fi_err = (struct fi_eq_err_entry *)entry->the_entry;

	memcpy(buf, entry->the_entry, read_size);

	/* If removing an event with err_data, mark err buf to be freed during
	 * the next EQ read. */
	if (!(flags & FI_PEEK) && fi_err->err_data) {
		err_buf = container_of(fi_err->err_data,
				       struct sstmacx_eq_err_buf, buf);
		err_buf->do_free = 1;
	}

	_sstmacx_queue_enqueue_free(eq_priv->errors, &entry->item);

err:
	fastlock_release(&eq_priv->lock);

	return read_size;
}

DIRECT_FN STATIC ssize_t sstmacx_eq_write(struct fid_eq *eq, uint32_t event,
				       const void *buf, size_t len,
				       uint64_t flags)
{
	struct sstmacx_fid_eq *eq_priv;
	struct slist_entry *item;
	struct sstmacx_eq_entry *entry;

	ssize_t ret = len;

	eq_priv = container_of(eq, struct sstmacx_fid_eq, eq_fid);

	fastlock_acquire(&eq_priv->lock);

	item = _sstmacx_queue_get_free(eq_priv->events);
	if (!item) {
		SSTMACX_WARN(FI_LOG_EQ, "error creating eq_entry\n");
		ret = -FI_ENOMEM;
		goto err;
	}

	entry = container_of(item, struct sstmacx_eq_entry, item);

	entry->the_entry = calloc(1, len);
	if (!entry->the_entry) {
		_sstmacx_queue_enqueue_free(eq_priv->events, &entry->item);
		SSTMACX_WARN(FI_LOG_EQ, "error allocating buffer\n");
		ret = -FI_ENOMEM;
		goto err;
	}

	memcpy(entry->the_entry, buf, len);

	entry->len = len;
	entry->type = event;
	entry->flags = flags;

	_sstmacx_queue_enqueue(eq_priv->events, &entry->item);

	if (eq_priv->wait)
		_sstmacx_signal_wait_obj(eq_priv->wait);

err:
	fastlock_release(&eq_priv->lock);

	return ret;
}

/**
 * Converts provider specific error information into a printable string.
 *
 * @param[in] eq		the event queue
 * @param[in] prov_errno	the provider specific error number
 * @param[in/out] buf		optional buffer to print error information
 * @param[in] len		the length of buf
 *
 * @return the printable string
 * @return NULL upon error or if the operation is not supported yet
 */
DIRECT_FN STATIC const char *sstmacx_eq_strerror(struct fid_eq *eq, int prov_errno,
					      const void *err_data, char *buf,
					      size_t len)
{
	return NULL;
}

/*******************************************************************************
 * FI_OPS_* data structures.
 ******************************************************************************/
static struct fi_ops_eq sstmacx_eq_ops = {
	.size = sizeof(struct fi_ops_eq),
	.read = sstmacx_eq_read,
	.readerr = sstmacx_eq_readerr,
	.write = sstmacx_eq_write,
	.sread = sstmacx_eq_sread,
	.strerror = sstmacx_eq_strerror
};

static struct fi_ops sstmacx_fi_eq_ops = {
	.size = sizeof(struct fi_ops),
	.close = sstmacx_eq_close,
	.bind = fi_no_bind,
	.control = sstmacx_eq_control,
	.ops_open = fi_no_ops_open
};

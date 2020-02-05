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
#include <config.h>
#endif /* HAVE_CONFIG_H */

#ifndef _SSTMACX_UTIL_H_
#define _SSTMACX_UTIL_H_

#include <stdio.h>
#include <ofi.h>

extern struct fi_provider sstmacx_prov;
#if HAVE_CRITERION
extern int sstmacx_first_pe_on_node; /* globally visible for  criterion */
#endif

/*
 * For debug logging (ENABLE_DEBUG)
 * Q: should this just always be available?
 */
#ifndef ENABLE_DEBUG

#define SSTMACX_LOG_INTERNAL(FI_LOG_FN, LEVEL, subsystem, fmt, ...)	\
	FI_LOG_FN(&sstmacx_prov, subsystem, fmt, ##__VA_ARGS__)

#define SSTMACX_FI_PRINT(prov, subsystem, ...)

#else

/* defined in sstmacx_init.c */
extern __thread pid_t sstmacx_debug_pid;
extern __thread uint32_t sstmacx_debug_tid;
extern ofi_atomic32_t sstmacx_debug_next_tid;

#define SSTMACX_FI_PRINT(prov, subsystem, ...)				\
	do {								\
		fi_log(prov, FI_LOG_WARN, subsystem,			\
				__func__, __LINE__, __VA_ARGS__);	\
	} while (0)


/* These macros are used to prepend the log message with the pid and
 * unique thread id.  Do not use them directly.  Rather use the normal
 * SSTMACX_* macros.
 */
#define SSTMACX_LOG_INTERNAL(FI_LOG_FN, LEVEL, subsystem, fmt, ...)	\
	do {	\
		if (fi_log_enabled(&sstmacx_prov, LEVEL, subsystem)) { \
			const int fmt_len = 256;			\
			char new_fmt[fmt_len];				\
			if (sstmacx_debug_tid  == ~(uint32_t) 0) {		\
				sstmacx_debug_tid = ofi_atomic_inc32(&sstmacx_debug_next_tid); \
			}						\
			if (sstmacx_debug_pid == ~(uint32_t) 0) {		\
				sstmacx_debug_pid = getpid();		\
			}						\
			snprintf(new_fmt, fmt_len, "[%%d:%%d] %s", fmt);	\
			FI_LOG_FN(&sstmacx_prov, subsystem, new_fmt,	\
				  sstmacx_debug_pid, sstmacx_debug_tid, ##__VA_ARGS__); \
		} \
	} while (0)

#endif

#define SSTMACX_WARN(subsystem, ...)                                              \
	SSTMACX_LOG_INTERNAL(FI_WARN, FI_LOG_WARN, subsystem, __VA_ARGS__)
#define SSTMACX_TRACE(subsystem, ...)                                             \
	SSTMACX_LOG_INTERNAL(FI_TRACE, FI_LOG_TRACE, subsystem, __VA_ARGS__)
#define SSTMACX_INFO(subsystem, ...)                                              \
	SSTMACX_LOG_INTERNAL(FI_INFO, FI_LOG_INFO, subsystem, __VA_ARGS__)
#if ENABLE_DEBUG
#define SSTMACX_DEBUG(subsystem, ...)                                             \
	SSTMACX_LOG_INTERNAL(FI_DBG, FI_LOG_DEBUG, subsystem, __VA_ARGS__)
#define SSTMACX_DBG_TRACE(subsystem, ...)                                         \
	SSTMACX_LOG_INTERNAL(FI_TRACE, FI_LOG_TRACE, subsystem, __VA_ARGS__)
#else
#define SSTMACX_DEBUG(subsystem, ...)                                             \
	do {} while (0)
#define SSTMACX_DBG_TRACE(subsystem, ...)                                         \
	do {} while (0)
#endif

#define SSTMACX_ERR(subsystem, ...)                                               \
	SSTMACX_LOG_INTERNAL(SSTMACX_FI_PRINT, FI_LOG_WARN, subsystem, __VA_ARGS__)
#define SSTMACX_FATAL(subsystem, ...)                                             \
	do { \
		SSTMACX_LOG_INTERNAL(SSTMACX_FI_PRINT, FI_LOG_WARN, subsystem, __VA_ARGS__); \
		abort(); \
	} while (0)

#if 1
#define SSTMACX_LOG_DUMP_TXD(txd)
#else
#define SSTMACX_LOG_DUMP_TXD(txd)						     \
	do {								     \
		sstmac_mem_handle_t *tl_mdh = &(txd)->sstmac_desc.local_mem_hndl;  \
		sstmac_mem_handle_t *tr_mdh = &(txd)->sstmac_desc.remote_mem_hndl; \
		SSTMACX_INFO(FI_LOG_EP_DATA, "la: %llx ra: %llx len: %d\n",     \
			  (txd)->sstmac_desc.local_addr,			     \
			  (txd)->sstmac_desc.remote_addr,			     \
			  (txd)->sstmac_desc.length);			     \
		SSTMACX_INFO(FI_LOG_EP_DATA,				     \
			  "lmdh: %llx:%llx rmdh: %llx:%llx key: %llx\n",     \
			  *(uint64_t *)tl_mdh, *(((uint64_t *)tl_mdh) + 1),  \
			  *(uint64_t *)tr_mdh, *(((uint64_t *)tr_mdh) + 1),  \
			  fab_req->amo.rem_mr_key);			     \
	} while (0)
#endif

/* slist and dlist utilities */
#include "ofi_list.h"

static inline void dlist_node_init(struct dlist_entry *e)
{
	e->prev = e->next = NULL;
}

#define DLIST_IN_LIST(e) e.prev != e.next

#define DLIST_HEAD(dlist)  struct dlist_entry dlist = { &(dlist), &(dlist) }

#define dlist_entry(e, type, member) container_of(e, type, member)

#define dlist_first_entry(h, type, member)				\
	(dlist_empty(h) ? NULL : dlist_entry((h)->next, type, member))

/* Iterate over the entries in the list */
#define dlist_for_each(h, e, member)					\
	for (e = dlist_first_entry(h, typeof(*e), member);		\
	     e && (&e->member != h);					\
	     e = dlist_entry((&e->member)->next, typeof(*e), member))

/* Iterate over the entries in the list, possibly deleting elements */
#define dlist_for_each_safe(h, e, n, member)				\
	for (e = dlist_first_entry(h, typeof(*e), member),		\
		     n = e ? dlist_entry((&e->member)->next,		\
					 typeof(*e), member) : NULL;	\
	     e && (&e->member != h);					\
	     e = n, n = dlist_entry((&e->member)->next, typeof(*e), member))

#define rwlock_t pthread_rwlock_t
#define rwlock_init(lock) pthread_rwlock_init(lock, NULL)
#define rwlock_destroy(lock) pthread_rwlock_destroy(lock)
#define rwlock_wrlock(lock) pthread_rwlock_wrlock(lock)
#define rwlock_rdlock(lock) pthread_rwlock_rdlock(lock)
#define rwlock_unlock(lock) pthread_rwlock_unlock(lock)

/*
 * prototypes
 */
int _sstmacx_get_cq_limit(void);
int sstmacxu_get_rdma_credentials(void *addr, uint8_t *ptag, uint32_t *cookie);
int sstmacxu_to_fi_errno(int err);

int _sstmacx_task_is_not_app(void);
int _sstmacx_job_enable_unassigned_cpus(void);
int _sstmacx_job_disable_unassigned_cpus(void);
int _sstmacx_job_enable_affinity_apply(void);
int _sstmacx_job_disable_affinity_apply(void);

void _sstmacx_app_cleanup(void);
int _sstmacx_job_fma_limit(uint32_t dev_id, uint8_t ptag, uint32_t *limit);
int _sstmacx_job_cq_limit(uint32_t dev_id, uint8_t ptag, uint32_t *limit);
int _sstmacx_pes_on_node(uint32_t *num_pes);
int _sstmacx_pe_node_rank(int *pe_node_rank);
int _sstmacx_nics_per_rank(uint32_t *nics_per_rank);
void _sstmacx_dump_sstmac_res(uint8_t ptag);
int _sstmacx_get_num_corespec_cpus(uint32_t *num_core_spec_cpus);

struct sstmacx_reference {
	ofi_atomic32_t references;
	void (*destruct)(void *obj);
};

/* Should not be used unless the reference counting variable has a
 * non-standard name
 */
#define __ref_get(ptr, var) \
	({ \
		struct sstmacx_reference *ref = &(ptr)->var; \
		int references_held = ofi_atomic_inc32(&ref->references); \
		SSTMACX_DEBUG(FI_LOG_CORE, "%p refs %d\n", \
			   ref, references_held); \
		assert(references_held > 0); \
		references_held; })

#define __ref_put(ptr, var) \
	({ \
		struct sstmacx_reference *ref = &(ptr)->var; \
		int references_held = ofi_atomic_dec32(&ref->references); \
		SSTMACX_DEBUG(FI_LOG_CORE, "%p refs %d\n", \
			   ref, references_held); \
		assert(references_held >= 0); \
		if (references_held == 0) \
			ref->destruct((void *) (ptr)); \
		references_held; })

/* by default, all of the sstmacx reference counting variables are
 *   named 'ref_cnt'. The macros provided below will autofill the var arg.
 */
#define _sstmacx_ref_get(ptr) __ref_get(ptr, ref_cnt)
#define _sstmacx_ref_put(ptr) __ref_put(ptr, ref_cnt)

/**
 * Only allow FI_REMOTE_CQ_DATA when the EP cap, FI_RMA_EVENT, is also set.
 *
 * @return zero if FI_REMOTE_CQ_DATA is not permitted; otherwise one.
 */
#define SSTMACX_ALLOW_FI_REMOTE_CQ_DATA(_flags, _ep_caps) \
					(((_flags) & FI_REMOTE_CQ_DATA) && \
					 ((_ep_caps) & FI_RMA_EVENT))

static inline void _sstmacx_ref_init(
		struct sstmacx_reference *ref,
		int initial_value,
		void (*destruct)(void *))
{
	ofi_atomic_initialize32(&ref->references, initial_value);
	SSTMACX_DEBUG(FI_LOG_CORE, "%p refs %d\n",
		   ref, initial_value);
	ref->destruct = destruct;
}

#define __STRINGIFY(expr) #expr
#define STRINGIFY(expr) __STRINGIFY(expr)

#define __COND_FUNC(cond, lock, func) \
	do { \
		if ((cond)) { \
			func(lock); \
		} \
	} while (0)

#define COND_ACQUIRE(cond, lock) \
	__COND_FUNC((cond), (lock), fastlock_acquire)
#define COND_READ_ACQUIRE(cond, lock) \
	__COND_FUNC((cond), (lock), rwlock_rdlock)
#define COND_WRITE_ACQUIRE(cond, lock) \
	__COND_FUNC((cond), (lock), rwlock_wrlock)

#define COND_RELEASE(cond, lock) \
	__COND_FUNC((cond), (lock), fastlock_release)
#define COND_RW_RELEASE(cond, lock) \
	__COND_FUNC((cond), (lock), rwlock_unlock)
#ifdef __GNUC__
#define __PREFETCH(addr, rw, locality) __builtin_prefetch(addr, rw, locality)
#else
#define __PREFETCH(addr, rw, locality) ((void *) 0)
#endif

#define READ_PREFETCH(addr) __PREFETCH(addr, 0, 3)
#define WRITE_PREFETCH(addr) __PREFETCH(addr, 1, 3)

#endif

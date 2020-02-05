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

#ifndef SSTMACX_MR_H_
#define SSTMACX_MR_H_

#ifdef HAVE_UDREG
#include <udreg_pub.h>
#endif

/* global includes */
#include "rdma/fi_domain.h"

/* provider includes */
#include "sstmacx_priv.h"
#include "sstmacx_mr_cache.h"

#define SSTMACX_USER_REG 0
#define SSTMACX_PROV_REG 1

#define SSTMACX_MR_PAGE_SHIFT 12
#define SSTMACX_MR_PFN_BITS 37
#define SSTMACX_MR_MDD_BITS 12
#define SSTMACX_MR_FMT_BITS 1
#define SSTMACX_MR_FLAG_BITS 2
#define SSTMACX_MR_VA_BITS (SSTMACX_MR_PFN_BITS + SSTMACX_MR_PAGE_SHIFT)
#define SSTMACX_MR_KEY_BITS (SSTMACX_MR_PFN_BITS + SSTMACX_MR_MDD_BITS)
#define SSTMACX_MR_RESERVED_BITS \
	(SSTMACX_MR_KEY_BITS + SSTMACX_MR_FLAG_BITS + SSTMACX_MR_FMT_BITS)
#define SSTMACX_MR_PADDING_LENGTH (64 - SSTMACX_MR_RESERVED_BITS)

/* TODO: optimize to save space by using a union to combine the two
 * independent sets of data
 */
struct sstmacx_mr_cache_info {
	/* used only with internal mr cache */
	sstmacx_mr_cache_t *mr_cache_rw;
	sstmacx_mr_cache_t *mr_cache_ro;

	/* used only with udreg */
	struct udreg_cache *udreg_cache;
	struct sstmacx_fid_domain *domain;
	struct sstmacx_auth_key *auth_key;

	fastlock_t mr_cache_lock;
	int inuse;
};

enum {
	SSTMACX_MR_FLAG_READONLY = 1 << 0,
	SSTMACX_MR_FLAG_BASIC_REG = 1 << 1,
};

enum {
	SSTMACX_MR_TYPE_INTERNAL = 0,
	SSTMACX_MR_TYPE_UDREG,
	SSTMACX_MR_TYPE_NONE,
	SSTMACX_MR_MAX_TYPE,
};

#define SSTMACX_DEFAULT_CACHE_TYPE SSTMACX_MR_TYPE_INTERNAL

/* forward declarations */
struct sstmacx_fid_domain;
struct sstmacx_nic;

/**
 * @brief sstmacx memory descriptor object for use with fi_mr_reg
 *
 * @var   mr_fid    libfabric memory region descriptor
 * @var   domain    sstmacx domain associated with this memory region
 * @var   mem_hndl  sstmac memory handle for the memory region
 * @var   nic       sstmacx nic associated with this memory region
 * @var   key       sstmacx memory cache key associated with this memory region
 */
struct sstmacx_fid_mem_desc {
	struct fid_mr mr_fid;
	struct sstmacx_fid_domain *domain;
	sstmac_mem_handle_t mem_hndl;
	struct sstmacx_nic *nic;
	struct sstmacx_auth_key *auth_key;
#ifdef HAVE_UDREG
	udreg_entry_t *entry;
#endif
};

/**
 * @brief sstmacx memory region key
 *
 * @var   pfn      prefix of the virtual address
 * @var   mdd      index for the mdd
 * @var   format   flag for determining whether new mdd format is used
 * @var   flags    set of bits for passing flags such as read-only
 * @var   padding  reserved bits, unused for now
 */
typedef struct sstmacx_mr_key {
	union {
		struct {
			uint64_t pfn: SSTMACX_MR_PFN_BITS;
			uint64_t mdd: SSTMACX_MR_MDD_BITS;
			uint64_t format : SSTMACX_MR_FMT_BITS;
			uint64_t flags : SSTMACX_MR_FLAG_BITS;
			uint64_t padding: SSTMACX_MR_PADDING_LENGTH;
		};
		uint64_t value;
	};
} sstmacx_mr_key_t;

/**
 *
 */
struct sstmacx_mr_ops {
	int (*init)(struct sstmacx_fid_domain *domain,
			struct sstmacx_auth_key *auth_key);
	int (*is_init)(struct sstmacx_fid_domain *domain,
			struct sstmacx_auth_key *auth_key);
	int (*reg_mr)(struct sstmacx_fid_domain *domain, uint64_t address,
			uint64_t length, struct _sstmacx_fi_reg_context *fi_reg_context,
			void **handle);
	int (*dereg_mr)(struct sstmacx_fid_domain *domain,
			struct sstmacx_fid_mem_desc *md);
	int (*destroy_cache)(struct sstmacx_fid_domain *domain,
			struct sstmacx_mr_cache_info *info);
	int (*flush_cache)(struct sstmacx_fid_domain *domain);
};


/**
 * @brief Converts a libfabric key to a sstmac memory handle, skipping memory
 *        handle CRC generation.
 *
 * @param[in]     key   libfabric memory region key
 * @param[in,out] mhdl  sstmac memory handle
 */
void _sstmacx_convert_key_to_mhdl_no_crc(
		sstmacx_mr_key_t    *key,
		sstmac_mem_handle_t *mhdl);

/**
 * @brief Converts a libfabric key to a sstmac memory handle
 *
 * @param[in]     key   libfabric memory region key
 * @param[in,out] mhdl  sstmac memory handle
 */
void _sstmacx_convert_key_to_mhdl(
		sstmacx_mr_key_t    *key,
		sstmac_mem_handle_t *mhdl);

#define _SSTMACX_CONVERT_MR_KEY(scalable, offset, convert_func, key, mhdl) \
	do { \
		if (scalable) { \
			sstmacx_mr_key_t _sstmacx_mr_key = { \
				.value = ((sstmacx_mr_key_t *) (key))->value + (offset), \
			}; \
			convert_func(&_sstmacx_mr_key, (mhdl)); \
		} else { \
			convert_func((sstmacx_mr_key_t *) (key), (mhdl)); \
		} \
	} while (0)

/**
 * @brief Converts a sstmac memory handle to a libfabric key
 *
 * @param[in]     mhdl  sstmac memory handle
 * @return              fi_mr_key to be used by remote EPs.
 */
uint64_t _sstmacx_convert_mhdl_to_key(sstmac_mem_handle_t *mhdl);

/* initializes mr cache for a given domain */
int _sstmacx_open_cache(struct sstmacx_fid_domain *domain, int type);

/* destroys mr cache for a given domain */
int _sstmacx_close_cache(struct sstmacx_fid_domain *domain,
	struct sstmacx_mr_cache_info *info);

/* flushes the memory registration cache for a given domain */
int _sstmacx_flush_registration_cache(struct sstmacx_fid_domain *domain);


/** 
 * used for internal registrations,
 *
 * @param fid  endpoint fid
 * @param buf            buffer to register
 * @param len            length of buffer to register
 * @param access         access permissions
 * @param offset         registration offset 
 * @param requested_key  key requested for new registration
 * @param flags          registration flags
 * @param mr_o           pointer to returned registration
 * @param context        context to associate with registration
 * @param auth_key       authorization key to associate with registration
 * @param reserved       1 if provider registration, 0 otherwise
 *
 * @note  Set reserved to 0 for a user registration
 * @note  Set reserved to 1 for a provider registration 
 */
int _sstmacx_mr_reg(struct fid *fid, const void *buf, size_t len,
			  uint64_t access, uint64_t offset,
			  uint64_t requested_key, uint64_t flags,
			  struct fid_mr **mr_o, void *context,
			  struct sstmacx_auth_key *auth_key,
			  int reserved);

extern sstmacx_mr_cache_attr_t _sstmacx_default_mr_cache_attr;

#endif /* SSTMACX_MR_H_ */

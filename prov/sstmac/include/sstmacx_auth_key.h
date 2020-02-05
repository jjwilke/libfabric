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

#ifndef PROV_SSTMAC_INCLUDE_SSTMACX_AUTH_KEY_H_
#define PROV_SSTMAC_INCLUDE_SSTMACX_AUTH_KEY_H_

#include <ofi_lock.h>

#include "fi_ext_sstmac.h"
#include "sstmacx_bitmap.h"

/*
 * SSTMACX Authorization keys are directly associated with a specific SSTMAC network
 * key. There are some limitations to SSTMAC network keys that should be noted.
 *
 * SSTMAC network keys are directly associated with memory registrations, and
 * can only support a single type of memory mode at a time. This means that
 * the memory mode must be tracked with the authorization key, and must exist
 * as globally known information. Since references to objects may still exist
 * after the fabric is closed, this information must persist unless the
 * application has promised not to open any more SSTMAC fabric instances.
 * See fi_sstmac man page for guidance on SSTMAC_DEALLOC_AKI_ON_FABRIC_CLOSE.
 */

/**
 * SSTMACX authorization key construct
 *
 * @var lock        lock for data structure
 * @var attr        authorization key attributes
 * @var enabled     Is this authorization key live? If so, refuse changes to limits
 * @var using_vmdh  Is this authorization key associated with a domain using
 *                  VMDH?
 * @var prov        bitmap for detecting provider key usage
 * @var user        bitmap for detecting user key usage
 */
struct sstmacx_auth_key {
	fastlock_t lock;
	struct sstmacx_auth_key_attr attr;
	int enabled;
	uint8_t ptag;
	uint32_t cookie;
	int using_vmdh;
	uint32_t key_partition_size;
	uint32_t key_offset;
	sstmacx_bitmap_t *prov;
	sstmacx_bitmap_t *user;
};

/**
 * Allocates an authorization key structure, if possible
 *
 * @return  non-NULL pointer to initialized memory on success
 *          NULL on failure
 */
struct sstmacx_auth_key *_sstmacx_auth_key_alloc();

/**
 * Frees an authorization key structure
 *
 * @param key    A SSTMAC authorization key structure to free
 * @return       0 on success
 *               -FI_EINVAL, if invalid parameter passed as key
 */
int _sstmacx_auth_key_free(struct sstmacx_auth_key *key);

/**
 * Lookup an authorization key in global data storage
 *
 * @param auth_key     authorization key
 * @param auth_key_size  length of authorization key in bytes
 * @return             non-NULL pointer on success
 *                     NULL pointer if not found
 */
struct sstmacx_auth_key *_sstmacx_auth_key_lookup(
		uint8_t *auth_key,
		size_t auth_key_size);

/**
 * Enables and prevents further limit modifications for an authorization key
 *
 * @param key  SSTMAC authorization key
 * @return     FI_SUCCESS on success
 *             -FI_EINVAL, if bad parameters were passed
 *             -FI_EBUSY, if already enabled
 */

int _sstmacx_auth_key_enable(struct sstmacx_auth_key *key);

/**
 * Retrieves the next available provider-reserved key for a given
 * authorization key
 *
 * @param info  A SSTMAC authorization key
 * @return      FI_SUCCESS on success
 *              -FI_EINVAL, if bad parameters were passed
 *              -FI_EAGAIN, if no available key could be foundi
 */
int _sstmacx_get_next_reserved_key(struct sstmacx_auth_key *info);

/**
 * Releases a reserved key back to the bitset to be reused
 *
 * @param info          A SSTMAC authorization key
 * @param reserved_key  index of the reserved key
 * @return              FI_SUCCESS on success
 *                      -FI_EINVAL, if invalid parameters were passed
 *                      -FI_EBUSY, if reserved key was already released
 */
int _sstmacx_release_reserved_key(struct sstmacx_auth_key *info, int reserved_key);

/**
 * Creates an authorization key from default configuration
 *
 * @param auth_key     authorization key
 * @param auth_key_size  length of authorization key in bytes
 * @return             non-NULL pointer on success
 *                     NULL pointer on failure
 */
struct sstmacx_auth_key *_sstmacx_auth_key_create(
		uint8_t *auth_key,
		size_t auth_key_size);

/**
 * Inserts an authorization key into global data storage
 *
 * @param auth_key     authorization key
 * @param auth_key_size  length of authorization key in bytes
 * @param to_insert    SSTMAC authorization key structure to insert
 * @return             FI_SUCCESS on success
 *                     -FI_EINVAL, if to_insert is NULL or global data
 *                                 storage is destroyed
 *                     -FI_ENOSPC, if auth key exists in global data
 *                                 storage
 */
int _sstmacx_auth_key_insert(
		uint8_t *auth_key,
		size_t auth_key_size,
		struct sstmacx_auth_key *to_insert);

#define SSTMACX_GET_AUTH_KEY(auth_key, auth_key_size, requested_mode) \
	({ \
		struct sstmacx_auth_key *_tmp; \
		_tmp  = _sstmacx_auth_key_lookup((auth_key), (auth_key_size)); \
		int _tmp_ret; \
		if (!_tmp) { \
			SSTMACX_INFO(FI_LOG_FABRIC, \
				"failed to find authorization " \
				"key, creating new authorization key\n"); \
			_tmp = _sstmacx_auth_key_create( \
				(auth_key), (auth_key_size)); \
			if (!_tmp) { \
				SSTMACX_DEBUG(FI_LOG_FABRIC, \
					"failed to create new " \
					"authorization key, "\
					"another thread beat us to the insert " \
					"- searching again\n"); \
				_tmp = _sstmacx_auth_key_lookup((auth_key), \
					(auth_key_size)); \
				assert(_tmp); \
			} \
			_tmp->using_vmdh = (requested_mode); \
			_tmp_ret = _sstmacx_auth_key_enable(_tmp); \
			if (_tmp_ret) { \
				SSTMACX_WARN(FI_LOG_FABRIC, \
					"failed to enable new " \
					"authorization key\n"); \
			} \
		} \
		_tmp; \
	})

/* provider subsystem initialization and teardown functions */
int _sstmacx_auth_key_subsys_init(void);
int _sstmacx_auth_key_subsys_fini(void);

#endif /* PROV_SSTMAC_INCLUDE_SSTMACX_AUTH_KEY_H_ */

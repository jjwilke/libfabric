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

#include "rdma/fabric.h"
#include "rdma/fi_errno.h"
#include "fi_ext_sstmac.h"

#include "sstmacx_auth_key.h"
#include "sstmacx_hashtable.h"
#include "sstmacx_shmem.h"
#include "sstmacx_bitmap.h"
#include "sstmacx.h"

#define SSTMACX_AUTH_KEY_HASHSEED 0xdeadbeef

#define GAI_VERSION(major, minor) (((major) << 16) + (minor))
typedef enum sstmacx_global_auth_info_version {
	SSTMACX_GAI_VERSION_1 = GAI_VERSION(1, 0), /* initial version */
} sstmacx_global_auth_info_version_t;

#define MAX_VMDH_TAGS 4
#define MAX_VMDH_REGS 4096
#define BITMAP_ARR_SIZE(nbits) \
	(SSTMACX_BITMAP_BLOCKS(nbits) * sizeof(sstmacx_bitmap_block_t))

#define SSTMACX_DEFAULT_AK_DIR "/tmp"
#define SSTMACX_DEFAULT_AK_FILENAME "sstmacx_vmdh_info"
#define SSTMACX_DEFAULT_AK_PATH \
	SSTMACX_DEFAULT_AK_DIR "/" SSTMACX_DEFAULT_AK_FILENAME
#define SSTMACX_AK_PATH_LEN 256

static char *sstmacx_default_ak_path = SSTMACX_DEFAULT_AK_PATH;

uint8_t* sstmacx_default_auth_key = NULL;

struct sstmacx_global_ptag_info {
	sstmacx_bitmap_t prov;
	sstmacx_bitmap_t user;
	uint8_t arr[BITMAP_ARR_SIZE(MAX_VMDH_REGS)];
};

struct sstmacx_global_vmdh_info {
	uint32_t version;
	uint32_t size;
	uint32_t table_size;
	fastlock_t lock;
	int ptag_index[MAX_VMDH_TAGS];
	struct sstmacx_global_ptag_info info[MAX_VMDH_TAGS];
};

/* Global data storage for authorization key information */
/* sstmacx_vmdh_info is the shared memory synchronization area for ptag info */
static struct sstmacx_shared_memory __sstmacx_shmem_region;
static struct sstmacx_global_vmdh_info *__sstmacx_vmdh_info;
sstmacx_hashtable_t __sstmacx_auth_key_ht;

static int __sstmacx_global_vmdh_info_init(const char *path,
	uint32_t size, void *buffer)
{
	struct sstmacx_global_vmdh_info *info =
		(struct sstmacx_global_vmdh_info *) buffer;
	int i;

	memset(info, 0, sizeof(struct sstmacx_global_vmdh_info));

	info->version = SSTMACX_GAI_VERSION_1;
	info->size = size;
	info->table_size = _sstmacx_bitmap_get_buffer_size(MAX_VMDH_REGS);
	for (i = 0; i < MAX_VMDH_TAGS; i++)
		info->ptag_index[i] = -1;
	fastlock_init(&info->lock);

	return 0;
}

static extern "C" int _sstmacx_open_vmdh_info_file(const char *path)
{
	int ret;

	if (!__sstmacx_vmdh_info) {
		ret = _sstmacx_shmem_create(path,
			sizeof(struct sstmacx_global_vmdh_info),
			__sstmacx_global_vmdh_info_init,
			&__sstmacx_shmem_region);
		if (ret)
			return ret;

		__sstmacx_vmdh_info = (struct sstmacx_global_vmdh_info *)
			__sstmacx_shmem_region.addr;
	}

	if (__sstmacx_vmdh_info->version != SSTMACX_GAI_VERSION_1)
		SSTMACX_FATAL(FI_LOG_FABRIC,
			"failed to find compatible version of "
			"vmdh information file, expected=%x actual=%x\n",
			SSTMACX_GAI_VERSION_1, __sstmacx_vmdh_info->version);

	return 0;
}
extern "C" int _sstmacx_get_next_reserved_key(struct sstmacx_auth_key *info)
{
	int reserved_key;
	int offset = info->attr.user_key_limit;
	int retry_limit = 10; /* randomly picked */
	int ret;

	if (!info) {
		SSTMACX_WARN(FI_LOG_MR, "bad authorization key, key=%p\n",
			info);
		return -FI_EINVAL;
	}

	do {
		reserved_key = _sstmacx_find_first_zero_bit(info->prov);
		if (reserved_key >= 0) {
			ret = _sstmacx_test_and_set_bit(info->prov, reserved_key);
			if (ret)
				reserved_key = -FI_EAGAIN;
		}
		retry_limit--;
	} while (reserved_key < 0 && retry_limit > 0);

	ret = (reserved_key < 0) ? reserved_key : (offset + reserved_key);

	SSTMACX_INFO(FI_LOG_DOMAIN, "returning key=%d offset=%d\n", ret, offset);

	return ret;
}

extern "C" int _sstmacx_release_reserved_key(struct sstmacx_auth_key *info, int reserved_key)
{
	int offset = info->attr.user_key_limit;
	int ret;

	if (!info || reserved_key < 0) {
		SSTMACX_WARN(FI_LOG_MR, "bad authorization key or reserved key,"
			" auth_key=%p requested_key=%d\n",
			info, reserved_key);
		return -FI_EINVAL;
	}

	ret = _sstmacx_test_and_clear_bit(info->prov, reserved_key - offset);
	assert(ret == 1);

	return (ret == 1) ? FI_SUCCESS : -FI_EBUSY;
}

static inline int __sstmacx_auth_key_enable_vmdh(struct sstmacx_auth_key *info)
{
	int i, ret;
	void *buffer;

	fastlock_acquire(&__sstmacx_vmdh_info->lock);
	/* Find ptag in node-local info structure */
	for (i = 0; i < MAX_VMDH_TAGS; i++)
		if (__sstmacx_vmdh_info->ptag_index[i] == info->ptag)
			break;

	if (i == MAX_VMDH_TAGS) { /* didn't find it */
		/* find first empty region */
		for (i = 0; i < MAX_VMDH_TAGS; i++)
			if (__sstmacx_vmdh_info->ptag_index[i] == -1)
				break;

		/* if no space ... */
		if (i == MAX_VMDH_TAGS) {
			fastlock_release(&__sstmacx_vmdh_info->lock);
			SSTMACX_WARN(FI_LOG_FABRIC,
				"application is attempting to use too many keys "
				"with scalable memory registration, "
				"ret=-FI_ENOSPC\n");
			return -FI_ENOSPC;
		}

		/* set index entry to ptag ID */
		__sstmacx_vmdh_info->ptag_index[i] = info->ptag;

		/* setup provider key space */
		buffer = (void *) __sstmacx_vmdh_info->info[i].arr;
		ret = _sstmacx_alloc_bitmap(&__sstmacx_vmdh_info->info[i].prov,
			info->attr.prov_key_limit, buffer);
		if (ret) {
			fastlock_release(&__sstmacx_vmdh_info->lock);
			SSTMACX_WARN(FI_LOG_FABRIC,
				"failed to allocate bitmap on mmap backed page, ret=%d\n",
				ret);
			return ret;
		}

		/* advance buffer and setup user key space */
		buffer = (void *) ((uint64_t) (buffer) +
			 _sstmacx_bitmap_get_buffer_size(info->attr.prov_key_limit));

		ret = _sstmacx_alloc_bitmap(&__sstmacx_vmdh_info->info[i].user,
			info->attr.user_key_limit, buffer);
		if (ret) {
			fastlock_release(&__sstmacx_vmdh_info->lock);
			SSTMACX_WARN(FI_LOG_FABRIC,
				"failed to allocate bitmap on mmap backed page, ret=%d\n",
				ret);
			return ret;
		}

		SSTMACX_INFO(FI_LOG_FABRIC,
			"set resource limits: pkey=%08x ptag=%d "
			"reserved=%d registration_limit=%d "
			"reserved_keys=%d-%d\n",
			info->cookie,
			info->ptag,
			info->attr.prov_key_limit,
			info->attr.user_key_limit,
			info->attr.user_key_limit,
			(info->attr.prov_key_limit +
			info->attr.user_key_limit - 1));
	}
	info->prov = &__sstmacx_vmdh_info->info[i].prov;
	info->user = &__sstmacx_vmdh_info->info[i].user;
	fastlock_release(&__sstmacx_vmdh_info->lock);

	return FI_SUCCESS;
}

extern "C" int _sstmacx_auth_key_enable(struct sstmacx_auth_key *info)
{
	int ret = -FI_EBUSY;
	uint32_t pes_on_node;
	int logical_rank;

	if (!info) {
		SSTMACX_WARN(FI_LOG_MR, "bad authorization key, key=%p\n",
			info);
		return -FI_EINVAL;
	}

	fastlock_acquire(&info->lock);
	if (!info->enabled) {
		info->enabled = 1;

		if (info->using_vmdh) {
			if (!__sstmacx_vmdh_info) {
				char *dir = getenv("TMPDIR");
				char *filename = getenv("SSTMACX_AK_FILENAME");
				char path[SSTMACX_AK_PATH_LEN];
				int sz, i;

				if (dir || filename) {
					SSTMACX_DEBUG(FI_LOG_FABRIC,
						"using non-default directory or file name, "
						"errors may occur\n");
					if (!dir)
						sz = snprintf(path, SSTMACX_AK_PATH_LEN,
							"%s/", SSTMACX_DEFAULT_AK_DIR);
					else
						sz = snprintf(path, SSTMACX_AK_PATH_LEN,
							"%s/", dir);

					if (sz < 0)
						return -FI_EINVAL;

					i = sz;
					if (!filename)
						sz = snprintf(&path[i], SSTMACX_AK_PATH_LEN - i,
							"%s", SSTMACX_DEFAULT_AK_FILENAME);
					else
						sz = snprintf(&path[i], SSTMACX_AK_PATH_LEN - i,
							"%s", filename);

					if (sz < 0)
						return -FI_EINVAL;
					sz += i;
				} else {
					sz = snprintf(path, SSTMACX_AK_PATH_LEN, "%s",
						sstmacx_default_ak_path);
				}

				path[(sz == SSTMACX_AK_PATH_LEN) ?
					SSTMACX_AK_PATH_LEN : sz + 1] = '\0';
				if (sz == SSTMACX_AK_PATH_LEN) {
					SSTMACX_WARN(FI_LOG_FABRIC,
						"file path maximum length exceeded, "
						"truncating name to 256 characters path=%s\n",
						path);
				}

				SSTMACX_INFO(FI_LOG_FABRIC,
					"opening auth key file at %s\n", path);

				ret = _sstmacx_open_vmdh_info_file(path);
				if (ret) {
					info->enabled = 0;
					fastlock_release(&info->lock);
					return ret;
				}
			}

			ret = __sstmacx_auth_key_enable_vmdh(info);
			if (ret) {
				info->enabled = 0;
				fastlock_release(&info->lock);
				return ret;
			}

			ret = _sstmacx_pes_on_node(&pes_on_node);
			if (ret)
				SSTMACX_FATAL(FI_LOG_DOMAIN,
					"failed to get count of pes on node, rc=%d\n", ret);

			ret = _sstmacx_pe_node_rank(&logical_rank);
			if (ret)
				SSTMACX_FATAL(FI_LOG_DOMAIN,
					"failed to get logical node rank, rc=%d\n", ret);

			info->key_partition_size = info->attr.user_key_limit / pes_on_node;
			info->key_offset = logical_rank * info->key_partition_size;
		}
		SSTMACX_INFO(FI_LOG_DOMAIN,
			"pkey=%08x ptag=%d key_partition_size=%d key_offset=%d enabled\n",
			info->cookie, info->ptag, info->key_partition_size, info->key_offset);
		ret = FI_SUCCESS;
	}
	fastlock_release(&info->lock);

	if (ret == -FI_EBUSY) {
		SSTMACX_DEBUG(FI_LOG_MR, "authorization key already enabled, "
			"auth_key=%p\n", info);
	}

	return ret;
}

struct sstmacx_auth_key *_sstmacx_auth_key_alloc()
{
	struct sstmacx_auth_key *auth_key = NULL;

	auth_key = calloc(1, sizeof(*auth_key));
	if (auth_key) {
		fastlock_init(&auth_key->lock);
	} else {
		SSTMACX_WARN(FI_LOG_MR, "failed to allocate memory for "
			"authorization key\n");
	}

	return auth_key;
}

extern "C" int _sstmacx_auth_key_insert(
		uint8_t *auth_key,
		size_t auth_key_size,
		struct sstmacx_auth_key *to_insert)
{
	int ret;
	sstmacx_ht_key_t key;
	struct fi_sstmac_auth_key *sstmac_auth_key =
		(struct fi_sstmac_auth_key *) auth_key;

	if (!to_insert) {
		SSTMACX_WARN(FI_LOG_MR, "bad parameters, to_insert=%p\n",
			to_insert);
		return -FI_EINVAL;
	}

	if (!auth_key) {
		SSTMACX_INFO(FI_LOG_FABRIC, "auth key is null\n");
		return -FI_EINVAL;
	}

	switch (sstmac_auth_key->type) {
	case SSTMACX_AKT_RAW:
		key = (sstmacx_ht_key_t) sstmac_auth_key->raw.protection_key;
		break;
	default:
		SSTMACX_INFO(FI_LOG_FABRIC, "unrecosstmaczed auth key "
			"type, type=%d\n",
			sstmac_auth_key->type);
		return -FI_EINVAL;
	}

	ret = _sstmacx_ht_insert(&__sstmacx_auth_key_ht, key, to_insert);
	if (ret) {
		SSTMACX_WARN(FI_LOG_MR, "failed to insert entry, ret=%d\n",
			ret);
	}

	return ret;
}

extern "C" int _sstmacx_auth_key_free(struct sstmacx_auth_key *key)
{
	if (!key) {
		SSTMACX_WARN(FI_LOG_MR, "bad parameters, key=%p\n", key);
		return -FI_EINVAL;
	}

	fastlock_destroy(&key->lock);

	key->enabled = 0;

	free(key);

	return FI_SUCCESS;
}

struct sstmacx_auth_key *
_sstmacx_auth_key_lookup(uint8_t *auth_key, size_t auth_key_size)
{
	sstmacx_ht_key_t key;
	struct sstmacx_auth_key *ptr = NULL;
	struct fi_sstmac_auth_key *sstmac_auth_key = NULL;

	if (auth_key == NULL || auth_key_size == 0) {
		auth_key = sstmacx_default_auth_key;
	}

	sstmac_auth_key = (struct fi_sstmac_auth_key *) auth_key;
	switch (sstmac_auth_key->type) {
	case SSTMACX_AKT_RAW:
		key = (sstmacx_ht_key_t) sstmac_auth_key->raw.protection_key;
		break;
	default:
		SSTMACX_INFO(FI_LOG_FABRIC, "unrecosstmaczed auth key type, "
			"type=%d\n", sstmac_auth_key->type);
		return NULL;
	}

	ptr = (struct sstmacx_auth_key *) _sstmacx_ht_lookup(
		&__sstmacx_auth_key_ht, key);

	return ptr;
}

extern "C" int _sstmacx_auth_key_subsys_init(void)
{
	int ret = FI_SUCCESS;

	sstmacx_hashtable_attr_t attr = {
			.ht_initial_size     = 8,
			.ht_maximum_size     = 256,
			.ht_increase_step    = 2,
			.ht_increase_type    = SSTMACX_HT_INCREASE_MULT,
			.ht_collision_thresh = 400,
			.ht_hash_seed        = 0xcafed00d,
			.ht_internal_locking = 1,
			.destructor          = NULL
	};

	ret = _sstmacx_ht_init(&__sstmacx_auth_key_ht, &attr);
	assert(ret == FI_SUCCESS);

	struct fi_sstmac_auth_key *sstmac_auth_key = calloc(1, sizeof(*sstmac_auth_key));
	sstmac_auth_key->type = SSTMACX_AKT_RAW;
	sstmac_auth_key->raw.protection_key = 0;
	sstmacx_default_auth_key = (uint8_t *) sstmac_auth_key;

	return ret;
}

extern "C" int _sstmacx_auth_key_subsys_fini(void)
{
	free(sstmacx_default_auth_key);

	return FI_SUCCESS;
}

struct sstmacx_auth_key *_sstmacx_auth_key_create(
		uint8_t *auth_key,
		size_t auth_key_size)
{
	struct sstmacx_auth_key *to_insert;
	struct fi_sstmac_auth_key *sstmac_auth_key;
	int ret;
	sstmac_return_t grc;
	uint8_t ptag;
	uint32_t cookie;

	if (auth_key == NULL || auth_key_size == 0) {
		auth_key = sstmacx_default_auth_key;
	}

	sstmac_auth_key = (struct fi_sstmac_auth_key *) auth_key;
	if (auth_key == sstmacx_default_auth_key) {
		sstmacxu_get_rdma_credentials(NULL, &ptag, &cookie);
		sstmac_auth_key->raw.protection_key = cookie;
	} else {
		switch (sstmac_auth_key->type) {
		case SSTMACX_AKT_RAW:
			cookie = sstmac_auth_key->raw.protection_key;
			break;
		default:
			SSTMACX_WARN(FI_LOG_FABRIC,
				"unrecosstmaczed auth key type, type=%d\n",
				sstmac_auth_key->type);
			return NULL;
		}

		grc = SSTMAC_GetPtag(0, cookie, &ptag);
		if (grc) {
			SSTMACX_WARN(FI_LOG_FABRIC,
				"could not retrieve ptag, "
				"cookie=%d ret=%d\n", cookie, grc);
			return NULL;
		}
	}

	to_insert = _sstmacx_auth_key_alloc();
	if (!to_insert) {
		SSTMACX_WARN(FI_LOG_MR, "failed to allocate memory for "
			"auth key\n");
		return NULL;
	}

	to_insert->attr.prov_key_limit = sstmacx_default_prov_registration_limit;
	to_insert->attr.user_key_limit = sstmacx_default_user_registration_limit;
	to_insert->ptag = ptag;
	to_insert->cookie = cookie;

	ret = _sstmacx_auth_key_insert(auth_key, auth_key_size, to_insert);
	if (ret) {
		SSTMACX_INFO(FI_LOG_MR, "failed to insert authorization key, "
			"key=%p len=%d to_insert=%p ret=%d\n",
			auth_key, auth_key_size, to_insert, ret);
		_sstmacx_auth_key_free(to_insert);
		to_insert = NULL;
	}

	return to_insert;
}

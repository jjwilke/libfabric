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
 * Copyright (c) 2016      Los Alamos National Security, LLC.
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

#ifndef SSTMACX_XPMEM_H_
#define SSTMACX_XPMEM_H_

#include "sstmacx.h"
#if HAVE_XPMEM
#include <xpmem.h>
#else
typedef int64_t xpmem_apid_t;
typedef int64_t xpmem_segid_t;
#endif

struct sstmacx_xpmem_handle {
	struct sstmacx_reference ref_cnt;
	struct sstmacx_hashtable *apid_ht;
	fastlock_t lock;
};

struct sstmacx_xpmem_access_handle {
	struct sstmacx_xpmem_handle *xp_hndl;
	struct sstmacx_xpmem_ht_entry *entry;
	void *attach_addr;
	void *remote_base_addr;
	size_t access_len;
};

extern bool sstmacx_xpmem_disabled;

/*******************************************************************************
 * API Prototypes
 ******************************************************************************/

/**
 * @brief create an xpmem handle to use for subsequent
 *        xpmem operations
 *
 * @param [in] dom      pointer to a previously allocated
 *                      sstmacx_fid_domain struct
 * @param [out] handle  pointer to a memory location where
 *                      a pointer to an xpmem_handle will be
 *                      returned
 *
 * @return FI_SUCCESS   xpmem handle successfully allocated
 * @return -FI_EINVAL   Upon receiving an invalid parameter
 */
int _sstmacx_xpmem_handle_create(struct sstmacx_fid_domain *dom,
			      struct sstmacx_xpmem_handle **handle);

/**
 * @brief destroy an xpmem handle
 *
 * @param [in] handle   pointer to a previously allocated
 *                      xpmem_handle
 * @return FI_SUCCESS   xpmem handle successfully destroyed
 * @return -FI_EINVAL   Upon receiving an invalid parameter
 */
int _sstmacx_xpmem_handle_destroy(struct sstmacx_xpmem_handle *hndl);

/**
 * @brief get an access handle to a address range a peer's
 *        address space
 *
 * @param[in] xp_handle         pointer to previously created
 *                              xpmem handle
 * @param[in] peer_apid         xpmem apid for peer
 * @param[in] remote_vaddr      virtual address in process associated
 *                              with the target EP
 * @param[in] len               length in bytes of the region to
 *                              to be accessed in the target process
 * @param[out] access_hndl      access handle to be used to copy data
 *                              from the peer process in to the local
 *                              address space
 *
 * @return FI_SUCCESS   Upon xpmem successfully initialized
 * @return -FI_EINVAL   Upon receiving an invalid parameter
 * @return -FI_ENOSYS   Target EP can't be attached to local process
 *                      address space
 */
int _sstmacx_xpmem_access_hndl_get(struct sstmacx_xpmem_handle *xp_hndl,
			     xpmem_apid_t peer_apid,
			     uint64_t remote_vaddr,
			     size_t len,
			     struct sstmacx_xpmem_access_handle **access_hndl);


/**
 * @brief release an access handle
 *
 * @param[in] access_handle     pointer to previously created
 *                              access handle
 *
 * @return FI_SUCCESS   Upon xpmem successfully initialized
 * @return -FI_EINVAL   Upon receiving an invalid parameter
 */
int _sstmacx_xpmem_access_hndl_put(struct sstmacx_xpmem_access_handle *access_hndl);

/**
 * @brief memcpy from previously accessed memory in peer's
 *        virtual address space
 *
 * @param[in] access_hndl       pointer to previously created
 *                              xpmem access handle
 * @param[in] dst_addr          starting virtual address in the calling
 *                              process address space where data
 *                              will be copied
 * @param[in] remote_start_addr   starting virtual address in the target
 *                              address space from which data will be copied
 * @param[in] len		copy length in bytes
 *
 * @return FI_SUCCESS	Upon successful copy
 * @return -FI_EINVAL	Invalid argument
 */
int _sstmacx_xpmem_copy(struct sstmacx_xpmem_access_handle *access_hndl,
		     void *dst_addr,
		     void *remote_start_addr,
		     size_t len);

/**
 * @brief get the xpmem segid associated with an xpmem_handle
 *
 * @param[in] xp_handle         pointer to previously created
 *                              will be copied
 * @param[out] seg_id           pointer to memory location where
 *                              the segid value will be returned
 *
 * @return FI_SUCCESS	Upon success
 * @return -FI_EINVAL	Invalid argument
 */
int _sstmacx_xpmem_get_my_segid(struct sstmacx_xpmem_handle *xp_hndl,
				xpmem_segid_t *seg_id);

/**
 * @brief get the xpmem apid associated with an xpmem_handle
 *        and input segid
 *
 * @param[in] xp_handle         pointer to previously created
 *                              will be copied
 * @param[in] seg_id            seg_id obtained from process
 *                              whose memory is to be accessed
 *                              via xpmem.
 * @param[out] peer_apid        pointer to memory location where
 *                              the apid value to use for accessing
 *                              the address space of the peer
 *                              process.
 *
 * @return FI_SUCCESS	Upon success
 * @return -FI_EINVAL	Invalid argument
 */
int _sstmacx_xpmem_get_apid(struct sstmacx_xpmem_handle *xp_hndl,
				xpmem_segid_t segid,
				xpmem_apid_t *peer_apid);

/**
 * @brief determine if a process at a given sstmacx_address can
 *        be accessed using xpmem
 *
 * @param[in] ep                pointer to a previously allocated
 *                              sstmacx_fid_ep structure
 * @param[in] addr              address used by an endpoint of the
 *                              peer process
 * @param[out] accessible       set to true if endpoint with
 *                              sstmacx_address addr can be accessed
 *                              using xpmem, otherwise false
 *
 * @return FI_SUCCESS	Upon success
 * @return -FI_EINVAL	Invalid argument
 */
int _sstmacx_xpmem_accessible(struct sstmacx_fid_ep *ep,
			   struct sstmacx_address addr,
			   bool *accessible);




#endif /* SSTMACX_XPMEM_H_ */

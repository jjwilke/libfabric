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
 * Copyright (c) 2015-2016 Cray Inc. All rights reserved.
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

#ifndef _SSTMACX_AV_H_
#define _SSTMACX_AV_H_

#include "sstmacx.h"

/*
 * this structure should ideally be as compact
 * as possible, since its looked up in the critical
 * path for FI_EP_RDM EPs that use FI_AV_MAP.  It
 * needs to hold sufficient content that the sstmacx_ep_name
 * can be regnerated in full for fi_av_lookup.
 */

/**
 * Av addr entry struct
 *
 * @var sstmacx_addr            sstmacx address for this entry
 * @var name_type            the endpoint type associated with this
 *                           address (SSTMACX_EPN_TYPE_UNBOUND/BOUND)
 * @var cm_nic_cdm_id        for SSTMACX_EPN_TYPE_UNBOUND endpoint types
 *                           the cdm id of the cm_nic with which the endpoint
 *                           is associated
 * @var cookie               RDMA cookie credential for the endpoint
 *                           this entry corresponds to
 * @var rx_ctx_cnt           number of contexts associated with this AV
 */
struct sstmacx_av_addr_entry {
	struct sstmacx_address sstmacx_addr;
	struct {
		uint32_t name_type : 8;
		uint32_t cm_nic_cdm_id : 24;
		uint32_t cookie;
	};
	struct {
		uint32_t rx_ctx_cnt : 8;
		uint32_t key_offset: 12;
		uint32_t unused1 : 12;
	};
};

/*
 * Prototypes for SSTMAC AV helper functions for managing the AV system.
 */

/**
 * @brief  Return pointer to an AV table internal sstmacx_av_addr_entry for
 *         a given fi_addr address
 *
 * @param[in]     sstmacx_av   pointer to a previously allocated sstmacx_fid_av
 * @param[in]     fi_addr   address to be translated
 * @param[out]    addr      pointer to address entry in AV table
 * @return  FI_SUCCESS on success, -FI_EINVAL on error
 */
int _sstmacx_av_lookup(struct sstmacx_fid_av *sstmacx_av, fi_addr_t fi_addr,
		    struct sstmacx_av_addr_entry *addr);

/**
 * @brief Return the FI address mapped to a given SSTMACX address.
 *
 * @param[in]   sstmacx_av   The AV to use for lookup.
 * @param[in]   sstmacx_addr The SSTMACX address to translate.
 * @param[out]  fi_addr   The FI address mapped to sstmacx_addr.
 * @return      FI_SUCCESS on success, -FI_EINVAL or -FI_ENOENT on error.
 */
int _sstmacx_av_reverse_lookup(struct sstmacx_fid_av *sstmacx_av,
			    struct sstmacx_address sstmacx_addr,
			    fi_addr_t *fi_addr);

/*******************************************************************************
 * If the caller already knows the av type they can call the lookups directly
 * using the following functions.
 ******************************************************************************/

/**
 * @brief (FI_AV_TABLE) Return fi_addr using its corresponding sstmacx address.
 *
 * @param[in] int_av		The AV to use for the lookup.
 * @param[in] sstmacx_addr		The sstmacx address
 * @param[in/out] fi_addr	The pointer to the corresponding fi_addr.
 *
 * @return FI_SUCCESS on successfully looking up the entry in the entry table.
 * @return -FI_EINVAL upon passing an invalid parameter.
 */
int _sstmacx_table_reverse_lookup(struct sstmacx_fid_av *int_av,
			       struct sstmacx_address sstmacx_addr,
			       fi_addr_t *fi_addr);

/**
 * @brief (FI_AV_MAP) Return fi_addr using its corresponding sstmacx address.
 *
 * @param[in] int_av		The AV to use for the lookup.
 * @param[in] sstmacx_addr		The sstmacx address
 * @param[in/out] fi_addr	The pointer to the corresponding fi_addr.
 *
 * @return FI_SUCCESS on successfully looking up the entry in the entry table.
 * @return -FI_EINVAL upon passing an invalid parameter.
 */
int _sstmacx_map_reverse_lookup(struct sstmacx_fid_av *int_av,
			     struct sstmacx_address sstmacx_addr,
			     fi_addr_t *fi_addr);

/**
 * @brief Return the string representation of the FI address.
 *
 * @param[in]      av      The AV to use.
 * @param[in]      addr    The SSTMACX address to translate.
 * @param[in/out]  buf     The buffer that contains the address string.
 * @param[in/out]  len     The length of the address string.
 * @return         char    The buffer that contains the address string.
 */
const char *sstmacx_av_straddr(struct fid_av *av,
			    const void *addr,
			    char *buf,
			    size_t *len);

#endif /* _SSTMACX_AV_H_ */

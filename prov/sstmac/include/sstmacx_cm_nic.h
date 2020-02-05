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

#ifndef _SSTMACX_CM_NIC_H_
#define _SSTMACX_CM_NIC_H_

#include "sstmacx.h"

#define SSTMACX_CM_NIC_MAX_MSG_SIZE (SSTMAC_DATAGRAM_MAXSIZE - sizeof(uint8_t))

extern struct dlist_entry sstmacx_cm_nic_list;
extern pthread_mutex_t sstmacx_cm_nic_list_lock;

typedef int sstmacx_cm_nic_rcv_cb_func(struct sstmacx_cm_nic *cm_nic,
				    char *rbuf,
				    struct sstmacx_address addr);

/**
 * @brief SSTMAC provider connection management (cm) nic structure
 *
 * @var cm_nic_list    global CM NIC list element
 * @var nic            pointer to sstmacx_nic associated with this cm nic
 * @var dgram_hndl     handle to dgram allocator associated with this nic
 * @var fabric         SSTMAC provider fabric associated with this nic
 * @var addr_to_ep_ht  Hash table for looking up ep bound to this
 *                     cm nic, key is ep's sstmacx_address
 * @var wq_lock        spin lock for cm nic's work queue
 * @var cm_nic_wq      workqueue associated with this nic
 * @var ref_cnt        used for internal reference counting
 * @var ctl_progress   control progress type for this cm nic
 * @var my_name        sstmacx ep name for this cm nic
 * @var rcv_cb_fn      pointer to callback function used to process
 *                     incoming messages received by this cm nic
 * @var ptag           ptag of this nic.
 * @var poll_cnt       non-atomic counter to reduce datagram polling cnt
 *                     when using FI_PROGRESS_MANUAL for control progress.
 * @var device_id      local Aries device id associated with this nic.
 */
struct sstmacx_cm_nic {
	struct dlist_entry cm_nic_list;
	struct sstmacx_nic *nic;
	struct sstmacx_dgram_hndl *dgram_hndl;
	struct sstmacx_fid_domain *domain;
	struct sstmacx_hashtable *addr_to_ep_ht;
	fastlock_t wq_lock;
	struct dlist_entry cm_nic_wq;
	struct sstmacx_reference ref_cnt;
	enum fi_progress ctrl_progress;
	struct sstmacx_ep_name my_name;
	sstmacx_cm_nic_rcv_cb_func *rcv_cb_fn;
	uint8_t ptag;
	uint32_t poll_cnt;
	uint32_t device_id;
};


/**
 * @brief send a message to a cm_nic
 *
 * @param[in]  cm_nic   pointer to a previously allocated sstmacx_cm_nic struct
 * @param[in]  sbuf     pointer to the beginning of a message to send
 * @param[in]  len      length of message to send.  May not exceed SSTMAC_DATAGRAM_MAXSIZE
 *                      bytes.
 * @param[in]  taddr    address of target cm_nic
 * @return              FI_SUCCESS on success, -FI_EINVAL on invalid argument,
 *                      -FI_AGAIN unable to send message , -FI_ENOSPC
 *                      message too large
 * Upon return, sbuf may be reused.
 */
int _sstmacx_cm_nic_send(struct sstmacx_cm_nic *cm_nic,
		      char *sbuf, size_t len,
		      struct sstmacx_address target_addr);

/**
 * @brief register a callback function to invoke upon receiving message
 *
 * @param[in] cm_nic   pointer to previously allocated sstmacx_cm_nic struct
 * @param[in] recv_fn  pointer to receive function to invoke upon
 *                     receipt of a message
 * @param[out] o_fn    pointer to previously registered callback function
 *                     message.  Must be SSTMAC_DATAGRAM_MAXSIZE bytes in size.
 * @return             FI_SUCCESS on success, -FI_EINVAL on invalid argument.
 *
 * This call is non-blocking.  If FI_SUCCESS is returned, a message
 * sent from peer cm_nic at src_addr will be present in rbuf.
 */
int _sstmacx_cm_nic_reg_recv_fn(struct sstmacx_cm_nic *cm_nic,
			     sstmacx_cm_nic_rcv_cb_func *recv_fn,
			     sstmacx_cm_nic_rcv_cb_func **o_fn);

/**
 * @brief Frees a previously allocated cm nic structure
 *
 * @param[in] cm_nic   pointer to previously allocated sstmacx_cm_nic struct
 * @return             FI_SUCCESS on success, -EINVAL on invalid argument
 */
int _sstmacx_cm_nic_free(struct sstmacx_cm_nic *cm_nic);

/**
 * @brief allocates a cm nic structure
 *
 * @param[in]  domain   pointer to a previously allocated sstmacx_fid_domain struct
 * @param[in]  info     pointer to fi_info struct returned from fi_getinfo (may
 *                      be NULL)
 * @param[in]  cdm_id   cdm id to be used for this cm nic
 * @param[out] cm_nic   pointer to address where address of the allocated
 *                      cm nic structure should be returned
 * @return              FI_SUCCESS on success, -EINVAL on invalid argument,
 *                      -FI_ENOMEM if insufficient memory to allocate
 *                      the cm nic structure
 */
int _sstmacx_cm_nic_alloc(struct sstmacx_fid_domain *domain,
		       struct fi_info *info,
		       uint32_t cdm_id,
			   struct sstmacx_auth_key *auth_key,
		       struct sstmacx_cm_nic **cm_nic);

/**
 * @brief enable a cm_nic for receiving incoming connection requests
 *
 * @param[in] cm_nic   pointer to previously allocated sstmacx_cm_nic struct
 * @return             FI_SUCCESS on success, -EINVAL on invalid argument.
 */
int _sstmacx_cm_nic_enable(struct sstmacx_cm_nic *cm_nic);

/**
 * @brief poke the cm nic's progress engine
 *
 * @param[in] arg      pointer to previously allocated sstmacx_cm_nic struct
 * @return             FI_SUCCESS on success, -EINVAL on invalid argument.
 *                     Other error codes may be returned depending on the
 *                     error codes returned from callback function
 *                     that had been added to the nic's work queue.
 */
int _sstmacx_cm_nic_progress(void *arg);

/**
 * @brief generate a cdm_id to be used in call to  SSTMAC_CdmCreate based on a seed
 * value previously returned from _sstmacx_cm_nic_get_cdm_seed_set
 *
 * @param[in]  domain  pointer to previously allocated sstmacx_fid_domain struct
 * @param[out] id      pointer to address where the 32 bit ids will be returned
 * @return FI_SUCCESS upon generation of 32 bit id.
 */
int _sstmacx_cm_nic_create_cdm_id(struct sstmacx_fid_domain *domain, uint32_t *id);

/**
 * @brief generate a set of contiguous, unique 32 bit cdm_ids for use with SSTMAC_CdmCreate
 *
 * @param domain  pointer to previously allocated sstmacx_fid_domain struct
 * @param nids    number of ids to be allocated
 * @param id      pointer to address where the 32 bit id will be returned
 * @return FI_SUCCESS upon generate ion of 32 bit id.
 */
int _sstmacx_get_new_cdm_id_set(struct sstmacx_fid_domain *domain, int nids,
				uint32_t *id);

/**
 * @brief helper function to quickly check whether progress is required on
 *        a cm_nic
 *
 * @param cm_nic  pointer to previously allocated sstmacx_cm_nic struct
 * @return true if progress is needed, otherwise false
 */
static inline bool _sstmacx_cm_nic_need_progress(struct sstmacx_cm_nic *cm_nic)
{
	bool ret;

	/*
	 * if control progress is manual, always need to progress
	 */
	if (cm_nic->domain->control_progress == FI_PROGRESS_MANUAL)
		return true;

	/*
	 * otherwise we only need to see if the wq has stuff to
	 * progress
	 */
	ret = (dlist_empty(&cm_nic->cm_nic_wq)) ? false : true;
	return ret;
}

#endif /* _SSTMACX_CM_NIC_H_ */

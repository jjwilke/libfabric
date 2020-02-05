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
 * Copyright (c) 2015-2017 Los Alamos National Security, LLC. All rights reserved.
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

#ifndef _SSTMACX_DATAGRAM_H_
#define _SSTMACX_DATAGRAM_H_

#include "sstmacx.h"

/*
 * SSTMAC datagram related structs and defines.
 * The SSTMAC_EpPostDataWId, etc. are used to manage
 * connecting VC's for the FI_EP_RDM endpoint
 * type.
 *
 * There are two types of datagrams used by the
 * sstmac provider: bound (bnd) datagrams and wildcard (wc)
 * datagrams.
 *
 * Bound datagrams are those that are bound to a particular
 * target nic address by means of the SSTMAC_EpBind function
 * When a bound datagram is submitted to the datagram system via
 * a SSTMAC_EpPostDataWId, ksstmac forwards the datagram to
 * the target node/cdm_id. Note that once a datagram exchange
 * has been completed, the datagram can be unbound using
 * the SSTMAC_EpUnbind, and subsequently reused to target a different
 * sstmac nic address/cdm_id.
 *
 * Wildcard datagrams have semantics similar to listening
 * sockets.  When a wildcard datagram is submitted to the
 * datagram system, ksstmac adds the datagram to the list of
 * datagrams to match for the given sstmac nic/cdm_id.  When an
 * incoming bound datagram matches the wildcard, the datagram
 * exchange is completed.
 */

/**
 * Set of attributes that can be used as an argument to sstmacx_dgram_hndl_alloc
 *
 * @var timeout_needed       pointer to a function which returns true
 *                           if a timeout is needed in the call to
 *                           SSTMAC_EpPostdataWaitById to insure progress
 * @var timeout_progress     pointer to a function should be invoked
 *                           by the datagram engine to progress
 *                           the state of the consumer of the datagram
 *                           functionality.
 * @var timeout_data         pointer to data supplied as the argument to
 *                           the timeout_needed and timeout_progress methods
 * @var timeout              the timeout value in milliseconds to be
 *                           supplied to SSTMAC_EpPostdataWaitById if
 *                           timeout_needed returns to true
 */
struct sstmacx_dgram_hndl_attr {
	bool (*timeout_needed)(void *);
	void (*timeout_progress)(void *);
	void *timeout_data;
	uint32_t timeout;
};

/**
 * Datagram allocator struct
 *
 * @var cm_nic               pointer to a previously allocated cm_nic with
 *                           which this datagram is associated
 * @var bnd_dgram_free_list  head of free list for bound datagrams
 * @var bnd_dgram_active_list  head of active list for bound datagrams
 * @var wc_dgram_free_list   head of free list of wildcard datagrams
 * @var wc_dgram_active_list head of active list of wildcard datagrams
 * @var dgram_base           starting address of memory block from
 *                           which datagram structures are allocated
 * @var timeout_needed       In the case of FI_PROGRESS_AUTO, invoke this
 *                           method prior to call to SSTMAC_EpPostDataWaitById
 *                           to check if we need to timeout in order to
 *                           progress datagrams which had been stalled
 *                           due to SSTMAC_RC_ERROR_RESOURCE.
 * @var lock                 lock to protect dgram lists
 * @var progress_thread      pthread id of progress thread for this
 *                           datagram allocator
 * @var n_dgrams             number of bound datagrams managed by the
 *                           datagram allocator
 * @var n_wc_dgrams          number of wildcard datagrams managed by
 *                           the datagram allocator
 * @var timeout              time in milliseconds to wait for datagram to
 *                           complete. By default set to -1 (infinite timeout),
 *                           but can be set to handle cases where a timeout
 *                           is required when using FI_PROGRESS_AUTO for
 *                           control progress.
 */
struct sstmacx_dgram_hndl {
	struct sstmacx_cm_nic *cm_nic;
	struct dlist_entry bnd_dgram_free_list;
	struct dlist_entry bnd_dgram_active_list;
	struct dlist_entry wc_dgram_free_list;
	struct dlist_entry wc_dgram_active_list;
	struct sstmacx_datagram *dgram_base;
	bool (*timeout_needed)(void *);
	void (*timeout_progress)(void *);
	void *timeout_data;
	fastlock_t lock;
	pthread_t progress_thread;
	int n_dgrams;
	int n_wc_dgrams;
	uint32_t timeout;
};

enum sstmacx_dgram_type {
	SSTMACX_DGRAM_WC = 100,
	SSTMACX_DGRAM_BND
};

enum sstmacx_dgram_state {
	SSTMACX_DGRAM_STATE_FREE,
	SSTMACX_DGRAM_STATE_ACTIVE
};

enum sstmacx_dgram_buf {
	SSTMACX_DGRAM_IN_BUF,
	SSTMACX_DGRAM_OUT_BUF
};

enum sstmacx_dgram_poll_type {
	SSTMACX_DGRAM_NOBLOCK,
	SSTMACX_DGRAM_BLOCK
};

/**
 * @brief SSTMAC datagram structure
 *
 * @var list                 list element for managing datagrams in llists
 * @var free_list_head       pointer to free list head from which
 *                           this datagram is allocated
 * @var sstmac_ep               SSTMAC ep used for posting this datagram to SSTMAC
 * @var nic                  sstmacx connection management (cm) nic with which
 *                           this datagram is associated
 * @var target_addr          target address to which this datagram is to be
 *                           delivered which posted to SSTMAC (applicable only
 *                           for bound datagrams)
 * @var state                state of the datagram (see enum sstmacx_dgram_state)
 * @var type                 datagram type (bound or wildcard)
 * @var d_hndl               pointer to datagram handle this datagram is
 *                           associated
 * @var pre_post_clbk_fn     Call back function to be called prior to
 *                           to the call to SSTMAC_EpPostDataWId. This callback
 *                           is invoked while the lock is held on the cm nic.
 * @var post_post_clbk_fn    Call back function to be called following
 *                           a call to SSTMAC_EpPostDataWId. This callback
 *                           is invoked while the lock is held on the cm nic.
 * @var callback_fn          Call back function to be called following
 *                           a call SSTMAC_EpPostDataTestById and a datagram
 *                           is returned in any of the following SSTMAC
 *                           post state states: SSTMAC_POST_TIMEOUT,
 *                           SSTMAC_POST_TERMINATED, SSTMAC_POST_ERROR, or
 *                           SSTMAC_POST_COMPLETED.  The cm nic lock is
 *                           not held when this callback is invoked.
 * @var r_index_in_buf       Internal index for tracking where to unstart
 *                           a unpack request on the SSTMACX_DGRAM_IN_BUF buffer
 *                           of the datagram.
 * @var w_index_in_buf       Internal index for tracking where to unstart
 *                           a pack request on the SSTMACX_DGRAM_IN_BUF buffer
 *                           of the datagram.
 * @var r_index_out_buf      Internal index for tracking where to unstart
 *                           a unpack request on the SSTMACX_DGRAM_OUT_BUF buffer
 *                           of the datagram.
 * @var w_index_out_buf      Internal index for tracking where to unstart
 *                           a pack request on the SSTMACX_DGRAM_OUT_BUF buffer
 *                           of the datagram.
 * @var cache                Pointer that can be used by datagram user to track
 *                           data associated with the datagram transaction.
 * @var dgram_in_buf         Internal buffer used for the IN data to be
 *                           posted to the SSTMAC.
 * @var dgram_out_buf        Internal buffer used for the OUT data to be
 *                           posted to the SSTMAC.
 */
struct sstmacx_datagram {
	struct dlist_entry      list;
	struct dlist_entry       *free_list_head;
	sstmac_ep_handle_t         sstmac_ep;
	struct sstmacx_cm_nic      *cm_nic;
	struct sstmacx_address     target_addr;
	enum sstmacx_dgram_state   state;
	enum sstmacx_dgram_type    type;
	struct sstmacx_dgram_hndl  *d_hndl;
	int  (*pre_post_clbk_fn)(struct sstmacx_datagram *,
				 int *);
	int  (*post_post_clbk_fn)(struct sstmacx_datagram *,
				  sstmac_return_t);
	int  (*callback_fn)(struct sstmacx_datagram *,
			    struct sstmacx_address,
			    sstmac_post_state_t);
	int r_index_in_buf;
	int w_index_in_buf;
	int r_index_out_buf;
	int w_index_out_buf;
	void *cache;
	char dgram_in_buf[SSTMAC_DATAGRAM_MAXSIZE];
	char dgram_out_buf[SSTMAC_DATAGRAM_MAXSIZE];
};

/*
 * prototypes for sstmac datagram internal functions
 */

/**
 * @brief Allocates a handle to a datagram allocator instance
 *
 * @param[in]  cm_nic     pointer to previously allocated sstmacx_cm_nic object
 * @param[in]  attr       optional pointer to a sstmacx_dgram_hndl_attr
 *                        structure
 * @param[in]  progress   progress model to be used for this cm_nic
 *                        (see fi_domain man page)
 * @param[out] handl_ptr  location in which the address of the allocated
 *                        datagram allocator handle is to be returned
 * @return FI_SUCCESS     Upon successfully creating a datagram allocator.
 * @return -FI_ENOMEM     Insufficient memory to create datagram allocator
 * @return -FI_EINVAL     Upon getting an invalid fabric or cm_nic handle
 * @return -FI_EAGAIN     In the case of FI_PROGRESS_AUTO, system lacked
 *                        resources to spawn a progress thread.
 */
int _sstmacx_dgram_hndl_alloc(struct sstmacx_cm_nic *cm_nic,
			   enum fi_progress progress,
			   const struct sstmacx_dgram_hndl_attr *attr,
			   struct sstmacx_dgram_hndl **hndl_ptr);

/**
 * @brief Frees a handle to a datagram allocator and associated internal
 *        structures
 *
 * @param[in]  hndl       pointer to previously allocated datagram allocator
 *                        instance
 * @return FI_SUCCESS     Upon successfully freeing the datagram allocator
 *                        handle and associated internal structures
 * @return -FI_EINVAL     Invalid handle to a datagram allocator was supplied
 *                        as input
 */
int _sstmacx_dgram_hndl_free(struct sstmacx_dgram_hndl *hndl);

/**
 * @brief  Allocates a datagram
 *
 * @param[in]  hndl       pointer to previously allocated datagram allocator
 *                        instance
 * @param[in] type        datagram type - wildcard or bound
 * @param[out] d_ptr      location in which the address of the allocated
 *                        datagram is to be returned
 * @return FI_SUCCESS     Upon successfully allocating a datagram
 * @return -FI_EAGAIN     Temporarily insufficient resources to allocate
 *                        a datagram.  The associated cm_nic needs to be
 *                        progressed.
 */
int _sstmacx_dgram_alloc(struct sstmacx_dgram_hndl *hndl,
			enum sstmacx_dgram_type type,
			struct sstmacx_datagram **d_ptr);

/**
 * @brief  Frees a datagram
 *
 * @param[in]  d          pointer to previously allocated datagram
 *                        datagram is to be returned
 * @return FI_SUCCESS     Upon successfully freeing a datagram
 * @return -FI_EINVAL     Invalid argument was supplied
 * @return -FI_EOPBADSTAT Datagram is currently in an internal state where
 *                        it cannot be freed
 */
int _sstmacx_dgram_free(struct sstmacx_datagram *d);

/**
 * @brief  Post a wildcard datagram to the SSTMAC datagram state engine
 *
 * @param[in]  d          pointer to previously allocated datagram
 * @return FI_SUCCESS     Upon successfully posting a wildcard datagram
 * @return -FI_EINVAL     Invalid argument was supplied
 * @return -FI_ENOMEM     Insufficient memory to post datagram
 * @return -FI_EMSGSIZE   Payload for datagram exceeds internally
 *                        supported size (see SSTMAC_DATAGRAM_MAXSIZE in
 *                        sstmac_pub.h)
 */
int _sstmacx_dgram_wc_post(struct sstmacx_datagram *d);

/**
 * @brief  Post a bound datagram to the SSTMAC datagram state engine
 *
 * @param[in]  d          pointer to previously allocated datagram
 * @return FI_SUCCESS     Upon successfully posting a wildcard datagram
 * @return -FI_EINVAL     Invalid argument was supplied
 * @return -FI_ENOMEM     Insufficient memory to post datagram
 * @return -FI_BUSY       Only one outstanding datagram to a given
 8                        target address is allowed
 * @return -FI_EMSGSIZE   Payload for datagram exceeds internally
 *                        supported size (see SSTMAC_DATAGRAM_MAXSIZE in
 *                        sstmac_pub.h)
 */
int _sstmacx_dgram_bnd_post(struct sstmacx_datagram *d);

/**
 * @brief   Pack the buffer of a previously allocated datagram
 *          with application data
 * @param[in] d           pointer to previously allocated datagram
 * @param[in] sstmacx_dgram_buf which buffer into which to pack data
 * @param[in] data        pointer to data to be packed
 * @param[in] nbytes      number of bytes to pack
 * @return  (> 0)         number of bytes packed
 * @return -FI_EINVAL     Invalid argument was supplied
 * @return -FI_ENOSPC     Insufficient space for data
 */
ssize_t _sstmacx_dgram_pack_buf(struct sstmacx_datagram *d, enum sstmacx_dgram_buf,
			 void *data, uint32_t nbytes);

/**
 * @brief   Unpack the buffer of a previously allocated datagram
 *          with application data
 * @param[in] d           pointer to previously allocated datagram
 * @param[in] sstmacx_dgram_buf which buffer from which to unpack data
 * @param[in] data        address into which the data is to be unpacked
 * @param[in] nbytes      number of bytes to unpacked
 * @return  (> 0)         number of bytes unpacked
 */
ssize_t _sstmacx_dgram_unpack_buf(struct sstmacx_datagram *d, enum sstmacx_dgram_buf,
			   void *data, uint32_t nbytes);

/**
 * @brief   rewind the internal pointers to datagram buffers to
 *          beginning of the internal buffers
 * @param[in] d           pointer to previously allocated datagram
 * @param[in] sstmacx_dgram_buf which buffer to rewind
 * @param[in] data        address into which the data is to be unpacked
 * @param[in] nbytes      number of bytes to unpacked
 * @return FI_SUCCESS     Upon successfully rewinding internal buffer
 *                        pointers
 */
int _sstmacx_dgram_rewind_buf(struct sstmacx_datagram *d, enum sstmacx_dgram_buf);

/**
 * @brief   poll datagram handle to progress the underlying cm_nic's
 *          progress engine
 * @param[in] hndl_ptr    handle to a previously allocated datagram
 *                        allocator
 * @param[in] type        progress type (blocking or non-blocking)
 * @return FI_SUCCESS     Upon successfully progressing the state
 *                        engine
 */
int _sstmacx_dgram_poll(struct sstmacx_dgram_hndl *hndl_ptr,
			enum sstmacx_dgram_poll_type type);


#endif /* _SSTMACX_DATAGRAM_H_ */

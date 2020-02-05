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
 * Copyright (c) 2015-2017 Cray Inc.  All rights reserved.
 * Copyright (c) 2015-2016 Los Alamos National Security, LLC. All rights reserved.
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

#ifndef _SSTMACX_NIC_H_
#define _SSTMACX_NIC_H_

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */
#include <ofi_list.h>
#include <assert.h>

#include "sstmacx.h"
#include "sstmacx_bitmap.h"
#include "sstmacx_mbox_allocator.h"
#include "sstmacx_util.h"

#define SSTMACX_DEF_MAX_NICS_PER_PTAG	4

/*
 * globals
 */

extern uint32_t sstmacx_max_nics_per_ptag;
extern struct dlist_entry sstmacx_nic_list_ptag[];
extern struct dlist_entry sstmacx_nic_list;
extern pthread_mutex_t sstmacx_nic_list_lock;

/*
 * allocation flags for cleaning up SSTMAC resources
 * when closing a sstmacx_nic - needed since these
 * can be dup'd from another structure.
 */

#define SSTMACX_NIC_CDM_ALLOCD	(1ULL << 1)
#define SSTMACX_NIC_TX_CQ_ALLOCD	(1ULL << 2)
#define SSTMACX_NIC_RX_CQ_ALLOCD	(1ULL << 3)

/*
 * typedefs for callbacks for handling
 * receipt of SMSG messages at the target
 */
typedef int (*smsg_callback_fn_t)(void  *ptr, void *msg);

extern smsg_callback_fn_t sstmacx_ep_smsg_callbacks[];

/*
 * typedef for completer functions invoked
 * at initiator when local CQE (tx) is processed
 */
typedef int (*smsg_completer_fn_t)(void  *desc, sstmac_return_t);

/**
 * Set of attributes that can be passed to the sstmacx_alloc_nic.
 *
 * @var sstmac_cdm_hndl         optional previously allocated sstmac_cdm_hndl to
 *                           use for allocating SSTMAC resources (SSTMAC CQs) for
 *                           this nic.
 * @var sstmac_nic_hndl         optional previously allocated sstmac_nic_hndl to
 *                           use for allocating SSTMAC resources (SSTMAC CQs) for
 *                           this nic
 *
 * @var sstmac_cdm_modes	     The mode bits sstmac_cdm_hndl was created with.
 */
struct sstmacx_nic_attr {
	sstmac_cdm_handle_t sstmac_cdm_hndl;
	uint32_t	 sstmac_cdm_modes;
	sstmac_nic_handle_t sstmac_nic_hndl;
	bool use_cdm_id;
	uint32_t cdm_id;
	bool must_alloc;
	struct sstmacx_auth_key *auth_key;
};

/**
 * SSTMACX nic struct
 *
 * @var sstmacx_nic_list        list element used for global NIC list
 * @var ptag_nic_list        list element used for NIC linked list associated
 *                           with a given PTAG.
 * @var lock                 lock used for serializing access to
 *                           sstmac_nic_hndl, rx_cq, and tx_cq
 * @var sstmac_cdm_hndl         handle for the SSTMAC communication domain (CDM)
 *                           this nic is bound to.
 * @var sstmac_cdm_modes	     The mode bits sstmac_cdm_hndl was created with.
 * @var sstmac_nic_hndl         handle for the SSTMAC nic to which this SSTMACX nic is bound
 * @var rx_cq                SSTMAC rx cq (non-blocking) bound to this nic
 * @var rx_cq_blk            SSTMAC rx cq (blocking) bound to this nic
 * @var tx_cq                SSTMAC tx cq (non-blocking) bound to this nic
 * @var tx_cq_blk            SSTMAC tx cq (blocking) bound to this nic
 * @var progress_thread      thread id of progress thread for this nic
 * @var tx_desc_active_list  linked list of active tx descriptors associated
 *                           with this nic
 * @var tx_desc_free_list    linked list of free tx descriptors associated
 *                           with this nic
 * @var tx_desc_base         base address for the block of memory from which
 *                           tx descriptors were allocated
 * @var prog_vcs_lock        lock for prog_vcs
 * @var prog_vcs             list of VCs needing progress
 * @var wq_lock              lock for serializing access to the nic's work queue
 * @var nic_wq               head of linked list of work queue elements
 *                           associated with this nic
 * @var ptag                 ptag of the SSTMAC CDM this nic is bound to
 * @var cookie               cookie of the SSTMAC CDM this nic is bound to
 *                           of the VC when using SSTMAC_CQ_GET_INST_ID to get
 * @var device_id            device id of the SSTMAC nic this nic is bound to (always 0,
 *                           unless ever need to support multiple SSTMAC nics/node)
 * @var device_addr          address (L2) of the SSTMAC nic to which this nic is bound
 * @var max_tx_desc_id       max tx descriptor id for this nic
 * @var vc_id_lock           lock for serializing access to the vc_id_table for
 *                           this nic
 * @var vc_id_table          base address of the nic's vc_id_table
 * @var vc_id_table_capacity current capacity of the nic's vc_id_table
 * @var vc_id_table_count    current location of the next unoccupied entry in the
 *                           vc_id_table - note there may be unused entries
 *                           below this entry.
 * @var vc_id_bitmap         bitmap indicating which entries in the vc_id_table are
 *                           currently in use (1 - used, 0 - unused)
 * @var mem_per_mbox         number of bytes consumed per SSTMAC SMSG mailbox associated
 *                           with this nic's vd_id_table
 * @var mbox_hndl            handle for the mailbox allocator bound to this nic
 * @var s_rdma_buf_hndl      handle for send side rdma buffer allocator bound to this nic
 * @var r_rdma_buf_hndl      handle for recv side rdma buffer allocator bound to this nic
 * @var ref_cnt              ref cnt for this nid
 * @var smsg_callbacks       pointer to table of SSTMAC SMSG callback functions used
 *                           by this nic for processing incoming SSTMAC SMS
 *                           messages
 * @var err_txds             slist of error'd tx descriptors
 * @var tx_cq_blk_post_cnt   count of outstanding tx desc's posted using tx_cq_blk
 *                           SSTMAC CQ.
 * @var irq_mem_hndl         sstmac_mem_handle_t for mmap region registered with
 *                           sstmac hw cq handle used for SSTMAC_PostCqWrite
 * @var irq_mmap_addr        base address of mmap associated with irq_dma_hndl
 * @var irq_mmap_len         length of the mmap in bytes
 * @var using_vmdh           denotes whether nic is associated with a domain
 *                           that is utilizing VMDH
 * @var mdd_resources_set    flag to indicate whether SSTMAC_SetMDDResources has
 *                           called yet to reserve MDD resources
 */
struct sstmacx_nic {
	struct dlist_entry sstmacx_nic_list; /* global NIC list */
	struct dlist_entry ptag_nic_list; /* global PTAG NIC list */
	struct dlist_entry sstmacx_nic_prog_list; /* temporary list for nic progression */
	fastlock_t lock;
	uint32_t allocd_sstmac_res;
	sstmac_cdm_handle_t sstmac_cdm_hndl;
	uint32_t	 sstmac_cdm_modes;
	sstmac_nic_handle_t sstmac_nic_hndl;
	sstmac_cq_handle_t rx_cq;
	sstmac_cq_handle_t rx_cq_blk;
	sstmac_cq_handle_t tx_cq;
	sstmac_cq_handle_t tx_cq_blk;
	pthread_t progress_thread;
	fastlock_t tx_desc_lock;
	struct dlist_entry tx_desc_active_list;
	struct dlist_entry tx_desc_free_list;
	struct sstmacx_tx_descriptor *tx_desc_base;
	fastlock_t prog_vcs_lock;
	struct dlist_entry prog_vcs;
	/* note this free list will be initialized for thread safe */
	struct sstmacx_freelist vc_freelist;
	uint8_t ptag;
	uint32_t cookie;
	uint32_t device_id;
	uint32_t device_addr;
	int max_tx_desc_id;
	fastlock_t vc_id_lock;
	void **vc_id_table;
	int vc_id_table_capacity;
	int vc_id_table_count;
	sstmacx_bitmap_t vc_id_bitmap;
	uint32_t mem_per_mbox;
	struct sstmacx_mbox_alloc_handle *mbox_hndl;
	/* TODO: sstmacx_buddy_alloc_handle_t *alloc_handle */
	struct sstmacx_mbox_alloc_handle *s_rdma_buf_hndl;
	struct sstmacx_mbox_alloc_handle *r_rdma_buf_hndl;
	struct sstmacx_reference ref_cnt;
	smsg_callback_fn_t const *smsg_callbacks;
	struct slist err_txds;
	sstmac_mem_handle_t irq_mem_hndl;
	void *irq_mmap_addr;
	size_t irq_mmap_len;
	int requires_lock;
	int mdd_resources_set;
	int using_vmdh;
};


/**
 * sstmacx_smsg_eager_hdr  - first part of an eager send SMSG message
 *
 * @var flags      flag bits from send side that are needed at
 *                 rcv side (e.g. FI_REMOTE_CQ_DATA)
 * @var imm        immediate data associated with this message
 * @var msg_tag    libfabric tag associated with this message
 * @var len        length in bytes of the incoming message
 */
struct sstmacx_smsg_eager_hdr {
	uint64_t flags;
	uint64_t imm;
	uint64_t msg_tag;
	size_t len;
};

/**
 * sstmacx_smsg_rndzv_start_hdr  - first part of a rendezvous send start SMSG
 *                              message
 *
 * @var flags      flag bits from send side that are needed at
 *                 rcv side (e.g. FI_REMOTE_CQ_DATA)
 * @var imm        immediate data associated with this message
 * @var msg_tag    libfabric tag associated with this message
 * @var mdh        MDH for the rendezvous send buffer
 * @var addr       address of the rendezvous send buffer
 * @var len        length in bytes of the send buffer
 * @var req_addr   local request address
 * @var head       unaligned data at the head of a rendezvous send
 * @var tail       unaligned data at the tail of a rendezvous send
 */
struct sstmacx_smsg_rndzv_start_hdr {
	uint64_t flags;
	uint64_t imm;
	uint64_t msg_tag;
	sstmac_mem_handle_t mdh;
	uint64_t addr;
	size_t len;
	uint64_t req_addr;
	uint32_t head;
	uint32_t tail;
};

/**
 * sstmacx_smsg_rndzv_iov_start_hdr
 *
 * @var flags	      the sender's flags needed on the receive side.
 * @var imm	      the immediate data associated with this message.
 * @var msg_tag       the tag associated with this message.
 * @var mdh	      the memory handle associated with the iov buffer.
 * @var iov_cnt       the length of the scatter/gather vector.
 * @var req_addr      the sender's fabric request address.
 * @var send_len      the cumulative size (in bytes) of the client's
 * iov base buffers.
 *
 * @note the actual iov base addresses and lengths are placed in the
 * data section of the start message.
 */
struct sstmacx_smsg_rndzv_iov_start_hdr {
	uint64_t flags;
	uint64_t imm;
	uint64_t msg_tag;
	uint64_t req_addr;
	size_t   iov_cnt;
	uint64_t send_len;
};

/**
 * sstmacx_smsg_rndzv_fin_hdr  - first part of a rendezvous send fin SMSG message
 *
 * @var req_addr   returned local request address
 */
struct sstmacx_smsg_rndzv_fin_hdr {
	uint64_t req_addr;
	int status;
};

/**
 * sstmacx_smsg_rma_data_hdr  - RMA remote data message
 *
 * @var flags       control flags
 * @var user_flags  remote CQ user flags
 * @var user_data   remote CQ user immediate data
 */
struct sstmacx_smsg_rma_data_hdr {
	uint64_t flags;
	uint64_t user_flags;
	uint64_t user_data;
};

/**
 * sstmacx_smsg_amo_cntr_hdr  - RMA remote counter message
 *
 * @var user_flags  control flags
 */
struct sstmacx_smsg_amo_cntr_hdr {
	uint64_t flags;
};

/**
 * sstmac_tx_descriptor - full tx descriptor used to to track SSTMAC SMSG
 *                     and Post operations
 *
 * @var list             list element
 * @var sstmac_desc         embedded SSTMAC post descriptor
 * @var sstmacx_ct_descs    embedded SSTMAC post descriptors for concatenated gets
 *                       used for unaligned gets
 * @var sstmac_more_ct_descs embedded SSTMAC post descriptors for concatenated puts
			  or gets for FI_MORE.
 * @var sstmacx_smsg_eager_hdr embedded header for SMSG eager protocol
 * @var sstmacx_smsg_rndzv_start_hdr embedded header for rendezvous protocol
 * @var sstmacx_smsg_rndzv_iov_start_hdr embedded header for iovec rndzv protocol
 * @var sstmacx_smsg_rndzv_fin_hdr embedded header for rendezvous protocol
 * @var sstmacx_smsg_rndzv_rma_data_hdr embedded header for remote notification for
 *                       rma operations
 * @var sstmacx_smsg_amo_cntr_hdr embedded header for AMO remote counter events.
 * @var req              pointer to fab request associated with this descriptor
 * @var completer_fn     call back to invoke when associated SSTMAC CQE's are
 *                       returned.
 * @var id               the id of this descriptor - the value returned
 *                       from SSTMAC_CQ_MSG_ID
 * @var err_list         Error TXD list entry
 * @var tx_failures	 Number of times this transmission descriptor failed.
 */
struct sstmacx_tx_descriptor {
	struct dlist_entry          list;
	union {
		struct {
			sstmac_post_descriptor_t        sstmac_desc;
			sstmac_ct_get_post_descriptor_t sstmac_ct_descs[2];
			void			     *sstmac_more_ct_descs;
		};
		struct sstmacx_smsg_eager_hdr           eager_hdr;
		struct sstmacx_smsg_rndzv_start_hdr     rndzv_start_hdr;
		struct sstmacx_smsg_rndzv_iov_start_hdr rndzv_iov_start_hdr;
		struct sstmacx_smsg_rndzv_fin_hdr       rndzv_fin_hdr;
		struct sstmacx_smsg_rma_data_hdr        rma_data_hdr;
		struct sstmacx_smsg_amo_cntr_hdr	     amo_cntr_hdr;
	};
	struct sstmacx_fab_req *req;
	int  (*completer_fn)(void *, sstmac_return_t);
	int id;
	struct slist_entry err_list;
};

/*
 * prototypes
 */

/**
 * @brief allocate a tx descriptor to use for SSTMAC Post, SMSG ops
 *
 * @param[in] nic      pointer to previously allocated sstmacx_nic struct
 * @param[in] tdesc    pointer to address where allocated tx descriptor
 *                     is to be stored
 * @return             FI_SUCCESS on success, -FI_ENOSPC no free tx descriptors
 */
static inline int _sstmacx_nic_tx_alloc(struct sstmacx_nic *nic,
               struct sstmacx_tx_descriptor **desc)
{
    struct dlist_entry *entry;

    COND_ACQUIRE(nic->requires_lock, &nic->tx_desc_lock);
    if (dlist_empty(&nic->tx_desc_free_list)) {
        COND_RELEASE(nic->requires_lock, &nic->tx_desc_lock);
        return -FI_ENOSPC;
    }

    entry = nic->tx_desc_free_list.next;
    dlist_remove_init(entry);
    dlist_insert_head(entry, &nic->tx_desc_active_list);
    *desc = dlist_entry(entry, struct sstmacx_tx_descriptor, list);
    COND_RELEASE(nic->requires_lock, &nic->tx_desc_lock);

    return FI_SUCCESS;
}


/**
 * @brief frees a previously allocated tx descriptor
 *
 * @param[in] nic      pointer to previously allocated sstmacx_nic struct used
 *                     when allocating the tx descriptor to be freed
 * @param[in] tdesc    pointer to previously allocated tx descriptor
 * @return             FI_SUCCESS on success
 */
static inline int _sstmacx_nic_tx_free(struct sstmacx_nic *nic,
                                struct sstmacx_tx_descriptor *desc)
{
    COND_ACQUIRE(nic->requires_lock, &nic->tx_desc_lock);
    dlist_remove_init(&desc->list);
    dlist_insert_head(&desc->list, &nic->tx_desc_free_list);
    COND_RELEASE(nic->requires_lock, &nic->tx_desc_lock);

    return FI_SUCCESS;
}


/**
 * @brief allocate a sstmacx_nic struct
 *
 * @param[in] domain   pointer to previously allocated sstmacx_fid_domain struct
 * @param[in] attrs    optional pointer to an attributes argument.  NULL
 *                     can be supplied if no attributes are required
 * @param[out] nic_ptr pointer to address where address of allocated nic is
 *                     to be returned
 * @return             FI_SUCCESS on success, -FI_ENOMEM if insufficient memory
 *                     to allocate nic struct, -FI_EINVAL if an invalid domain
 *                     struct was supplied, -FI_EBUSY if insufficient resources
 *                     are available to allocate the nic struct, -FI_EACCESS
 *                     if a permissions access error occurred while allocating
 *                     the nic struct, -FI_EAGAIN if an invalid state
 *                     prevents creation or an interrupt was received while
 *                     allocating kernel related resources for the nic.
 */
int sstmacx_nic_alloc(struct sstmacx_fid_domain *domain,
		   struct sstmacx_nic_attr *attrs,
		   struct sstmacx_nic **nic_ptr);

/**
 * @brief frees a previously allocated sstmacx_nic struct
 *
 * @param[in] nic      pointer to previously allocated sstmacx_nic struct
 * @return             FI_SUCCESS on success, -FI_ENOSPC no free tx descriptors
 */
int _sstmacx_nic_free(struct sstmacx_nic *nic);

/**
 * @brief progresses control/data operations associated with the nic
 *
 * @param[in] arg      pointer to previously allocated sstmacx_nic struct
 * @return             FI_SUCCESS on success, -FI_EINVAL if an invalid
 *                     nic struct was supplied. TODO: a lot more error
 *                     values can be returned.
 */
int _sstmacx_nic_progress(void *arg);

/**
 * @brief allocate a remote id for an object, used for looking up an object
 *        in O(1) based on returned value of SSTMAC_CQ_INST_ID applied to a SSTMAC
 *        CQE
 *
 * @param[in] nic             pointer to previously allocated sstmacx_nic struct
 * @param[out] remote_id      address where allocate remote_id is returned
 * @param[in] entry           pointer to object to be associated with the
 *                            remote id

 * @return             FI_SUCCESS on success, -FI_ENOMEM if insufficient
 *                     memory to allocate remote_id
 */
int _sstmacx_nic_get_rem_id(struct sstmacx_nic *nic, int *remote_id, void *entry);

/**
 * @brief release a previously allocated remote_id
 *
 * @param[in] nic            pointer to previously allocated sstmacx_nic struct
 * @param[in] remote_id      previously allocated remote_id

 * @return             FI_SUCCESS on success, -FI_EINVAL if an invalid
 *                     argument was provided.
 */
int _sstmacx_nic_free_rem_id(struct sstmacx_nic *nic, int remote_id);

/**
 * @brief Look up an element by id
 *
 * @param[in] nic    pointer to sstmac nic with which the vc is associated
 * @param[in] rem_id rem_id of the object being looked up
 *                   rem_id comes from SSTMAC_CQ_GET_INST_ID on a SSTMAC CQE
 *
 * @return           pointer to vc with the given vc_id
 *
 * This function is only here because its used for criterion tests,
 * otherwise it would be a static function within sstmacx_nic.c
 */
static inline void *__sstmacx_nic_elem_by_rem_id(struct sstmacx_nic *nic, int rem_id)
{
	void *elem;

	assert(nic);

	COND_ACQUIRE(nic->requires_lock, &nic->vc_id_lock);

	assert(rem_id <= nic->vc_id_table_count);
	elem = nic->vc_id_table[rem_id];

	COND_RELEASE(nic->requires_lock, &nic->vc_id_lock);

	return elem;
}

void _sstmacx_nic_txd_err_inject(struct sstmacx_nic *nic,
			      struct sstmacx_tx_descriptor *txd);

/**
 * @brief Initialize global NIC data.
 */
void _sstmacx_nic_init(void);

#endif /* _SSTMACX_NIC_H_ */

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

#ifndef _SSTMACX_CQ_H_
#define _SSTMACX_CQ_H_

#include <ofi.h>

#include "sstmacx_progress.h"
#include "sstmacx_queue.h"
#include "sstmacx_wait.h"
#include "sstmacx_util.h"
#include <ofi_list.h>
#include <stdbool.h>

#define SSTMACX_CQ_DEFAULT_FORMAT struct fi_cq_entry
#define SSTMACX_CQ_DEFAULT_SIZE   256
#define SSTMACX_CQ_MAX_ERR_DATA_SIZE 64

/* forward declaration */
struct sstmacx_fid_ep;

struct sstmacx_cq_entry {
	void *the_entry;
	fi_addr_t src_addr;
	struct slist_entry item;
};

struct sstmacx_fid_cq {
	struct fid_cq cq_fid;
	struct sstmacx_fid_domain *domain;

	struct sstmacx_queue *events;
	struct sstmacx_queue *errors;

	struct fi_cq_attr attr;
	size_t entry_size;

	struct fid_wait *wait;

	fastlock_t lock;
	struct sstmacx_reference ref_cnt;

	struct sstmacx_prog_set pset;

	bool requires_lock;
	char err_data[SSTMACX_CQ_MAX_ERR_DATA_SIZE];
};

ssize_t _sstmacx_cq_add_event(struct sstmacx_fid_cq *cq, struct sstmacx_fid_ep *ep,
			   void *op_context, uint64_t flags, size_t len,
			   void *buf, uint64_t data, uint64_t tag,
			   fi_addr_t src_addr);

ssize_t _sstmacx_cq_add_error(struct sstmacx_fid_cq *cq, void *op_context,
			  uint64_t flags, size_t len, void *buf,
			  uint64_t data, uint64_t tag, size_t olen,
			  int err, int prov_errno, void *err_data,
			  size_t err_data_size);

int _sstmacx_cq_poll_obj_add(struct sstmacx_fid_cq *cq, void *obj,
			  int (*prog_fn)(void *data));
int _sstmacx_cq_poll_obj_rem(struct sstmacx_fid_cq *cq, void *obj,
			  int (*prog_fn)(void *data));

#endif

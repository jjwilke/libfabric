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
 * Copyright (c) 2015 Los Alamos National Security, LLC. All rights reserved.
 * Copyright (c) 2015-2016 Cray Inc. All rights reserved.
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

#ifndef _SSTMACX_EQ_H_
#define _SSTMACX_EQ_H_

#include <rdma/fi_eq.h>
#include <stdbool.h>

#include "sstmacx_queue.h"
#include "sstmacx_wait.h"
#include "sstmacx_util.h"

#define SSTMACX_EQ_DEFAULT_SIZE 256

extern struct dlist_entry sstmacx_eq_list;
extern pthread_mutex_t sstmacx_eq_list_lock;

/*
 * Stores events inside of the event queue.
 *
 * type: EQ event type defined in fi_eq.h
 * len: length of the event
 * flags: control flags
 * buf: event
 * item: list entry, contains next pointer
 */
struct sstmacx_eq_entry {
	uint64_t flags;
	uint32_t type;
	size_t len;
	void *the_entry;

	struct slist_entry item;
};

struct sstmacx_eq_poll_obj {
	struct dlist_entry list;
	struct fid *obj_fid;
};

struct sstmacx_eq_err_buf {
	struct dlist_entry dlist;
	int do_free;
	char buf[];
};

/*
 * EQ structure. Contains error and event queue.
 */
struct sstmacx_fid_eq {
	struct fid_eq eq_fid;
	struct sstmacx_fid_fabric *fabric;

	bool requires_lock;

	struct sstmacx_queue *events;
	struct sstmacx_queue *errors;

	struct fi_eq_attr attr;

	struct fid_wait *wait;

	fastlock_t lock;
	struct sstmacx_reference ref_cnt;

	rwlock_t poll_obj_lock;
	struct dlist_entry poll_objs;
	struct dlist_entry sstmacx_fid_eq_list;

	struct dlist_entry err_bufs;
};

ssize_t _sstmacx_eq_write_error(struct sstmacx_fid_eq *eq, fid_t fid,
			     void *context, uint64_t index, int err,
			     int prov_errno, void *err_data,
			     size_t err_size);

int _sstmacx_eq_progress(struct sstmacx_fid_eq *eq);

int _sstmacx_eq_poll_obj_add(struct sstmacx_fid_eq *eq, struct fid *obj_fid);
int _sstmacx_eq_poll_obj_rem(struct sstmacx_fid_eq *eq, struct fid *obj_fid);

#endif /* _SSTMACX_EQ_H_ */

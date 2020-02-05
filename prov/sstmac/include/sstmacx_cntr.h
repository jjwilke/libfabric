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

#ifndef _SSTMACX_CNTR_H_
#define _SSTMACX_CNTR_H_

#include <ofi.h>

#include "sstmacx.h"
#include "sstmacx_progress.h"
#include "sstmacx_wait.h"
#include "sstmacx_util.h"

struct sstmacx_fid_cntr {
	struct fid_cntr cntr_fid;
	struct sstmacx_fid_domain *domain;
	struct fid_wait *wait;
	struct fi_cntr_attr attr;
	ofi_atomic32_t cnt;
	ofi_atomic32_t cnt_err;
	struct sstmacx_reference ref_cnt;
	struct dlist_entry trigger_list;
	fastlock_t trigger_lock;
	struct sstmacx_prog_set pset;
	bool requires_lock;
};

/**
 * @brief              Increment event counter associated with a sstmacx_fid counter
 *                     object
 * @param[in] cntr     pointer to previously allocated sstmacx_fid_cntr structure
 * @return             FI_SUCCESS on success, -FI_EINVAL on invalid argument
 */
int _sstmacx_cntr_inc(struct sstmacx_fid_cntr *cntr);

/**
 * @brief              Increment error event counter associated with a sstmacx_fid counter
 *                     object
 * @param[in] cntr     pointer to previously allocated sstmacx_fid_cntr structure
 * @return             FI_SUCCESS on success, -FI_EINVAL on invalid argument
 */
int _sstmacx_cntr_inc_err(struct sstmacx_fid_cntr *cntr);

/**
 * @brief              Add an object to the list progressed when fi_cntr_read
 *                     and related functions are called.
 * @param[in] cntr     pointer to previously allocated sstmacx_fid_cntr structure
 * @param[in] obj      pointer to object to add to the progress list.
 * @param[in] prog_fn  object progress function
 * @return             FI_SUCCESS on success, -FI_EINVAL on invalid argument
 */
int _sstmacx_cntr_poll_obj_add(struct sstmacx_fid_cntr *cntr, void *obj,
			    int (*prog_fn)(void *data));

/**
 * @brief              Remove an object from the list progressed when
 *                     fi_cntr_read and related functions are called.
 * @param[in] cntr     pointer to previously allocated sstmacx_fid_cntr structure
 * @param[in] obj      pointer to previously added object
 * @param[in] prog_fn  object progress function
 * @return             FI_SUCCESS on success, -FI_EINVAL on invalid argument
 */
int _sstmacx_cntr_poll_obj_rem(struct sstmacx_fid_cntr *cntr, void *obj,
			    int (*prog_fn)(void *data));

#endif

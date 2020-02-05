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
 * Copyright (c) 2015-2016 Los Alamos National Security, LLC. All
 * Copyright (c) 2016 Cray Inc.  All rights reserved.
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

#ifndef _SSTMACX_POLL_H_
#define _SSTMACX_POLL_H_

/*******************************************************************************
 * API Functions
 ******************************************************************************/
/**
 * Poll progress and events across multiple completion queues and counters.
 *
 * @param[in] pollset		the pollset
 * @param[in/out] context	user context values associated with completion
 * queues or counters
 * @param[in] count		number of entries in context
 *
 * @return FI_SUCCESS	upon successfully polling progress
 * @return -FI_ERRNO	upon an error
 * @return -FI_ENOSYS	if this operation is not supported
 */
int sstmacx_poll_poll(struct fid_poll *pollset, void **context, int count);

/**
 * Associates a completions queue or counter with a poll set
 *
 * @param[in] pollset	the pollset
 * @param[in] event_fid	the queue or counter
 * @param[in] flags	flags for the requests
 *
 * @return FI_SUCCESS	upon adding the completion queue or counter
 * @return -FI_ERRNO	upon an error
 * @return -FI_ENOSYS	if this operation is not supported
 */
int sstmacx_poll_add(struct fid_poll *pollset, struct fid *event_fid,
		  uint64_t flags);

/**
 * Removes a completion queue or counter from a poll set.
 *
 * @param[in] pollset	the pollset
 * @param[in] event_fid	the queue or counter
 * @param[in] flags	flags for the requests
 *
 * @return FI_SUCCESS	upon removing the completion queue or counter
 * @return -FI_ERRNO	upon an error
 * @return -FI_ENOSYS	if this operation is not supported
 */
int sstmacx_poll_del(struct fid_poll *pollset, struct fid *event_fid,
		  uint64_t flags);

/*******************************************************************************
 * Exposed internal functions.
 ******************************************************************************/

#endif /* _SSTMACX_POLL_H_ */

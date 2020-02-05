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
 * Copyright (c) 2016 Cray Inc. All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc. All rights reserved.
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

#ifndef _SSTMACX_MR_NOTIFIER_H_
#define _SSTMACX_MR_NOTIFIER_H_

#include <stdint.h>
#include <stddef.h>
#include "rdma/fi_errno.h"
#include "config.h"

#if HAVE_KDREG

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <kdreg_pub.h>

#include "rdma/providers/fi_log.h"
#include "sstmacx_util.h"

#define KDREG_DEV "/dev/kdreg"

typedef volatile uint64_t kdreg_user_delta_t;

/**
 * @brief memory registration notifier
 *
 * @var   fd        File descriptor for KDREG_DEV
 * @var   cntr      Kernel managed counter for monitored events
 * @var   lock      Only used for set up and tear down (no guarantees
 *                  if reading or writing while setting up or tearing down)
 */
struct sstmacx_mr_notifier {
	int fd;
	kdreg_user_delta_t *cntr;
	fastlock_t lock;
	int ref_cnt;
};

/**
 * @brief initialize the process for use of the notifier
 *
 * @return              FI_SUCESSS on success
 */
int _sstmacx_notifier_init(void);

/**
 * @brief open the kdreg device and prepare for notifications
 *
 * @param[in,out] k     Empty and initialized sstmacx_mr_notifier struct
 * @return              FI_SUCESSS on success
 *                      -FI_EBUSY if device already open
 *                      -FI_ENODATA if user delta unavailable
 *                      -fi_errno or -errno on other failures
 */
int _sstmacx_notifier_open(struct sstmacx_mr_notifier **mrn);

/**
 * @brief close the kdreg device and zero the notifier
 *
 * @param[in] k         sstmacx_mr_notifier struct
 * @return              FI_SUCESSS on success
 *                      -fi_errno or -errno on other failures
 */
int _sstmacx_notifier_close(struct sstmacx_mr_notifier *mrn);

/**
 * @brief monitor a memory region
 *
 * @param[in] k         sstmacx_mr_notifier struct
 * @param[in] addr      address of memory region to monitor
 * @param[in] len       length of memory region
 * @param[in] cookie    user identifier associated with the region
 * @return              FI_SUCESSS on success
 *                      -fi_errno or -errno on failure
 */
int _sstmacx_notifier_monitor(struct sstmacx_mr_notifier *mrn, void *addr,
			   uint64_t len, uint64_t cookie);

/**
 * @brief stop monitoring a memory region
 *
 * @param[in]  k        sstmacx_mr_notifier struct
 * @param[out] cookie   user identifier for notification event
 * @return              FI_SUCESSS on success
 *                      -fi_errno or -errno on failure
 */
int _sstmacx_notifier_unmonitor(struct sstmacx_mr_notifier *mrn, uint64_t cookie);

/**
 * @brief get a monitoring event
 *
 * @param[in]  k        sstmacx_mr_notifier struct
 * @param[out] buf      buffer to write event data
 * @param[in]  len      length of buffer
 * @return              Number of bytes read on success
 *                      -FI_EINVAL if invalid arguments
 *                      -FI_EAGAIN if nothing to read
 *                      -fi_errno or -errno on failure
 */
int _sstmacx_notifier_get_event(struct sstmacx_mr_notifier *mrn,
			     void* buf, size_t len);

#else

struct sstmacx_mr_notifier {
	int dummy[0];
};

static inline int
_sstmacx_notifier_init(void)
{
	return FI_SUCCESS;
}

static inline int
_sstmacx_notifier_open(struct sstmacx_mr_notifier **mrn)
{
	return FI_SUCCESS;
}

static inline int
_sstmacx_notifier_close(struct sstmacx_mr_notifier *mrn)
{
	return FI_SUCCESS;
}

static inline int
_sstmacx_notifier_monitor(struct sstmacx_mr_notifier *mrn, void *addr,
		       uint64_t len, uint64_t cookie)
{
	return FI_SUCCESS;
}

static inline int
_sstmacx_notifier_unmonitor(struct sstmacx_mr_notifier *mrn, uint64_t cookie)
{
	return FI_SUCCESS;
}

static inline int
_sstmacx_notifier_get_event(struct sstmacx_mr_notifier *mrn, void* buf, size_t len)
{
	return -FI_EAGAIN;
}

#endif /* HAVE_KDREG */

#endif /* _SSTMACX_MR_NOTIFIER_H_ */

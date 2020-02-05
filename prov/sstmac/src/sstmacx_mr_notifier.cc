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
 * Copyright (c) 2017 Los Alamos National Security, LLC.
 *                    All rights reserved.
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


#include "sstmacx_mr_notifier.h"

#if HAVE_KDREG

struct sstmacx_mr_notifier global_mr_not;

static inline int
notifier_verify_stuff(struct sstmacx_mr_notifier *mrn) {
	/* Can someone confirm that these values are POSIX so we can
	 * be less pedantic? */
	if (mrn->fd == STDIN_FILENO ||
	    mrn->fd == STDOUT_FILENO ||
	    mrn->fd == STDERR_FILENO ||
	    mrn->fd < 0) {
		// Be quiet here
		return -FI_EBADF;
	}

	if (mrn->cntr == NULL) {
		// Be quiet here
		return -FI_ENODATA;
	}

	return FI_SUCCESS;
}

int
_sstmacx_notifier_init(void)
{
	global_mr_not.fd = -1;
	global_mr_not.cntr = NULL;
	fastlock_init(&global_mr_not.lock);
	global_mr_not.ref_cnt = 0;

	return FI_SUCCESS;
}

int
_sstmacx_notifier_open(struct sstmacx_mr_notifier **mrn)
{
	int ret = FI_SUCCESS;
	int kdreg_fd, ret_errno;
        kdreg_get_user_delta_args_t get_user_delta_args;

	fastlock_acquire(&global_mr_not.lock);

	if (!global_mr_not.ref_cnt) {
		kdreg_fd = open(KDREG_DEV, O_RDWR | O_NONBLOCK);
		if (kdreg_fd < 0) {
			ret_errno = errno;
			SSTMACX_WARN(FI_LOG_MR,
				  "kdreg device open failed: %s\n",
				  strerror(ret_errno));
			/* Not all of these map to fi_errno values */
			ret = -ret_errno;
			goto err_exit;
		}

		memset(&get_user_delta_args, 0, sizeof(get_user_delta_args));
		if (ioctl(kdreg_fd, KDREG_IOC_GET_USER_DELTA,
			  &get_user_delta_args) < 0) {
			ret_errno = errno;
			SSTMACX_WARN(FI_LOG_MR,
				  "kdreg get_user_delta failed: %s\n",
				  strerror(ret_errno));
			close(kdreg_fd);
			/* Not all of these map to fi_errno values */
			ret = -ret_errno;
			goto err_exit;
		}

		if (get_user_delta_args.user_delta == NULL) {
			SSTMACX_WARN(FI_LOG_MR, "kdreg get_user_delta is NULL\n");
			ret = -FI_ENODATA;
			goto err_exit;
		}

		global_mr_not.fd = kdreg_fd;
		global_mr_not.cntr = (kdreg_user_delta_t *)
				get_user_delta_args.user_delta;
	}

	global_mr_not.ref_cnt++;
	*mrn = &global_mr_not;

err_exit:
	fastlock_release(&global_mr_not.lock);

	return ret;
}

int
_sstmacx_notifier_close(struct sstmacx_mr_notifier *mrn)
{
	int ret = FI_SUCCESS;
	int ret_errno;

	fastlock_acquire(&mrn->lock);

	ret = notifier_verify_stuff(mrn);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_MR, "Invalid MR notifier\n");
		goto err_exit;
	}

	assert(mrn->ref_cnt > 0);
	if (--mrn->ref_cnt) {
		goto err_exit;
	}

	if (close(mrn->fd) != 0) {
		ret_errno = errno;
		SSTMACX_WARN(FI_LOG_MR, "error closing kdreg device: %s\n",
			  strerror(ret_errno));
		/* Not all of these map to fi_errno values */
		ret = -ret_errno;
		goto err_exit;
	}

	mrn->fd = -1;
	mrn->cntr = NULL;
err_exit:
	fastlock_release(&mrn->lock);

	return ret;
}

static inline int
kdreg_write(struct sstmacx_mr_notifier *mrn, void *buf, size_t len)
{
	int ret;

	ret = write(mrn->fd, buf, len);
	if ((ret < 0) || (ret != len)) {
		// Not all of these map to fi_errno values
		ret = -errno;
		SSTMACX_WARN(FI_LOG_MR, "kdreg_write failed: %s\n",
			  strerror(errno));
		return ret;
	}

	return FI_SUCCESS;
}

int
_sstmacx_notifier_monitor(struct sstmacx_mr_notifier *mrn,
		    void *addr, uint64_t len, uint64_t cookie)
{
	int ret;
	struct registration_monitor rm;

	fastlock_acquire(&mrn->lock);

	ret = notifier_verify_stuff(mrn);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_MR, "Invalid MR notifier\n");
		goto err_exit;
	}

	if (ret == 0) {
		SSTMACX_DEBUG(FI_LOG_MR, "monitoring %p (len=%lu) cookie=%lu\n",
			   addr, len, cookie);

		memset(&rm, 0, sizeof(rm));
		rm.type = REGISTRATION_MONITOR;
		rm.u.mon.addr = (uint64_t) addr;
		rm.u.mon.len = len;
		rm.u.mon.user_cookie = cookie;

		ret = kdreg_write(mrn, &rm, sizeof(rm));
	}

err_exit:
	fastlock_release(&mrn->lock);

	return ret;
}

int
_sstmacx_notifier_unmonitor(struct sstmacx_mr_notifier *mrn, uint64_t cookie)
{
	int ret;
	struct registration_monitor rm;

	fastlock_acquire(&mrn->lock);

	ret = notifier_verify_stuff(mrn);
	if (ret != FI_SUCCESS) {
		SSTMACX_WARN(FI_LOG_MR, "Invalid MR notifier\n");
		goto err_exit;
	}

	SSTMACX_DEBUG(FI_LOG_MR, "unmonitoring cookie=%lu\n", cookie);

	memset(&rm, 0, sizeof(rm));

	rm.type = REGISTRATION_UNMONITOR;
	rm.u.unmon.user_cookie = cookie;

	ret = kdreg_write(mrn, &rm, sizeof(rm));

err_exit:
	fastlock_release(&mrn->lock);

	return ret;
}

int
_sstmacx_notifier_get_event(struct sstmacx_mr_notifier *mrn, void* buf, size_t len)
{
	int ret, ret_errno;

	if ((mrn == NULL) || (buf == NULL) || (len <= 0)) {
		SSTMACX_WARN(FI_LOG_MR,
			  "Invalid argument to _sstmacx_notifier_get_event\n");
		return -FI_EINVAL;
	}

	fastlock_acquire(&mrn->lock);

	if (*(mrn->cntr) > 0) {
		SSTMACX_DEBUG(FI_LOG_MR, "reading kdreg event\n");
		ret = read(mrn->fd, buf, len);
		if (ret < 0) {
			ret_errno = errno;
			if (ret_errno != EAGAIN) {
				SSTMACX_WARN(FI_LOG_MR,
					  "kdreg event read failed: %s\n",
					  strerror(ret_errno));
			}
			/* Not all of these map to fi_errno values */
			ret = -ret_errno;
		}
	} else {
		SSTMACX_DEBUG(FI_LOG_MR, "nothing to read from kdreg :(\n");
		ret = -FI_EAGAIN;
	}

	fastlock_release(&mrn->lock);

	return ret;
}

#endif /* HAVE_KDREG */

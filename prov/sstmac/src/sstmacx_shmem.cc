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
 * Copyright (c) 2017 Cray Inc.  All rights reserved.
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


#include "sstmacx_shmem.h"

#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "rdma/fi_errno.h"
#include "sstmacx_util.h"

#define SSTMACX_DEFAULT_ACCESS_PERMS (0755)

extern uint32_t sstmacx_wait_shared_memory_timeout;

extern "C" int _sstmacx_shmem_create(
	const char *path,
	uint32_t size,
	int (*init_func)(const char *path, uint32_t size, void *region),
	struct sstmacx_shared_memory *region)
{
	int rc, fd, saved_errno, count;
	void *buffer;

	if (!region || !path) {
		SSTMACX_WARN(FI_LOG_FABRIC, "bad params, ret=-FINVAL");
		return -FI_EINVAL;
	}

	fd = open(path, O_CREAT | O_EXCL | O_RDWR, 
		SSTMACX_DEFAULT_ACCESS_PERMS);
	if (fd >= 0) {
		buffer = malloc(size);
		if (!buffer) {
			SSTMACX_INFO(FI_LOG_FABRIC,
				"failed to allocate memory for shared memory segment");
			return -FI_ENOMEM;
		}

		if (init_func) {
			rc = init_func(path, size, buffer);
			if (rc != 0) {
				free(buffer);
				return rc;
			}
		} else
			memset(buffer, 0, size);

		SSTMACX_INFO(FI_LOG_FABRIC,
			"initializing shared memory segment, path=%s\n",
			path);

		count = write(fd, buffer, size);
		if (count != size) {
			SSTMACX_WARN(FI_LOG_FABRIC,
				"failed to write to shared memory segment, "
				"expected=%d actual=%d\n",
				size, count);
			saved_errno = errno;
			close(fd);
			unlink(path);
			free(buffer);
			errno = saved_errno;
			return -saved_errno;
		}
		free(buffer);
		fchmod(fd,
			S_IRUSR | S_IWUSR |
			S_IRGRP | S_IWGRP |
			S_IROTH | S_IWOTH);
	} else {

		/* Unexpected error? */
		if (errno != EEXIST) {
			saved_errno = errno;
			SSTMACX_WARN(FI_LOG_FABRIC,
				"open() of shared memory segment failed, errno=%d\n",
				saved_errno);

			return -saved_errno;
		}

		/*
		 * The file was created by another process, but it might not yet
		 * be initialized.  Wait until it is.
		 */
		struct stat stat_info;
		int wait_count = 0;

		do {
			SSTMACX_INFO(FI_LOG_FABRIC,
				"stat() of shared memory segment.");
			rc = stat(path, &stat_info);
			if (rc != 0) {
				SSTMACX_DEBUG(FI_LOG_FABRIC,
					"stat() of shared memory segment "
					"failed, errno %d\n", errno);
				return -errno;
			}

			if (stat_info.st_size < size) {
				SSTMACX_INFO(FI_LOG_FABRIC,
					"Shared memory segment is %d bytes, "
					"waiting for it to be %d\n",
					stat_info.st_size, size);
				sleep(1);
				wait_count++;
			}
		} while ((stat_info.st_size < size) &&
			(wait_count < sstmacx_wait_shared_memory_timeout));

		/* If still not found, give up. */
		if (stat_info.st_size < size) {
			SSTMACX_WARN(FI_LOG_FABRIC,
				"can't open() shared memory segment.");
			return -ENODEV;
		}

		SSTMACX_INFO(FI_LOG_FABRIC, "open() of shared memory segment.");
		fd = open(path, O_RDWR, SSTMACX_DEFAULT_ACCESS_PERMS);
		if (fd < 0) {
			SSTMACX_WARN(FI_LOG_FABRIC,
				"open() of shared memory segment "
				"failed, errno %d\n", errno);
			return -errno;
		}
	}
	unlink(path);

	/* Get a pointer to the shared data structure. */
	region->addr = mmap(NULL, size,
		PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);

	if (region->addr == MAP_FAILED) {
		SSTMACX_WARN(FI_LOG_FABRIC, "failed to map fd\n");
		return -ENOTBLK;
	}

	region->size = size;
	return 0;
}

extern "C" int _sstmacx_shmem_destroy(struct sstmacx_shared_memory *region)
{
	if (!region)
		return -FI_EINVAL;

	if (region->addr == MAP_FAILED)
		return -FI_EINVAL;

	return munmap(region->addr, region->size);
}

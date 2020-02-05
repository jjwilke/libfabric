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

#include <stdio.h>
#include <stdlib.h>
#include <sstmac_pub.h>
#include "sstmacx.h"
#include "sstmacx_auth_key.h"
#include "sstmacx_util.h"
#include "ofi.h"
#include "ofi_prov.h"

/**
 * @note  To make sure that static linking will work, there must be at
 *        least one symbol in the file that requires sstmacx_init.o to have
 *        to be linked in when building the executable. This insures the
 *        ctor will run even with static linking.
 */

ofi_atomic32_t sstmacx_id_counter;
ofi_atomic32_t file_id_counter;
#ifdef ENABLE_DEBUG
/* don't think this needs to be in tls */
__thread pid_t sstmacx_debug_pid = ~(uint32_t) 0;
__thread uint32_t sstmacx_debug_tid = ~(uint32_t) 0;
ofi_atomic32_t sstmacx_debug_next_tid;
#endif

extern fastlock_t __sstmacx_alps_lock;

/**
 * Helper for static computation of SSTMAC CRC updating an intermediate crc
 * value based on the status of one bit in the data value.
 *
 * @param[in]  data  value to compute crc for
 * @param[in]  lcrc  intermediate crc to update
 * @param[in]  bit   which bit (in range [0-7]) of 'data' to test
 * @param[in]  xor   value to 'xor' into 'lcrc' iff bit 'bit' of 'data' is set
 *
 * @return updated intermediate crc
 */
#define CRC_HELPER(data, lcrc, bit, xor) (((((data)>>(bit))&1)*(xor))^(lcrc))

/* Parameterized helpers for each bit in SSTMAC CRC */
#define CRC_80(data, lcrc)              CRC_HELPER(data, lcrc, 7, 0x8c)
#define CRC_40(data, lcrc) CRC_80(data, CRC_HELPER(data, lcrc, 6, 0x46))
#define CRC_20(data, lcrc) CRC_40(data, CRC_HELPER(data, lcrc, 5, 0x23))
#define CRC_10(data, lcrc) CRC_20(data, CRC_HELPER(data, lcrc, 4, 0x9d))
#define CRC_08(data, lcrc) CRC_10(data, CRC_HELPER(data, lcrc, 3, 0xc2))
#define CRC_04(data, lcrc) CRC_08(data, CRC_HELPER(data, lcrc, 2, 0x61))
#define CRC_02(data, lcrc) CRC_04(data, CRC_HELPER(data, lcrc, 1, 0xbc))
#define CRC_01(data, lcrc) CRC_02(data, CRC_HELPER(data, lcrc, 0, 0x5e))

/* Static computation of 8-bit SSTMAC CRC of one 8-bit value */
#define CRC(data) ((uint8_t)CRC_01(data, 0))

/* Helpers for declaring large array of precomputed CRCs */
/* 4 elements starting at x */
#define CRCS_4(x)   CRC((x)), CRC((x)+1), CRC((x)+2), CRC((x)+3)

/* 16 elements starting at x: ie, CRC(x),...,CRC(x+15) */
#define CRCS_16(x)  CRCS_4((x)), CRCS_4((x)+4), \
		    CRCS_4((x)+8), CRCS_4((x)+12)

/* 64 elements starting at x: ie, CRC(x),...,CRC(x+63) */
#define CRCS_64(x)  CRCS_16((x)), CRCS_16((x)+16), \
		    CRCS_16((x)+32), CRCS_16((x)+48)

/* 256 elements starting at x: ie, CRC(x),...,CRC(x+255) */
#define CRCS_256(x) CRCS_64((x)), CRCS_64((x)+64), \
		    CRCS_64((x)+128), CRCS_64((x)+192)

uint8_t precomputed_crc_results[256] = { CRCS_256(0) };

#ifndef NDEBUG
static inline uint8_t __sstmac_crc_bits(uint8_t data)
{
  uint8_t lcrc = 0;

  if(data & 1)
    lcrc ^= 0x5e;
  if(data & 2)
    lcrc ^= 0xbc;
  if(data & 4)
    lcrc ^= 0x61;
  if(data & 8)
    lcrc ^= 0xc2;
  if(data & 0x10)
    lcrc ^= 0x9d;
  if(data & 0x20)
    lcrc ^= 0x23;
  if(data & 0x40)
    lcrc ^= 0x46;
  if(data & 0x80)
    lcrc ^= 0x8c;

  return lcrc;
}

static void __validate_precomputed_crcs(void)
{
	int i;
	uint8_t crc_i;

	for (i = 0; i < 256; i++) {
		crc_i = __sstmac_crc_bits(i);
		if (precomputed_crc_results[i] != crc_i) {
			SSTMACX_WARN(FI_LOG_FABRIC, "precomputed_crc_results[%d]"
				" initialized to 0x%x, expected 0x%x\n",
				i, (int)precomputed_crc_results[i], (int)crc_i);
			precomputed_crc_results[i] = crc_i;
		}
	}
}
#endif /* NDEBUG */

/**
 * Initialization function for performing global setup
 */
__attribute__((constructor))
void _sstmacx_init(void)
{
	static int called=0;

	if (called==0) {
		fastlock_init(&__sstmacx_alps_lock);

		if (sizeof(struct sstmacx_mr_key) != sizeof(uint64_t)) {
			SSTMACX_FATAL(FI_LOG_FABRIC,
				"sstmacx_mr_key size is invalid, "
				"size=%d expected=%d\n",
				sizeof(struct sstmacx_mr_key),
				sizeof(uint64_t));
			assert(0);
		}

		_sstmacx_auth_key_subsys_init();

		ofi_atomic_initialize32(&sstmacx_id_counter, 0);
		ofi_atomic_initialize32(&file_id_counter, 0);
#ifndef NDEBUG
		__validate_precomputed_crcs();
		ofi_atomic_initialize32(&sstmacx_debug_next_tid, 0);
#endif
		called = 1;
	}
}


#include <sys/compiler.h>

bool crc32c_arm64_available = false;

#ifdef ARCH_HAVE_CRC_CRYPTO

#define CRC32C3X8(ITR) \
	crc1 = __crc32cd(crc1, *((const u64 *)data + 42*1 + (ITR)));\
	crc2 = __crc32cd(crc2, *((const u64 *)data + 42*2 + (ITR)));\
	crc0 = __crc32cd(crc0, *((const u64 *)data + 42*0 + (ITR)));

#define CRC32C7X3X8(ITR) do {\
	CRC32C3X8((ITR)*7+0) \
	CRC32C3X8((ITR)*7+1) \
	CRC32C3X8((ITR)*7+2) \
	CRC32C3X8((ITR)*7+3) \
	CRC32C3X8((ITR)*7+4) \
	CRC32C3X8((ITR)*7+5) \
	CRC32C3X8((ITR)*7+6) \
	} while(0)

#include <arm_acle.h>
#include <arm_neon.h>

static bool crc32c_probed;

/*
 * Function to calculate reflected crc with PMULL Instruction
 * crc done "by 3" for fixed input block size of 1024 bytes
 */
u32 crc32c_arm64(unsigned char const *data, unsigned long length)
{
	signed long len = length;
	u32 crc = ~0;
	u32 crc0, crc1, crc2;

	/* Load two consts: K1 and K2 */
	const poly64_t k1 = 0xe417f38a, k2 = 0x8f158014;
	u64 t0, t1;

	while ((len -= 1024) >= 0) {
		/* Do first 8 bytes here for better pipelining */
		crc0 = __crc32cd(crc, *(const u64 *)data);
		crc1 = 0;
		crc2 = 0;
		data += sizeof(u64);

		/* Process block inline
		   Process crc0 last to avoid dependency with above */
		CRC32C7X3X8(0);
		CRC32C7X3X8(1);
		CRC32C7X3X8(2);
		CRC32C7X3X8(3);
		CRC32C7X3X8(4);
		CRC32C7X3X8(5);

		data += 42*3*sizeof(u64);

		/* Merge crc0 and crc1 into crc2
		   crc1 multiply by K2
		   crc0 multiply by K1 */

		t1 = (u64)vmull_p64(crc1, k2);
		t0 = (u64)vmull_p64(crc0, k1);
		crc = __crc32cd(crc2, *(const u64 *)data);
		crc1 = __crc32cd(0, t1);
		crc ^= crc1;
		crc0 = __crc32cd(0, t0);
		crc ^= crc0;

		data += sizeof(u64);
	}

	if (!(len += 1024))
		return crc;

	while ((len -= sizeof(u64)) >= 0) {
                crc = __crc32cd(crc, *(const u64 *)data);
                data += sizeof(u64);
        }

        /* The following is more efficient than the straight loop */
        if (len & sizeof(u32)) {
                crc = __crc32cw(crc, *(const u32 *)data);
                data += sizeof(u32);
        }
        if (len & sizeof(u16)) {
                crc = __crc32ch(crc, *(const u16 *)data);
                data += sizeof(u16);
        }
        if (len & sizeof(u8)) {
                crc = __crc32cb(crc, *(const u8 *)data);
        }

	return crc;
}

void crc32c_arm64_probe(void)
{
	if (!crc32c_probed) {
		crc32c_arm64_available = os_cpu_has(CPU_ARM64_CRC32C);
		crc32c_probed = true;
	}
}

#endif /* ARCH_HAVE_CRC_CRYPTO */

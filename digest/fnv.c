#include <sys/compiler.h>
#define FNV_PRIME	0x100000001b3ULL

/*
 * 64-bit fnv, but don't require 64-bit multiples of data. Use bytes
 * for the last unaligned chunk.
 */

static u64
fnv(const void *buf, u32 len, u64 hval)
{
	const u64 *ptr = buf;

	while (len) {
		hval *= FNV_PRIME;
		if (len >= sizeof(u64)) {
			hval ^= (u64) *ptr++;
			len -= sizeof(u64);
			continue;
		} else {
			const u8 *ptr8 = (const u8 *) ptr;
			u64 val = 0;
			int i;

			for (i = 0; i < len; i++) {
				val <<= 8;
				val |= (u8) *ptr8++;
			}
			hval ^= val;
			break;
		}
	}

	return hval;
}

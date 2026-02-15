/*
 * Minimal ephemeral-key randomness for the group keygen hooks. The passive
 * dissector rarely generates keys; when a backend's keygen is invoked it needs
 * a private scalar. Source it from the OS CSPRNG (getrandom(2), Linux) with a
 * /dev/urandom fallback. No crypto-library dependency.
 */

#ifndef __CRYPTO_GROUP_RANDOM_H__
#define __CRYPTO_GROUP_RANDOM_H__

#include <hpc/compiler.h>
#include <stddef.h>

#if defined(__linux__)
#include <sys/random.h>
#endif
#include <stdio.h>

static inline int
group_random(u8 *out, unsigned int len)
{
#if defined(__linux__)
	unsigned int off = 0;

	while (off < len) {
		ssize_t n = getrandom(out + off, len - off, 0);

		if (n < 0)
			break;
		off += (unsigned int)n;
	}
	if (off == len)
		return 0;
#endif
	{
		FILE *f = fopen("/dev/urandom", "rb");
		int ok;

		if (!f)
			return -1;
		ok = fread(out, 1, len, f) == len;
		fclose(f);
		return ok ? 0 : -1;
	}
}

#endif

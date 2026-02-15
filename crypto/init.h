#ifndef __OSS_CRYPTO_INIT_H__
#define __OSS_CRYPTO_INIT_H__

#include <hpc/compiler.h>

#if defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>

/*
 * OpenSSL ARM capability flags — must match vendor/openssl/crypto/arm_arch.h
 */
#define ARMV7_NEON   (1 << 0)
#define ARMV8_AES    (1 << 2)
#define ARMV8_SHA1   (1 << 3)
#define ARMV8_SHA256 (1 << 4)
#define ARMV8_PMULL  (1 << 5)
#define ARMV8_SHA512 (1 << 6)
#define ARMV8_SHA3   (1 << 11)

/*
 * Linux HWCAP bits for AArch64 (from asm/hwcap.h)
 */
#define HWCAP_AES    (1 << 3)
#define HWCAP_PMULL  (1 << 4)
#define HWCAP_SHA1   (1 << 5)
#define HWCAP_SHA2   (1 << 6)
#define HWCAP_SHA512 (1 << 21)
#define HWCAP_SHA3   (1 << 17)

extern unsigned int __attribute__((weak)) OPENSSL_armcap_P;

static inline void
crypto_init(void)
{
	unsigned long hwcap;

	if (!&OPENSSL_armcap_P)
		return;

	hwcap = getauxval(AT_HWCAP);

	OPENSSL_armcap_P = ARMV7_NEON;

	if (hwcap & HWCAP_AES)
		OPENSSL_armcap_P |= ARMV8_AES;
	if (hwcap & HWCAP_PMULL)
		OPENSSL_armcap_P |= ARMV8_PMULL;
	if (hwcap & HWCAP_SHA1)
		OPENSSL_armcap_P |= ARMV8_SHA1;
	if (hwcap & HWCAP_SHA2)
		OPENSSL_armcap_P |= ARMV8_SHA256;
	if (hwcap & HWCAP_SHA512)
		OPENSSL_armcap_P |= ARMV8_SHA512;
	if (hwcap & HWCAP_SHA3)
		OPENSSL_armcap_P |= ARMV8_SHA3;
}

#elif defined(__x86_64__) && defined(__linux__)

extern unsigned int OPENSSL_ia32cap_P[4];

static inline void
crypto_init(void)
{
}

#else

static inline void
crypto_init(void)
{
}

#endif

#endif

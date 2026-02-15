#include <hpc/compiler.h>

/*
 * Capability vector consumed by the OpenSSL / aws-lc x86_64 digest assembly.
 * A weak, hidden definition so the per-module copies (each OSSL digest module
 * links its own ossl_x86cap.o) merge into a single instance at link time, and
 * a full libcrypto's strong definition would still win if one is ever linked.
 */
/*
 * OpenSSL's x86_64 assembly indexes this vector beyond the first four words
 * (e.g. the SHA-512 AVX2 dispatch reads word 5 for the SHA-512 instruction
 * extension). Size it like OpenSSL's own OPENSSL_ia32cap_P so those reads stay
 * in bounds; the words we do not populate stay zero (feature absent).
 */
__attribute__((visibility("hidden"), weak))
unsigned int OPENSSL_ia32cap_P[8] = {0};

#if defined(CONFIG_CC_CPU_ACCEL_RUNTIME) && defined(__x86_64__)

#include <cpuid.h>

/*
 * Runtime CPU detection (CONFIG_CC_CPU_ACCEL_RUNTIME).
 *
 * The self-dispatching digest assembly reads OPENSSL_ia32cap_P in the raw CPUID
 * layout:
 *   [0] = CPUID leaf 1,        EDX
 *   [1] = CPUID leaf 1,        ECX
 *   [2] = CPUID leaf 7 (ECX=0), EBX
 *   [3] = CPUID leaf 7 (ECX=0), ECX
 *
 * We populate it once at startup so the accelerated code paths (SSSE3 / AVX /
 * AVX2 / SHA-NI) are selected according to the host CPU.
 */
static inline unsigned long long
crypto_xgetbv0(void)
{
	unsigned int lo, hi;

	__asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
	return ((unsigned long long)hi << 32) | lo;
}

static void __init__
crypto_x86_cpuid_setup(void)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned int leaf1_ecx;
	int ymm_enabled = 0;

	if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
		return;
	leaf1_ecx = ecx;
	OPENSSL_ia32cap_P[0] = edx;
	OPENSSL_ia32cap_P[1] = ecx;

	/*
	 * AVX state is only usable if the OS enabled XSAVE of the YMM registers
	 * (OSXSAVE = leaf1 ECX bit 27, and XCR0 bits 1:2 set). Mirror OpenSSL's
	 * OPENSSL_ia32_cpuid so we never advertise AVX/AVX2 the OS hasn't turned
	 * on — otherwise the AVX code path would fault.
	 */
	if ((leaf1_ecx >> 27) & 1)
		ymm_enabled = (crypto_xgetbv0() & 0x6) == 0x6;

	if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
		OPENSSL_ia32cap_P[2] = ebx;
		OPENSSL_ia32cap_P[3] = ecx;
	}

	/*
	 * OpenSSL's assembly reads ia32cap bit 43 (word 1, bit 11) as the AMD XOP
	 * flag, which comes from extended CPUID leaf 0x80000001 (ECX bit 11) — not
	 * leaf-1 ECX bit 11 (SDBG). Copying the raw leaf-1 value there can falsely
	 * advertise XOP and send the SHA-512 assembly down the XOP path (an illegal
	 * `vprotq`) on CPUs without it, so derive the bit from the extended leaf.
	 */
	OPENSSL_ia32cap_P[1] &= ~(1u << 11);
	if (__get_cpuid(0x80000001, &eax, &ebx, &ecx, &edx) && (ecx & (1u << 11)))
		OPENSSL_ia32cap_P[1] |= (1u << 11);

	if (!ymm_enabled) {
		OPENSSL_ia32cap_P[1] &= ~(1u << 28); /* AVX  (leaf1 ECX) */
		OPENSSL_ia32cap_P[2] &= ~(1u << 5);  /* AVX2 (leaf7 EBX) */
	}
}

#endif

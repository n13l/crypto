#include <hpc/compiler.h>

unsigned int __attribute__((weak)) OPENSSL_armcap_P = 0;

#if defined(CONFIG_CC_CPU_ACCEL_RUNTIME) && defined(__aarch64__)

#include <crypto/init.h>

/*
 * Runtime CPU detection (CONFIG_CC_CPU_ACCEL_RUNTIME).
 *
 * Populate OPENSSL_armcap_P from the kernel-exported hardware capabilities at
 * startup so the self-dispatching ARMv8 digest assembly selects the SHA1 /
 * SHA2 / SHA512 / SHA3 crypto-extension paths when the host CPU has them.
 * crypto_init() (crypto/init.h) reads getauxval(AT_HWCAP) and sets the bits.
 */
static void __init__
crypto_arm_cap_setup(void)
{
	crypto_init();
}

#endif

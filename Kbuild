subdir-y += crypto
subdir-y += modules
subdir-y += test
subdir-y += test/perf
subdir-ccflags-y += -I$(srctree)/hpc
subdir-ccflags-y += -I$(srctree)/crypto
subdir-ccflags-$(CONFIG_CRYPTO_SHA3_OSSL_X86_64) += -I$(srctree)/modules/digest/sha3-ossl-x86_64
subdir-ccflags-$(CONFIG_CRYPTO_SHA3_OSSL_ARMV8) += -I$(srctree)/modules/digest/sha3-ossl-armv8
subdir-ccflags-$(CONFIG_CRYPTO_SHA3_OSSL_X86_64_AVX2) += -I$(srctree)/modules/digest/sha3-ossl-x86_64-avx2

# test/digest links against modules/built-in.o
test: | modules
test/perf: | modules

subdir-y += crypto
subdir-y += modules
subdir-y += tools
subdir-ccflags-y += -I$(srctree)/hpc
subdir-ccflags-y += -I$(srctree)/crypto
subdir-ccflags-$(CONFIG_CRYPTO_SHA3_OSSL_X86_64) += -I$(srctree)/$(CRYPTO_DIR)/modules/digest/sha3-ossl-x86_64
subdir-ccflags-$(CONFIG_CRYPTO_SHA3_OSSL_ARMV8) += -I$(srctree)/$(CRYPTO_DIR)/modules/digest/sha3-ossl-armv8
subdir-ccflags-$(CONFIG_CRYPTO_SHA3_OSSL_X86_64_AVX2) += -I$(srctree)/$(CRYPTO_DIR)/modules/digest/sha3-ossl-x86_64-avx2

# tools link against modules/built-in.o
tools: | modules

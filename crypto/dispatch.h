#ifndef __CRYPTO_DISPATCH_H__
#define __CRYPTO_DISPATCH_H__

#include <hpc/compiler.h>
#include <hpc/array.h>
#include <hpc/mem/unaligned.h>
#include <crypto/digest.h>

#define ALG_TABLE(X) \

X(ALGORITHM_SHA1_160, arch_sha1_160) \
X(ALGORITHM_SHA2_224) \
X(ALGORITHM_SHA2_256) \
X(ALGORITHM_SHA2_384) \
X(ALGORITHM_SHA2_512) \
X(ALGORITHM_SHA3_224) \
X(ALGORITHM_SHA3_256) \
X(ALGORITHM_SHA3_384) \
X(ALGORITHM_SHA3_512) \
	

    X(SHA1, sha1_block) \
    X(SHA2, sha2_block) \
    X(SHA3, sha3_block) \
    X(SHA256, sha256_block)

#define AS_HANDLER_ARGS(name, fn) \
    _do_##name: fn(data, len, out); goto _dispatch_done;

#define BUILD_DISPATCH_ARGS(alg, data, len, out)         \
    do {                                                  \
        static const void *table[] = {                 \
            ALG_TABLE(AS_LABEL_ENTRY)                    \
        };                                               \
        goto *table[(alg) & ALG_MASK];                 \
        ALG_TABLE(AS_HANDLER_ARGS)                       \
    } while(0)

#endif

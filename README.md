# Intrusive Crypto Library

An intrusive cryptographic library designed to maximize performance and
efficiency by applying the same principles used in high-performance computing,
offensive security research, and embedded systems programming.

## Why Intrusive?

Writing high-performance code, researching small-footprint cryptographic
prototypes, and developing for embedded systems are fundamentally similar
disciplines. They all demand:

- **Intrusive operations** that embed crypto state directly into caller
  structures, eliminating indirection and pointer chasing.
- **Lock-free design** that avoids synchronization overhead and delegates
  concurrency responsibility to the caller who understands the access pattern.
- **Contiguous memory layout** that prefers flat, cache-friendly structures over
  scattered allocations for better caching and data locality.
- **No random memory access** so that sequential access patterns enable hardware
  prefetching and reduce cache misses.
- **Caller-owned security** where the caller manages buffer lifetimes,
  zeroization, and side-channel mitigations, because the library does not
  impose policy.

These are the same constraints that make small-footprint cryptographic payloads
efficient, make embedded firmware fit in constrained memory, and make HPC
kernels saturate hardware throughput. This library is designed around them.

## Build System

The build system is based on Kbuild, the same infrastructure known from the
Linux kernel. It provides strong, well-documented dependency tracking for all
capabilities and algorithms. Every feature, every algorithm backend, and every
platform-specific optimization is expressed as a Kconfig symbol with explicit
dependencies, so the build always pulls in exactly what is needed and nothing
more.

This means a minimal static build configured with a single algorithm contains
no dead code, no unused backends, and no unnecessary abstractions. The result
can be as small as a few kilobytes of machine code. Combined with freestanding
support (no C library required), the library can target bare-metal and deeply
embedded environments where every byte counts.

## Build Modes

The Kconfig/Kbuild system supports two distinct build strategies that serve
opposite ends of the flexibility and performance spectrum:

### Dynamic Modules (`CONFIG_MODULES=y`)

When configured for dynamic module support, the library provides maximum
modularity and flexibility:

- Algorithm implementations are built as loadable shared objects (`.so`).
- Selected algorithms can still be built statically and inlined into the
  caller, retaining full optimization even when dynamic module support is
  enabled.
- Multiple implementations can coexist and be loaded at runtime.

### Static Build (`CONFIG_MODULES` disabled)

When everything is built statically, there is no additional cost:

- A single algorithm implementation is selected at configure time.
- Hot paths use branchless, constant-time access.
- Algorithms can be inlined directly into the caller, eliminating function call
  overhead entirely.
- A minimal build may still use regular function calls, but when optimized for
  speed the compiler is free to inline the full algorithm into the hot path,
  removing all branches and indirection.

## Freestanding Support

The library can be built without any C library dependency. A minimal `nolibc`
layer provides raw syscall wrappers for supported architectures (x86_64,
ARM64, ARM, i386, s390, PowerPC), making it suitable for bare-metal firmware,
bootloaders, and constrained embedded targets.

## Minimal Overhead Interface

- No buffer copies. The caller provides input and output buffers directly.
- No dynamic allocation. All state is stack or caller allocated, avoiding
  heap fragmentation and allocation latency.

While dynamic allocation supports handling integers of any size, it may affect
performance and introduce potential side-channel vulnerabilities.

## Hardware Acceleration with Software Fallback

- Leverages platform-specific assembly (ARM64, x86_64) for optimized
  permutations and transforms.
- Multiple implementation backends: aws-lc verified assembly, OpenSSL
  platform-optimized assembly, and generic C fallback.
- Architecture selection is handled at build time via Kconfig, not at runtime.

## Cryptographic Hooks

Implements cryptographic and entropy-level hooks based on different types of
signatures that are independent of specific implementations and act as a crypto
operation state machine. This supports research, proof of concept development,
and prototyping of focused crypto primitives without any additional
complexities.

## Supported Algorithms

| Family | Implementations |
|--------|----------------|
| SHA-3 (Keccak) | Generic C, OpenSSL assembly, aws-lc assembly |
| SHA-2 (256/512) | Generic C, OpenSSL assembly, aws-lc assembly |
| SHA-1 | Generic C, OpenSSL assembly, aws-lc assembly |
| HMAC | Via modules |
| HKDF | Via modules |
| PRF | Via modules |

## Architecture Support

| Architecture | Assembly Backends |
|-------------|-------------------|
| x86_64 | OpenSSL, aws-lc |
| ARM64 | OpenSSL, aws-lc |
| Others | Generic C fallback |

## Project Structure

```
crypto/          core headers and inline hot-path API
modules/         algorithm implementations (static or dynamic)
  digest/        SHA-1, SHA-2, SHA-3 implementations
  hmac/          HMAC constructions
  hkdf/          HKDF key derivation
  prf/           pseudo-random functions
  transform/     symmetric transforms
arch/            architecture-specific support (x86, arm64, ...)
hpc/             high-performance computing primitives (compiler, memory, data structures)
vendor/          third-party sources (aws-lc, OpenSSL)
test/            test programs
scripts/         build system support scripts
```

## Verified Cryptography

When `CONFIG_CRYPTO_VERIFIED=y`, only formally verified or audited
implementations are available for selection, currently restricted to aws-lc
provided assembly. This ensures that the cryptographic core has been through
rigorous formal verification.

## Build in Action

```
git clone git@github.com:n13l/crypto.git
cd crypto/
git submodule update --init
```

![Demo](.github/assets/demo.gif)

## Algorithm Expansion

When the algorithm is known at build time, calling the typed API directly lets
the compiler inline the entire implementation into the caller's hot path,
eliminating function call overhead, vtable lookups, and all indirection.

```c
    u8 digest[SHA3_256_DIGEST_SIZE] = {};
    struct sha3 sha3;

    sha3_256_init(&sha3);
    sha3_256_update(&sha3, (const u8 *)"", 0);
    sha3_256_final(&sha3, digest);
```

## Branchless Constant-Time Dispatch (static module)

When the algorithm is selected at runtime, the generic digest interface
dispatches without function pointer calls or conditional branches. The
dispatcher resolves to the correct implementation through a constant-time,
branchless, streamlined array without misprediction penalties.

```c
    struct digest digest = {};
    u8 out[MAX_DIGEST_SIZE];

    digest_init(&digest, SHA3_256);
    digest_update(&digest, (const u8 *)"", 0);
    digest_final(&digest, out);
```

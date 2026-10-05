#!/bin/sh
# Configure OpenSSL vendor library based on Kbuild CONFIG_ variables.
#
# Usage: configure-openssl.sh <srctree> <objtree> <auto.conf>
#
# This script reads CONFIG_ variables from the Kbuild auto.conf file
# and translates them into OpenSSL ./Configure arguments, then runs
# OpenSSL's Configure in the output directory.

set -e

srctree="$1"
objtree="$2"
autoconf="$3"

if [ -z "$srctree" ] || [ -z "$objtree" ] || [ -z "$autoconf" ]; then
	echo "Usage: $0 <srctree> <objtree> <auto.conf>" >&2
	exit 1
fi

srctree=$(cd "$srctree" && pwd)
objtree=$(cd "$objtree" && pwd)
autoconf="${objtree}/${autoconf}"

OPENSSL_SRC="${srctree}/vendor/openssl"
OPENSSL_OUT="${objtree}/vendor/openssl"

if [ ! -f "${OPENSSL_SRC}/Configure" ]; then
	echo "  ERROR: OpenSSL source not found at ${OPENSSL_SRC}" >&2
	exit 1
fi

. "$autoconf" 2>/dev/null || true

ossl_target=""
case "${ARCH}" in
	x86_64|x86)
		if [ "${CONFIG_X86_64}" = "y" ] || [ "${ARCH}" = "x86_64" ]; then
			ossl_target="linux-x86_64"
		else
			ossl_target="linux-elf"
		fi
		;;
	arm64)
		ossl_target="linux-aarch64"
		;;
	arm)
		ossl_target="linux-armv4"
		;;
	s390)
		ossl_target="linux64-s390x"
		;;
	powerpc)
		ossl_target="linux-ppc64le"
		;;
	*)
		ossl_target="linux-generic64"
		;;
esac

# PLATFORM is kbuild's spelling (scripts/host_from_sys.sh): linux, macos,
# windows. It used to be compared against "darwin" here, which kbuild never
# says, so a macOS build was configured as Linux.
case "${PLATFORM}" in
macos|darwin)
	case "${ARCH}" in
		arm64) ossl_target="darwin64-arm64-cc" ;;
		x86_64|x86) ossl_target="darwin64-x86_64-cc" ;;
		*) ossl_target="darwin64-arm64-cc" ;;
	esac
	;;
windows)
	case "${ARCH}" in
		arm64) ossl_target="mingwarm64" ;;
		i386) ossl_target="mingw" ;;
		*) ossl_target="mingw64" ;;
	esac
	;;
esac

# The perlasm flavour of the one script run by hand below; the rest are made
# by OpenSSL's own Makefile, which knows its target's flavour itself.
case "${PLATFORM}" in
macos|darwin)	perlasm_flavour="macosx" ;;
windows)	perlasm_flavour="mingw64" ;;
*)		perlasm_flavour="elf" ;;
esac

OSSL_ARGS=""

if [ "${CONFIG_DEBUG_INFO}" = "y" ]; then
	OSSL_ARGS="${OSSL_ARGS} --debug"
fi

if [ "${CONFIG_CC_OPTIMIZE_FOR_SIZE}" = "y" ]; then
	OSSL_ARGS="${OSSL_ARGS} -Os"
fi

if [ "${CONFIG_OPENSSL_NO_ASM}" = "y" ]; then
	OSSL_ARGS="${OSSL_ARGS} no-asm"
fi

if [ "${CONFIG_OPENSSL_NO_SHARED}" != "y" ]; then
	OSSL_ARGS="${OSSL_ARGS} no-shared"
fi

if [ "${CONFIG_OPENSSL_NO_TESTS}" != "n" ]; then
	OSSL_ARGS="${OSSL_ARGS} no-tests"
fi

if [ "${CONFIG_OPENSSL_FIPS}" = "y" ]; then
	OSSL_ARGS="${OSSL_ARGS} enable-fips"
fi

# The toolchain. kbuild exports CC, AR, NM and CPP already prefixed
# ($(CROSS_COMPILE)gcc, ...), and OpenSSL prepends --cross-compile-prefix to
# each tool it is given — so handing it both made
# x86_64-linux-gnu-x86_64-linux-gnu-gcc. With a prefix, CC goes in bare, the
# rest are left for OpenSSL to name, and it adds the prefix to all of them once.
# Under LLVM=1 there is no prefix to add: CC is clang with --target in it
# (scripts/Makefile.target), and the binutils are LLVM's, named outright.
if [ -n "${LLVM}" ]; then
	unset CPP LD AS
	export CC AR NM
	export RANLIB="${AR%llvm-ar*}llvm-ranlib${AR#*llvm-ar}"
	[ "${PLATFORM}" = "windows" ] && \
		export RC="${AR%llvm-ar*}llvm-rc${AR#*llvm-ar}"
elif [ -n "${CROSS_COMPILE}" ]; then
	OSSL_ARGS="${OSSL_ARGS} --cross-compile-prefix=${CROSS_COMPILE}"
	unset AR NM RANLIB RC CPP LD AS
	export CC="${CC#${CROSS_COMPILE}}"
fi

if [ -n "${CONFIG_OPENSSL_EXTRA_ARGS}" ]; then
	extra=$(echo "${CONFIG_OPENSSL_EXTRA_ARGS}" | sed 's/^"//;s/"$//')
	OSSL_ARGS="${OSSL_ARGS} ${extra}"
fi

OSSL_ARGS="${OSSL_ARGS} --prefix=${OPENSSL_OUT}/install"
OSSL_ARGS="${OSSL_ARGS} --openssldir=${OPENSSL_OUT}/ssl"

mkdir -p "${OPENSSL_OUT}"

stamp="${OPENSSL_OUT}/.configured"
# The toolchain is part of the recipe in a cross or LLVM build, where it is
# what changes between one configure and the next; a native build hashes what
# it always has, so an existing tree is not reconfigured for nothing.
recipe="${ossl_target} ${OSSL_ARGS}"
if [ -n "${LLVM}${CROSS_COMPILE}" ]; then
	recipe="${recipe} CC=${CC} AR=${AR} NM=${NM} RANLIB=${RANLIB}"
fi
args_hash=$(echo "${recipe}" | sha1sum | cut -d' ' -f1)

if [ -f "${stamp}" ] && [ -f "${OPENSSL_OUT}/Makefile" ] && \
   [ "$(cat "${stamp}")" = "${args_hash}" ]; then
	exit 0
fi

echo "  CONFIG  vendor/openssl (${ossl_target})"

cd "${OPENSSL_OUT}"
if [ "${KBUILD_VERBOSE}" = "1" ]; then
	"${OPENSSL_SRC}/Configure" ${ossl_target} ${OSSL_ARGS}
else
	"${OPENSSL_SRC}/Configure" ${ossl_target} ${OSSL_ARGS} > /dev/null 2>&1
fi

echo "${args_hash}" > "${stamp}"

# Generate SHA assembly files for the target architecture
asm_stamp="${OPENSSL_OUT}/.asm_generated"
if [ ! -f "${asm_stamp}" ] || [ "${stamp}" -nt "${asm_stamp}" ]; then
	echo "  GEN     vendor/openssl (asm-${ARCH})"
	cd "${OPENSSL_OUT}"
	case "${ARCH}" in
		x86_64|x86)
			make -f Makefile crypto/sha/keccak1600-x86_64.s \
				crypto/sha/sha1-x86_64.s \
				crypto/sha/sha256-x86_64.s \
				crypto/sha/sha512-x86_64.s \
				2>&1 | if [ "${KBUILD_VERBOSE}" != "1" ]; then cat > /dev/null; else cat; fi
			perl "${OPENSSL_SRC}/crypto/sha/asm/keccak1600-avx2.pl" \
				"${perlasm_flavour}" \
				crypto/sha/keccak1600-avx2.S \
				2>&1 | if [ "${KBUILD_VERBOSE}" != "1" ]; then cat > /dev/null; else cat; fi
			;;
		arm64)
			make -f Makefile crypto/sha/keccak1600-armv8.S \
				crypto/sha/sha1-armv8.S \
				crypto/sha/sha256-armv8.S \
				crypto/sha/sha512-armv8.S \
				2>&1 | if [ "${KBUILD_VERBOSE}" != "1" ]; then cat > /dev/null; else cat; fi
			;;
		arm)
			make -f Makefile crypto/sha/sha1-armv4-large.S \
				crypto/sha/sha256-armv4.S \
				crypto/sha/sha512-armv4.S \
				crypto/sha/keccak1600-armv4.S \
				2>&1 | if [ "${KBUILD_VERBOSE}" != "1" ]; then cat > /dev/null; else cat; fi
			;;
		s390)
			make -f Makefile crypto/sha/sha1-s390x.S \
				crypto/sha/sha256-s390x.S \
				crypto/sha/sha512-s390x.S \
				crypto/sha/keccak1600-s390x.S \
				2>&1 | if [ "${KBUILD_VERBOSE}" != "1" ]; then cat > /dev/null; else cat; fi
			;;
		powerpc)
			make -f Makefile crypto/sha/sha1-ppc.s \
				crypto/sha/sha256-ppc.s \
				crypto/sha/sha512-ppc.s \
				crypto/sha/keccak1600-ppc64.s \
				2>&1 | if [ "${KBUILD_VERBOSE}" != "1" ]; then cat > /dev/null; else cat; fi
			;;
	esac
	touch "${asm_stamp}"
fi

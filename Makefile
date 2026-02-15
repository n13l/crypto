# crypto top-level Makefile.
#
# When built standalone, the crypto package is its own srctree, so its module
# tree lives at ./modules. CRYPTO_DIR names the package sources relative to
# srctree; CRYPTO_MODULES names where the module tree is built (relative to
# srctree and objtree). A host project (e.g. un) overrides both to point at
# the crypto submodule and its relocated module build dir.
CRYPTO_DIR := .
CRYPTO_MODULES := modules
export CRYPTO_DIR CRYPTO_MODULES
include vendor/kbuild/Makefile

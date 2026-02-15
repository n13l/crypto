subdir-y += crypto
subdir-y += modules
subdir-y += test
subdir-ccflags-y += -I$(srctree)/hpc
subdir-ccflags-y += -I$(srctree)/crypto

# test/digest links against modules/built-in.o
test: | modules

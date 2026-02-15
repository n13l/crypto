#ifndef __TEST_NOLIBC_H__
#define __TEST_NOLIBC_H__

#include <hpc/compiler.h>

#if defined(__x86_64__)

#define __NR_exit  60
#define __NR_write 1

static inline long
__syscall3(long nr, long a1, long a2, long a3)
{
	long ret;
	__asm__ volatile("syscall"
		: "=a"(ret)
		: "a"(nr), "D"(a1), "S"(a2), "d"(a3)
		: "rcx", "r11", "memory");
	return ret;
}

#elif defined(__aarch64__)

#define __NR_exit  93
#define __NR_write 64

static inline long
__syscall3(long nr, long a1, long a2, long a3)
{
	register long x8 __asm__("x8") = nr;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	__asm__ volatile("svc #0"
		: "=r"(x0)
		: "r"(x8), "0"(x0), "r"(x1), "r"(x2)
		: "memory");
	return x0;
}

#elif defined(__i386__)

#define __NR_exit  1
#define __NR_write 4

static inline long
__syscall3(long nr, long a1, long a2, long a3)
{
	long ret;
	__asm__ volatile("int $0x80"
		: "=a"(ret)
		: "a"(nr), "b"(a1), "c"(a2), "d"(a3)
		: "memory");
	return ret;
}

#elif defined(__arm__)

#define __NR_exit  1
#define __NR_write 4

static inline long
__syscall3(long nr, long a1, long a2, long a3)
{
	register long r7 __asm__("r7") = nr;
	register long r0 __asm__("r0") = a1;
	register long r1 __asm__("r1") = a2;
	register long r2 __asm__("r2") = a3;
	__asm__ volatile("swi #0"
		: "=r"(r0)
		: "r"(r7), "0"(r0), "r"(r1), "r"(r2)
		: "memory");
	return r0;
}

#elif defined(__s390x__) || defined(__s390__)

#define __NR_exit  1
#define __NR_write 4

static inline long
__syscall3(long nr, long a1, long a2, long a3)
{
	register long r1 __asm__("r1") = nr;
	register long r2 __asm__("r2") = a1;
	register long r3 __asm__("r3") = a2;
	register long r4 __asm__("r4") = a3;
	__asm__ volatile("svc 0"
		: "=d"(r2)
		: "d"(r1), "0"(r2), "d"(r3), "d"(r4)
		: "memory");
	return r2;
}

#elif defined(__powerpc64__) || defined(__powerpc__)

#define __NR_exit  1
#define __NR_write 4

static inline long
__syscall3(long nr, long a1, long a2, long a3)
{
	register long r0 __asm__("r0") = nr;
	register long r3 __asm__("r3") = a1;
	register long r4 __asm__("r4") = a2;
	register long r5 __asm__("r5") = a3;
	__asm__ volatile("sc"
		: "=r"(r3)
		: "r"(r0), "0"(r3), "r"(r4), "r"(r5)
		: "memory", "cr0");
	return r3;
}

#else
#error "unsupported architecture"
#endif

static inline void _noreturn
_exit(int status)
{
	__syscall3(__NR_exit, status, 0, 0);
	__builtin_unreachable();
}

static inline long
write(int fd, const void *buf, unsigned long count)
{
	return __syscall3(__NR_write, fd, (long)buf, count);
}

void *memcpy(void *dst, const void *src, unsigned long n)
{
	u8 *d = dst;
	const u8 *s = src;
	while (n--)
		*d++ = *s++;
	return dst;
}

void *memset(void *dst, int c, unsigned long n)
{
	u8 *d = dst;
	while (n--)
		*d++ = (u8)c;
	return dst;
}

int main(int argc, char *argv[]);

void _noreturn
_start(void)
{
	int rc = main(0, (char *[]){ 0 });
	_exit(rc);
}

#endif

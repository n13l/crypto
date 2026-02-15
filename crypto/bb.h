/*
 * The MIT License (MIT)         Copyright (c) 2017 Daniel Kubec <niel@rtfm.cz>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __GENERIC_BSD_BBUF_H__
#define __GENERIC_BSD_BBUF_H__

#include <hpc/compiler.h>
#include <string.h>

#define PDU_MOVE(pdu, avail, size) ({\
	pdu = (__typeof__(pdu))(((u8*)(pdu)) + (size)); (avail) -= size; \
})

/* Move buffer pointer backward and update available space */
#define PDU_MOVE_BACK(pdu, avail, size) ({\
	pdu = (__typeof__(pdu))(((u8*)pdu) - size); avail += size; \
})

#define SAFE_MOVE_PDU(payload, avail, size) \
	payload = (__typeof__(payload))(((u8*)payload) + size); avail -= size; \

/* Safe backward movement with type preservation */
#define BACK_PDU(payload, avail, size) \
	payload = (__typeof__(payload))(((u8*)payload) - size); avail += size; \

/*
 * Safety Check Macros
 * Verify buffer boundaries before operations
 */

/* Check if requested size fits in available space */
#define CHECK_AVAIL(size, avail, error) if (size > avail) { return -1; }

/*
 * Read Operation Macros
 * Safe reading operations with boundary checks
 */

/* Read single byte with bounds checking
 * @lv: source buffer
 * @avail: available space
 * @u8_num: destination variable
 */
#define SAFE_READ_U8(lv, avail, u8_num)         \
	CHECK_AVAIL(1, avail, -1);           \
	u8_num = *((u8*)lv); \
	SAFE_MOVE_PDU(lv, avail, 1) 

/* Read 16-bit value with bounds checking */
#define SAFE_READ_U16(payload, avail, val)         \
	CHECK_AVAIL(2, avail, -1);           \
	val = *((u16*)payload); \
	SAFE_MOVE_PDU(payload, avail, 2)

/* Copy buffer with bounds checking */
#define SAFE_READ_BUF(lv, avail, ptr, size) \
	CHECK_AVAIL(size, avail, -1); \
	memcpy((ptr), lv, size); \
	SAFE_MOVE_PDU(lv, avail, size)

#define SAFE_SAFE_MOVE_PDU(lv, avail, size) \
	CHECK_AVAIL(size, avail, -1); \
	SAFE_MOVE_PDU(lv, avail, size)

#define SAFE_READ_U16_REQUIRE(payload, avail, val, expected) \
	SAFE_READ_U16(payload, avail, val); \
	REQUIRE_U16(val, expected)

#define MOVE_U16_REQUIRE(payload, avail, expected) \
	CHECK_AVAIL(2, avail, -1); \
	REQUIRE_U16((*((u16*)payload)), expected); \
	SAFE_MOVE_PDU(payload, avail, 2); \

#define SAFE_MOVE_PDU_REQUIRE(payload, avail, buf, size) \
	CHECK_AVAIL(size, avail, -1); \
	REQUIRE_BUF(payload, buf, size); \
	SAFE_MOVE_PDU(payload, avail, size);

#define SAFE_WRITE_U16(payload, avail, val) \
	CHECK_AVAIL(2, avail, -1); \
	*((u16*)payload) = (u16)val; \
	SAFE_MOVE_PDU(payload, avail, 2)

#define SAFE_WRITE_BUF(payload, avail, buf, len) \
	CHECK_AVAIL(len, avail, -1); \
	memcpy(payload, buf, len); \
	SAFE_MOVE_PDU(payload, avail, len)


/* opaque info for memory allocation */
struct mm;

/* byte buffer */
struct bb {
	uint8_t *ptr;
	size_t len;
};

struct mb {
	size_t capacity;
	struct mm *mm;
	union { struct bb bb; };

};

#define bb_init(__addr, __size) \
  ({ struct bb __bb = (struct bb){.addr = __addr, .len = __size }; __bb; }) 

/*
 * Concatenate a string to an bbuf buffer
 *
 * @param bb pointer to the bbuf struct
 * @param str the string to append; must be at least len bytes long
 * @param len the number of characters of *str to concatenate to the buf
 * @note bb->len will be set to the length of the new string
 * @note bb->buf will be null-terminated
 */

void bb_strmemcat(struct bb *bb, const char *str, size_t len);

/*
 * Concatenate a string to an bbuf buffer
 *
 * @param bb pointer to the bbuf struct
 * @param str the string to append
 * @note bb->len will be set to the length of the new string
 */

#define bb_strcat(bb, str) bb_strmemcat(bb, str, strlen(str))

static inline void *
bb_unpack(struct bb *bb, size_t size)
{
	uint8_t *p = (uint8_t *)bb->ptr;
	bb->ptr += size;
	bb->len  -= size;
	return p;
}

static inline char *
bstrtok(char *buf, size_t *size, char *sep, char **ptr)
{
        char *p = buf = buf ? buf: *ptr;
        for (; *size; p++, (*size)--) {
                if (*p != *sep)
                        continue;
                *p = 0;
                *ptr = p + 1;
                (*size)--;
                return buf;
        }

        if (p == buf)
                return NULL;
        else
                *p = 0;
        return buf;
}

static inline size_t
bstrlcpy(char *dst, const char *src, size_t size)
{
	char *d = dst;
	const char *s = src;
	size_t n = size;

	if (n != 0) {
		while (--n != 0)
			if ((*d++ = *s++) == '\0')
				break;
	}

	if (n == 0) {
		if (size != 0)
			*d = '\0';
		while (*s++);
	}

	return(s - src - 1);
}

static inline size_t
bstrlcat(char *dst, const char *src, size_t size)
{
	char *d = dst;
	const char *s = src;
	int dlen, n = size;

	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = size - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));
}

#endif

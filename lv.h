/* LV (Length-Value) data encoding */

#ifndef __LV_FORMAT_H__
#define __LV_FORMAT_H__

#include <sys/compiler.h>
#include <mem/unaligned.h>

/* Run block on fixed size string */
#define VISIT_LV_STR_U8(payload, avail, lv, block)

/* Run block on fixed size string in native order */
#define VISIT_LV_STR_U16(payload, avail, lv, block)

/* Run block on fixed size string in big endian order */
#define VISIT_LV_STR_BE16(payload, avail, lv, block) \

/* Run block on fixed size string in little endian order */
#define VISIT_LV_STR_LE16(payload, avail, lv, block) \

/* Run block on fixed size string in native order */
#define VISIT_LV_STR_U32(payload, avail, lv, block)

/* Run block on fixed size string in big endian order */
#define VISIT_LV_STR_BE32(payload, avail, lv, block) \

/* Run block on fixed size string in little endian order */
#define VISIT_LV_STR_LE32(payload, avail, lv, block) \

/* Run block on fixed size string in native order */
#define VISIT_LV_STR_U64(payload, avail, lv, block)

/* Run block on fixed size string in big endian order */
#define VISIT_LV_STR_BE64(payload, avail, lv, block) \

/* Run block on fixed size string in little endian order */
#define VISIT_LV_STR_LE64(payload, avail, lv, block) \

/* Run block on fixed size buffer */
#define VISIT_LV_BUF_U8(payload, avail, lv, block)

/* Run block on fixed size buffer in native order */
#define VISIT_LV_BUF_U16(payload, avail, lv, block)

/* Run block on fixed size buffer in big endian order */
#define VISIT_LV_BUF_BE16(lv, avail, ptr, len, block)                \
{                                                                    \
	CHECK_AVAIL(2, avail, -1); \
	u16 len = be16_cpu(*((be16*)lv)); u8 *ptr = (((u8*)lv) + 2); \
	CHECK_AVAIL(len, avail, -1); \
	if (len > 0) { \
		block                            \
	} \
}

/* Run block on fixed size buffer in little endian order */
#define VISIT_LV_BUF_LE16(payload, avail, lv, block) \

/* Run block on fixed size buffer in native order */
#define VISIT_LV_BUF_U32(payload, avail, lv, block)

/* Run block on fixed size buffer in big endian order */
#define VISIT_LV_BUF_BE32(payload, avail, lv, block) \

/* Run block on fixed size buffer in little endian order */
#define VISIT_LV_BUF_LE32(payload, avail, lv, block) \

/* Run block on fixed size buffer in native order */
#define VISIT_LV_BUF_U64(payload, avail, lv, block)

/* Run block on fixed size buffer in big endian order */
#define VISIT_LV_BUF_BE64(payload, avail, lv, block) \

/* Run block on fixed size buffer in little endian order */
#define VISIT_LV_BUF_LE64(payload, avail, lv, block) \

/* Run block on array of big endian 16 byte wors where first contains size. */
#define VISIT_LV_ARY_BE16(lv, avail, num16, len, block) \
({ \
	CHECK_AVAIL(2, avail, -1);                                 \
	u16 len = be16_cpu(*((be16*)lv)); lv = (((u8*)lv) + 2); \
	CHECK_AVAIL((len * sizeof(be16)), avail, -1);                         \
	MOVE_PDU(lv, avail, 2);\
	for (unsigned __i = 0; __i < len; __i++) { \
		u16 num16 = be16_cpu(*((be16*)lv)); \
		block; \
		MOVE_PDU(lv, avail, sizeof(be16));  \
	}\
});

#define VISIT_AVAIL(avail, size, block) if (size <= avail) { block }

#define VISIT_STRUCT(payload, avail, type, val, block) \
{ \
	type val = (type)payload; \
	CHECK_AVAIL(sizeof(*val), avail, -1); \
	MOVE_PDU(payload, avail, sizeof(*val)); \
	block \
}

#define VISIT_MAYBE_STRUCT(payload, avail, type, val, block) \
{ \
	type val = (type)payload; \
	VISIT_AVAIL(avail, sizeof(*val), { \
		MOVE_PDU(payload, avail, sizeof(*val)); \
		block \
	}); \
}

#define VISIT_LV_BUF_BE24(lv, avail, ptr, size, block) \
{ \
	u32 size = be24_cpu(((u8*)lv)); \
	u8 *ptr = (((u8*)lv) + 3); \
	CHECK_AVAIL(size, avail, -1);           \
	if (size > 0) { \
		block \
	} \
}

#define REQUIRE_U16(val, expected) \
	if (expected != val) return -1

#define REQUIRE_BUF(buf, val, size) \
	if (memcmp(buf, val, size)) return -1

#define READ_BE16(lv, avail, val)         \
	CHECK_AVAIL(2, avail, -1);           \
	val = be16_cpu(*((be16*)lv)); \
	MOVE_PDU(lv, avail, 2) 

#define READ_BE24(lv, avail, val)         \
	CHECK_AVAIL(3, avail, -1);           \
	val = be24_cpu(lv); \
	MOVE_PDU(lv, avail, 3) 

#define READ_BE32(lv, avail, val)         \
	CHECK_AVAIL(4, avail, -1);           \
	val = be32_cpu(*((u32*)(lv))); \
	MOVE_PDU(lv, avail, 4) 

#define READ_BE16_REQUIRE(lv, avail, val, expected) \
	READ_BE16(lv, avail, val); \
	REQUIRE_U16(val, expected)

#define READ_LV_BUF_U8(lv, avail, ptr, size, maxsize) \
	CHECK_AVAIL(1, avail, -1); \
	size = *((u8*)lv); lv = (((u8*)lv) + 1); \
	CHECK_AVAIL(size, avail, -1);                                 \
	CHECK_LV_SIZE_LIMIT(size, maxsize); \
	if (size > 0) { \
		memcpy(ptr, ((u8*)lv), size); \
		MOVE_PDU(lv, avail, size); \
	} \

#define READ_LV_BUF_BE16(lv, avail, ptr, size, maxsize) \
	CHECK_AVAIL(sizeof(be16), avail, -1); \
	size = be16_cpu(*((be16*)lv)); lv = (((u8*)lv) + 2); \
	CHECK_AVAIL(size, avail, -1);                                 \
	CHECK_LV_SIZE_LIMIT(size, maxsize); \
	if (size > 0) { \
		memcpy(ptr, (((u8*)lv) + 2), size); \
		MOVE_PDU(lv, avail, size); \
	} \

#define SKIP_LV_BUF_BE16(lv, avail) \
{ \
	CHECK_AVAIL(2, avail, -1); \
	u16 size_not_used = be16_cpu(*((be16*)lv)); \
	MOVE_PDU(lv, avail, 2);\
	CHECK_AVAIL(size_not_used, avail, -1);                                 \
	if (size_not_used > 0) { \
		MOVE_PDU(lv, avail, size_not_used); \
	} \
} \

#define GET_LV_BUF_BE16(lv, avail, ptr, size) \
	CHECK_AVAIL(2, avail, -1);                                 \
	size = be16_cpu(*((be16*)lv)); \
	CHECK_AVAIL(size, avail, -1);                                 \
	MOVE_PDU(lv, avail, 2);\
	if (size > 0) { \
		ptr = (((u8*)lv)); \
		MOVE_PDU(lv, avail, size); \
	} \

#define GET_LV_BUF_BE32(lv, avail, ptr, size) \
	CHECK_AVAIL(4, avail, -1);                                 \
	size = be32_cpu(*((be16*)lv)); \
	CHECK_AVAIL(size, avail, -1);                                 \
	MOVE_PDU(lv, avail, 4);\
	if (size > 0) { \
		ptr = (((u8*)lv)); \
		MOVE_PDU(lv, avail, size); \
	} \

#define CHECK_LV_SIZE_LIMIT(size, limit) \
	if (size > limit) return -EPROTO

#endif

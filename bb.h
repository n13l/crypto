#ifndef __CRYPTO_BB_PARSER_H__
#define __CRYPTO_BB_PARSER_H__

#include <sys/compiler.h>
#include <mem/unaligned.h>

#define PDU_MOVE(pdu, avail, size) ({\
	pdu = (__typeof__(pdu))(((u8*)(pdu)) + (size)); (avail) -= size; \
})

#define PDU_MOVE_BACK(pdu, avail, size) ({\
	pdu = (__typeof__(pdu))(((u8*)pdu) - size); avail += size; \
})

#define MOVE_PDU(payload, avail, size) \
	payload = (__typeof__(payload))(((u8*)payload) + size); avail -= size; \

#define BACK_PDU(payload, avail, size) \
	payload = (__typeof__(payload))(((u8*)payload) - size); avail += size; \

#define CHECK_AVAIL(size, avail, error) if (size > avail) { return -1; }

/* Read byte and move forward. */
#define READ_U8(lv, avail, u8_num)         \
	CHECK_AVAIL(1, avail, -1);           \
	u8_num = *((u8*)lv); \
	MOVE_PDU(lv, avail, 1) 

/* Read byte and move forward. */
#define READ_U16(payload, avail, val)         \
	CHECK_AVAIL(2, avail, -1);           \
	val = *((u16*)payload); \
	MOVE_PDU(payload, avail, 2)

#define READ_BUF(lv, avail, ptr, size) \
	CHECK_AVAIL(size, avail, -1); \
	memcpy((ptr), lv, size); \
	MOVE_PDU(lv, avail, size)

#define MOVE_BUF(lv, avail, size) \
	CHECK_AVAIL(size, avail, -1); \
	MOVE_PDU(lv, avail, size)

#define READ_U16_REQUIRE(payload, avail, val, expected) \
	READ_U16(payload, avail, val); \
	REQUIRE_U16(val, expected)

#define MOVE_U16_REQUIRE(payload, avail, expected) \
	CHECK_AVAIL(2, avail, -1); \
	REQUIRE_U16((*((u16*)payload)), expected); \
	MOVE_PDU(payload, avail, 2); \

#define MOVE_BUF_REQUIRE(payload, avail, buf, size) \
	CHECK_AVAIL(size, avail, -1); \
	REQUIRE_BUF(payload, buf, size); \
	MOVE_PDU(payload, avail, size);

#define WRITE_U16(payload, avail, val) \
	CHECK_AVAIL(2, avail, -1); \
	*((u16*)payload) = (u16)val; \
	MOVE_PDU(payload, avail, 2)

#define WRITE_BUF(payload, avail, buf, len) \
	CHECK_AVAIL(len, avail, -1); \
	memcpy(payload, buf, len); \
	MOVE_PDU(payload, avail, len)

#endif

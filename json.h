/*
 * The MIT License (MIT)         Copyright (c) 2016 Daniel Kubec <niel@rtfm.cz>
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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#ifndef __CRYPTO_JSON_H__
#define __CRYPTO_JSON_H__

#include <sys/compiler.h>

__BEGIN_DECLS

#ifdef USE_NLOHMANN

#define JSON_DOC_DECL(doc) nlohmann::json doc
#define JSON_VAL_DECL(val) nlohmann::json val

#define JSON_DOC_CTOR(doc, pdu, bytes) ({\
	doc = nlohmann::json::parse((char *)pdu, ((char*)pdu) + bytes, false); \
})

#define JSON_DOC_DTOR(doc)
#define JSON_DOC_CHECK(doc) ({ unsigned __rv = doc.is_discarded(); __rv; })

#define VISIT_JSON(doc, key, obj, block)                   \
	for (auto it = doc.find(key); it != doc.end(); ) { \
		auto obj = it.value(); block ; break;      \
	}

#define VISIT_JSON_STR(doc, key, str, size, block) \
	VISIT_JSON(doc, key, val, { \
		if (!val.is_string() && !val.is_binary()) break; \
		std::string cxxstr = val.get<std::string>(); \
		const char *str = cxxstr.c_str(); \
		unsigned size = cxxstr.size(); \
		if (cxxstr.empty()) break; \
		block ; \
	});

#define VISIT_JSON_OBJ(doc, key, obj, block) \
	VISIT_JSON(doc, key, obj, { \
		if (!obj.is_object()) break; \
		block ; \
	});

#define VISIT_JSON_ARRAY(doc, key, obj, block) \
	VISIT_JSON(doc, key, obj, { \
		if (!obj.is_array()) break; \
		block \
	});
#endif

#ifdef USE_YYJSON

#define DEFINE_JSON_DOC(doc) yyjson_doc *doc
#define DEFINE_JSON_VAL(val) yyjson_val *val

#define JSON_DOC_DECL(doc) yyjson_doc *doc##_object; yyjson_val *doc; yyjson_read_err doc##_err;
#define JSON_VAL_DECL(val) yyjson_val *val

#define JSON_TYPE_DOC yyjson_doc *
#define JSON_TYPE yyjson_val *

#define JSON_DOC_CTOR(doc, pdu, bytes) ({ \
	yyjson_read_err doc##_error; \
	doc##_object = yyjson_read_opts((char*)pdu, bytes, 0, NULL, &doc##_err); \
	doc = yyjson_doc_get_root(doc##_object); \
})

#define JSON_DOC_DTOR(doc) yyjson_doc_free(doc##_object);
#define JSON_DOC_CHECK(doc) ({ unsigned __rv = (doc##_object == NULL); __rv; })

#define VISIT_JSON_ERROR(doc, code, str) ({ \
})

#define VISIT_JSON(doc, key, obj, block) ({ \
	yyjson_val *obj = yyjson_obj_get(doc, key); \
	if (obj) { block } \
})

#define VISIT_JSON_TYPE(obj, type, block) ({ \
	if (obj && yyjson_is_##type(obj)) { block } \
})

#define VISIT_JSON_ARRAY(doc, key, obj, block) \
	VISIT_JSON(doc, key, arr, { \
		if (arr && yyjson_is_arr(arr)) { \
			yyjson_val *obj; yyjson_arr_iter iter; \
			yyjson_arr_iter_init(arr, &iter); \
			while ((obj = yyjson_arr_iter_next(&iter))) { \
				block \
			} \
		} \
	})

#define VISIT_JSON_STR(doc, key, str, size, block) \
	VISIT_JSON(doc, key, val, { \
		if (val && yyjson_is_str(val)) { \
			const char *str = yyjson_get_str(val); \
			unsigned size = yyjson_get_len(val); \
			block \
		} \
	})

#define VISIT_JSON_INT(doc, key, num, block) \
	VISIT_JSON(doc, key, val, { \
		if (val && yyjson_is_int(val)) { \
			int num = yyjson_get_int(val); \
			block \
		} \
	})

#define VISIT_JSON_OBJECT(doc, key, obj, block) \
	VISIT_JSON(doc, key, obj, { \
		if (yyjson_is_obj(obj)) { \
			block \
		} \
	})

#define JSON_SET_INT(doc, key, num) \
	VISIT_JSON(doc, key, val, { \
		if (val && yyjson_is_int(val)) { \
			num = yyjson_get_int(val); \
		} \
	})

#define JSON_SET_STR(doc, key, str, len, max_len) \
	VISIT_JSON_STR(obj, key, __str, __len, { \
		snprintf(str, max_len, "%.*s", __len, __str); len = __len; \
	});

#define JSON_TYPE_DESC(obj) yyjson_get_type_desc(obj)

#define JSON_TRACE(obj) ({ \
	yyjson_obj_iter iter; yyjson_obj_iter_init(obj, &iter); yyjson_val *k, *v; \
	debug1("json %s(%u): %s", yyjson_get_str(obj), \
	       (unsigned)yyjson_get_len(obj), yyjson_get_type_desc(obj)); \
	while ((k = yyjson_obj_iter_next(&iter))) { \
		v = yyjson_obj_iter_get_val(k); \
		debug1("json %s: %s", yyjson_get_str(k), yyjson_get_type_desc(v)); \
	} \
})

#endif

__END_DECLS

#endif

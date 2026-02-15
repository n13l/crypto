/* AES cipher registration is backend-independent (it only uses the AES
 * free-function API), so the aws-lc x86_64 backend reuses the canonical
 * registration glue verbatim. */
#include "../aes/module.c"

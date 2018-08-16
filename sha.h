#ifndef SHA_H
#define SHA_H

// For regular platform with openssl
#include <openssl/sha.h>

/*
// For the nRF52 platform
#include "crys_hash.h"
#define SHA512(src, len, dst) \
	CRYS_HASH(CRYS_HASH_SHA512_mode, src, len, (uint32_t*)dst)
*/

#endif //SHA_H

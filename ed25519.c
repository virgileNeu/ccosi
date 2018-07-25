#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "type.h"
#include "edwards25519.h"
#include "ed25519.h"
#include "sha.h"
#include "my_random.h"

const size_t PublicKeySize = 32;
const size_t PrivateKeySize = 64;
const size_t SignatureSize = 64;

// Public returns the PublicKey corresponding to priv.
void PrivateKey_Public(const byte* privateKey, byte* publicKey) {
    memcpy(publicKey, &privateKey[32], PublicKeySize);
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
void GenerateKey(byte* privateKey, byte* publicKey) {

	fillRandom(privateKey, 32);

    byte digest[64];

    SHA512(privateKey, 32, digest);

	digest[0] &= 248;
	digest[31] &= 127;
    digest[31] |= 64;

	ExtendedGroupElement A;
	byte hBytes[32];
	memcpy(hBytes, digest, 32);
	GeScalarMultBase(&A, hBytes);
	byte publicKeyBytes[32];
	ExtendedGroupElement_ToBytes(&A, publicKeyBytes);

	memcpy(&privateKey[32], publicKeyBytes, 32);
	memcpy(publicKey, publicKeyBytes, 32);
}

// Sign signs the message with privateKey and returns a signature. It will
// panic if len(privateKey) is not PrivateKeySize.
void Sign(byte* privateKey, byte* message, size_t message_len, byte* signature) {

	byte digest1[64], messageDigest[64], hramDigest[64];
	byte expandedSecretKey[32];

    SHA512(&privateKey[32], 32, digest1);

	memcpy(expandedSecretKey, digest1, 32);
	expandedSecretKey[0] &= 248;
	expandedSecretKey[31] &= 63;
	expandedSecretKey[31] |= 64;

    byte* tohash = calloc(64+message_len, 1);
    memcpy(tohash, &digest1[32], 32);
    memcpy(&tohash[32], message, message_len);

    SHA512(tohash, 32+message_len, messageDigest);

	byte messageDigestReduced[32];
	ScReduce(messageDigestReduced, messageDigest);
	ExtendedGroupElement R;
	GeScalarMultBase(&R, messageDigestReduced);

	byte encodedR[32];
	ExtendedGroupElement_ToBytes(&R, encodedR);

    memcpy(tohash, encodedR, 32);
    memcpy(&tohash[32], &privateKey[32], 32);
    memcpy(&tohash[64], message, message_len);

    SHA512(tohash, 64+message_len, hramDigest);

    free(tohash);

	byte hramDigestReduced[32];

	ScReduce(hramDigestReduced, hramDigest);

	byte s[32];
	ScMulAdd(s, hramDigestReduced, expandedSecretKey, messageDigestReduced);

	memcpy(signature, encodedR, 32);
	memcpy(&signature[32], s, 32);
}

// Verify reports whether sig is a valid signature of message by publicKey. It
// will panic if len(publicKey) is not PublicKeySize.
bool Verify(byte* publicKey, byte* message, size_t message_len, byte* sig) {
	if ((sig[63]&224) != 0) {
		return false;
	}

	ExtendedGroupElement A;
	byte publicKeyBytes[PublicKeySize];
	memcpy(publicKeyBytes, publicKey, PublicKeySize);
	if (!ExtendedGroupElement_FromBytes(&A, publicKeyBytes)) {
		return false;
	}
	FeNeg(A.X, A.X);
	FeNeg(A.T, A.T);

    byte* tohash = calloc(32+PublicKeySize+message_len, 1);

    memcpy(tohash, sig, 32);
    memcpy(&tohash[32], publicKey, PublicKeySize);
    memcpy(&tohash[32+PublicKeySize], message, message_len);

	byte digest[64];

    SHA512(tohash, 32+PublicKeySize+message_len, digest);
    free(tohash);

	byte hReduced[32];
	ScReduce(hReduced, digest);

	ProjectiveGroupElement R;
	byte b[32];

	memcpy(b, &sig[32], 32);
	GeDoubleScalarMultVartime(&R, hReduced, &A, b);

	byte checkR[32];
	ProjectiveGroupElement_ToBytes(&R, checkR);
    return memcmp(sig, checkR, 32) == 0;
}

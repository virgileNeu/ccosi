#ifndef ED25519_H
#define ED25519_H

#include "type.h"
#include <stdlib.h>
#include <stdbool.h>
#include "my_random.h"

const unsigned int CommitmentSize;

// PublicKeySize is the size, in bytes, of public keys as used in this package.
const size_t PublicKeySize;
// PrivateKeySize is the size, in bytes, of private keys as used in this package
const size_t PrivateKeySize;
// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
const size_t SignatureSize;

void PrivateKey_Public(const byte* privateKey, byte* publicKey);
void GenerateKey(byte* privateKey, byte* publicKey);
void Sign(byte* privateKey, byte* message, size_t message_len, byte* signature);
bool Verify(byte* publicKey, byte* message, size_t message_len, byte* sig);

#endif //ED25519_H

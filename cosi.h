#ifndef COSI_H
#define COSI_H

#include <stdbool.h>
#include <stdlib.h>
#include "ed25519.h"
#include "edwards25519.h"

typedef bool MaskBit;

const MaskBit Enabled;
const MaskBit Disabled;

const unsigned int SignaturePartSize;

typedef struct Cosigners_t {
    ExtendedGroupElement* keys;
    unsigned int n_keys;
    byte* mask;
    unsigned int threshold;
    ExtendedGroupElement aggr;
} Cosigners;

typedef struct Secret_t {
    byte reduced[32];
    bool valid;
} Secret;

void Cosigners_Init(Cosigners* cosigners, byte** publicKeys, size_t n_keys, byte* mask, size_t mask_len);
unsigned int Cosigners_CountTotal(Cosigners* cosigners);
unsigned int Cosigners_CountEnabled(Cosigners* cosigners);
void Cosigners_SetMask(Cosigners* cosigners, byte* mask, size_t mask_len);
unsigned int Cosigners_Mask(Cosigners* cosigners, byte* mask);
unsigned int Cosigners_MaskLen(Cosigners* cosigners);
void Cosigners_SetMaskBit(Cosigners* cosigners, unsigned int index, MaskBit value);
bool Cosigners_MaskBit(Cosigners* cosigners, unsigned int index);
void Cosigners_AggregatePublicKeys(Cosigners* cosigners, byte* aggKeys);
bool Cosigners_AggregateCommit(Cosigners* cosigners, byte** commits, size_t n_commits, byte* aggCommits);
unsigned int Cosigners_CosignatureLen(Cosigners* cosigners);
void Cosigners_AggregateSignature(Cosigners* cosigners, byte* aggCommits, byte** sigParts, byte* Cosignature);
bool Cosigners_VerifyPart(Cosigners* cosigners, byte* message, size_t message_len, byte* aggR, unsigned int signer_index, byte* signer_commitment, byte* signer_part);
bool Cosigners_CheckThreshold(Cosigners* cosigners);
bool Cosigners_Verify(Cosigners* cosigners, byte* message, size_t message_len, byte* signature, size_t signature_len);
bool Cosigners_verify(Cosigners* cosigners, byte* message, size_t message_len, byte* aggR, byte* sigR, byte* sigS, ExtendedGroupElement* sigA);
void Cosigners_SetThresold(Cosigners* cosigners, unsigned int threshold);

void Commit(byte* commitment, Secret* secret);

void Cosign(byte* Privatekey, Secret* secret, byte* message, size_t message_len, byte* aggKeys, byte* aggCommits, byte* SignaturePart);

bool VerifyCosignature(byte** publicKeys, size_t n_keys, unsigned int threshold, byte* message, size_t message_len, byte* signature, size_t signature_len);

#endif //COSI_H

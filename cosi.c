#include "ed25519.h"
#include "cosi.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "edwards25519.h"
#include "sha.h"
#include <stdio.h>

const MaskBit Enabled = false;
const MaskBit Disabled = true;

const unsigned int CommitmentSize = 32;

const unsigned int SignaturePartSize = 32;

void Cosigners_Init(Cosigners* cosigners, byte** publicKeys, size_t n_keys, byte* mask, size_t mask_len) {
    byte publicKeyBytes[32];
    cosigners->keys = calloc(n_keys, sizeof(ExtendedGroupElement));
    cosigners->n_keys = n_keys;
    cosigners->threshold = n_keys;
    for (size_t i = 0; i < n_keys; i++) {
        memcpy(publicKeyBytes, publicKeys[i], PublicKeySize);
        if (!ExtendedGroupElement_FromBytes(&cosigners->keys[i], publicKeyBytes)) {
            exit(-1);
        }
    }

    size_t l = (n_keys+7)>>3;
    cosigners->mask = calloc(l, 1);
    for (size_t i = 0; i < l; i++) {
        cosigners->mask[i] = 0xff;
    }
    ExtendedGroupElement_Zero(&cosigners->aggr);
    Cosigners_SetMask(cosigners, mask, mask_len);
}

void Cosigners_Deinit(Cosigners* cosigners) {
    free(cosigners->keys);
    cosigners->keys = NULL;
    free(cosigners->mask);
    cosigners->mask = NULL;
}

unsigned int Cosigners_CountTotal(Cosigners* cosigners) {
    return cosigners->n_keys;
}

unsigned int Cosigners_CountEnabled(Cosigners* cosigners) {
    unsigned int count = 0;
	for (unsigned int i = 0; i < cosigners->n_keys; i++) {
		if ((cosigners->mask[i>>3]&(1<<(unsigned int)(i&7))) == 0) {
			count++;
		}
	}
	return count;
}

void Cosigners_SetMask(Cosigners* cosigners, byte* mask, size_t masklen) {
    for (unsigned int i = 0; i < cosigners->n_keys; i++) {
        int byt = i >> 3;
        byte bit = (byte)1 << (i&7);
        if (mask != NULL && (byt < masklen) && ((mask[byt]&bit) != 0)) {
            // Participant i disabled in new mask.
            if ((cosigners->mask[byt]&bit) == 0) {
                cosigners->mask[byt] |= bit; // disable it
                ExtendedGroupElement_Sub(&cosigners->aggr, &cosigners->aggr, &cosigners->keys[i]);
            }
        } else {
            // Participant i enabled in new mask.
            if ((cosigners->mask[byt]&bit) != 0) {
                cosigners->mask[byt] &= ~bit; // enable it
                ExtendedGroupElement_Add(&cosigners->aggr, &cosigners->aggr, &cosigners->keys[i]);
            }
        }
    }
}

unsigned int Cosigners_Mask(Cosigners* cosigners, byte* mask) {
    unsigned int len = Cosigners_MaskLen(cosigners);
    memcpy(mask, cosigners->mask, len);
    return len;
}

unsigned int Cosigners_MaskLen(Cosigners* cosigners) {
    return (cosigners->n_keys+7)>>3;
}

void Cosigners_SetMaskBit(Cosigners* cosigners, unsigned int index, MaskBit value) {
    if (index >= cosigners->n_keys) {
        return;
    }
    unsigned int byt = index >> 3;
    byte bit = (byte)(1) << (index&7);
	if (value == Disabled) { // disable
		if ((cosigners->mask[byt]&bit) == 0) { // was enabled
			cosigners->mask[byt] |= bit;// disable it
			ExtendedGroupElement_Sub(&cosigners->aggr, &cosigners->aggr, &cosigners->keys[index]);
		}
	} else { // enable
		if ((cosigners->mask[byt]&bit) != 0) { // was disabled
			cosigners->mask[byt] &= ~bit;
			ExtendedGroupElement_Add(&cosigners->aggr, &cosigners->aggr, &cosigners->keys[index]);
		}
	}
}

bool Cosigners_MaskBit(Cosigners* cosigners, unsigned int index) {
    unsigned int byt = index >> 3;
	byte bit = (byte)(1) << (index&7);
	return (cosigners->mask[byt] & bit) != 0;
}

void Cosigners_AggregatePublicKeys(Cosigners* cosigners, byte* aggKeys) {
    ExtendedGroupElement_ToBytes(&cosigners->aggr, aggKeys);
}

bool Cosigners_AggregateCommit(Cosigners* cosigners, byte** commits,
    size_t n_commits, byte* aggCommits) {
    ExtendedGroupElement aggR, indivR;
	byte commitBytes[32];

	ExtendedGroupElement_Zero(&aggR);
	for (unsigned int i = 0; i < cosigners->n_keys; i++) {
		if (Cosigners_MaskBit(cosigners, i) == Enabled) {
    		memcpy(commitBytes, commits[i], CommitmentSize);
    		if (!ExtendedGroupElement_FromBytes(&indivR, commitBytes)) {
                memset(aggCommits, 0, CommitmentSize);
    			return false;
    		}
    		ExtendedGroupElement_Add(&aggR, &aggR, &indivR);
        }
	}

	ExtendedGroupElement_ToBytes(&aggR, aggCommits);
    return true;
}

unsigned int Cosigners_CosignatureLen(Cosigners* cosigners) {
    return SignatureSize+Cosigners_MaskLen(cosigners);
}

byte scOne[32] = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

void Cosigners_AggregateSignature(Cosigners* cosigners, byte* aggCommits, byte** sigParts, byte* cosignature) {
	byte aggS[32], indivS[32];
    memset(aggS, 0, 32);
	for (unsigned int i = 0; i < cosigners->n_keys; i++) {
		if (Cosigners_MaskBit(cosigners, i) == Enabled) {
    		memcpy(indivS, sigParts[i], 32);
    		ScMulAdd(aggS, aggS, scOne, indivS);
        }
	}

    memcpy(cosignature, aggCommits, CommitmentSize);
    memcpy(&cosignature[32], aggS, 32);
    Cosigners_Mask(cosigners, &cosignature[64]);
}

bool Cosigners_VerifyPart(Cosigners* cosigners, byte* message, size_t message_len, byte* aggR, unsigned int signer_index, byte* signer_commitment, byte* signer_part) {
    if(signer_index >= cosigners->n_keys) {
        return false;
    }
    return Cosigners_verify(cosigners, message, message_len, aggR, signer_commitment, signer_part, &cosigners->keys[signer_index]);
}
bool Cosigners_CheckThreshold(Cosigners* cosigners) {
    return cosigners->threshold <= Cosigners_CountEnabled(cosigners);
}
bool Cosigners_Verify(Cosigners* cosigners, byte* message, size_t message_len, byte* signature, size_t signature_len) {
	if (signature_len != SignatureSize + Cosigners_MaskLen(cosigners)) {
		return false;
	}

	// Update our mask to reflect which cosigners actually signed
	Cosigners_SetMask(cosigners, &signature[64], signature_len - SignatureSize);

	// Check that this represents a sufficient set of signers
	if (!Cosigners_CheckThreshold(cosigners)) {
		return false;
	}

	return Cosigners_verify(cosigners, message, message_len, signature, signature, &signature[32], &cosigners->aggr);
}


bool Cosigners_verify(Cosigners* cosigners, byte* message, size_t message_len, byte* aggR, byte* sigR, byte* sigS, ExtendedGroupElement* sigA) {
    if ((sigS[31]&224) != 0) {
		return false;
	}


	// Compute the digest against aggregate public key and commit
	byte aggK[32];
	ExtendedGroupElement_ToBytes(&cosigners->aggr, aggK);

    size_t l = 64+message_len;
    byte* tohash = calloc(l, 1);
    memcpy(tohash, aggR, 32);
    memcpy(&tohash[32], aggK, 32);
    memcpy(&tohash[64], message, message_len);

	byte digest[64];

    SHA512(tohash, l, digest);

    free(tohash);

	byte hReduced[32];
	ScReduce(hReduced, digest);
	// The public key used for checking is whichever part was signed
	FeNeg(sigA->X, sigA->X);
	FeNeg(sigA->T, sigA->T);

    ProjectiveGroupElement projR;
    memset(&projR, 0, sizeof(projR));
	byte b[32];
	memcpy(b, sigS, 32);
	GeDoubleScalarMultVartime(&projR, hReduced, sigA, b);

	byte checkR[32];
    memset(checkR, 0, 32);
	ProjectiveGroupElement_ToBytes(&projR, checkR);
    int res = memcmp(sigR, checkR, 32);
    //restore the signature
    FeNeg(sigA->X, sigA->X);
	FeNeg(sigA->T, sigA->T);
    return res == 0;
}

void Cosigners_SetThresold(Cosigners* cosigners, unsigned int threshold) {
    cosigners->threshold = threshold;
}

void Commit(byte* commitment, Secret* secret) {
    byte secretFull[64];
	fillRandom(secretFull, 64);

	ScReduce(secret->reduced, secretFull);
	secret->valid = true;

	// compute R, the individual Schnorr commit to our one-time secret
	ExtendedGroupElement R;
	GeScalarMultBase(&R, secret->reduced);

	ExtendedGroupElement_ToBytes(&R, commitment);
}

void Cosign(byte* privateKey, Secret* secret, byte* message, size_t message_len, byte* aggKeys, byte* aggCommits, byte* signaturePart) {
	if (!secret->valid) {
		exit(-2);
	}

	byte digest1[64];
    SHA512(privateKey, 32, digest1);

    byte expandedSecretKey[32];
	memcpy(expandedSecretKey, digest1, 32);
	expandedSecretKey[0] &= 248;
	expandedSecretKey[31] &= 63;
	expandedSecretKey[31] |= 64;

	byte hramDigest[64];

    size_t len = PublicKeySize+CommitmentSize+message_len;
    byte* tohash = calloc(len, 1);
    memcpy(tohash, aggCommits, CommitmentSize);
    memcpy(&tohash[CommitmentSize], aggKeys, PublicKeySize);
    memcpy(&tohash[CommitmentSize+PublicKeySize], message, message_len);

    SHA512(tohash, len, hramDigest);
    free(tohash);

	byte hramDigestReduced[32];
	ScReduce(hramDigestReduced, hramDigest);

	// Produce our individual contribution to the collective signature
	ScMulAdd(signaturePart, hramDigestReduced, expandedSecretKey,
		secret->reduced);

	// Erase the one-time secret and make darn sure it gets used only once,
	// even if a buggy caller invokes Cosign twice after a single Commit
	secret->valid = false;
}

bool VerifyCosignature(byte** publicKeys, size_t n_keys, unsigned int threshold, byte* message, size_t message_len, byte* signature, size_t signature_len) {
    if (signature_len < SignatureSize) {
		return false;
	}
    Cosigners cosi;
    Cosigners_Init(&cosi, publicKeys, n_keys, &signature[64], signature_len-SignatureSize);
    Cosigners_SetThresold(&cosi, threshold);
	bool ok = Cosigners_Verify(&cosi, message, message_len, signature, signature_len);
    Cosigners_Deinit(&cosi);
    return ok;
}

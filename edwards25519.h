
#ifndef EDWARDS25519_H
#define EDWARDS25519_H

#include "type.h"
#include <stdint.h>
#include <stdbool.h>

const int32_t zero[10];

void FeZero(int32_t* fe);
void FeOne(int32_t* fe);
void FeAdd(int32_t* dst, const int32_t* a, const int32_t* b);
void FeSub(int32_t* dst, const int32_t* a, const int32_t* b);
void FeCopy(int32_t* dst, const int32_t* src);
void FeCMove(int32_t* f, const int32_t* g, int32_t b);
int64_t load3(byte* in);
int64_t load4(byte* in);
void FeFromBytes(int32_t* dst, byte* src);
void FeToBytes(byte* dst, int32_t* h);
byte FeIsNegative(int32_t* f);
int32_t FeIsNonZero(int32_t* f);
void FeNeg(int32_t* dst, const int32_t* src);
void FeCombine(int32_t* h, int64_t h0, int64_t h1, int64_t h2, int64_t h3, int64_t h4, int64_t h5, int64_t h6, int64_t h7, int64_t h8, int64_t h9);
void FeMul(int32_t* h, const int32_t*  f, const int32_t*  g);
void feSquare(int32_t* f, int64_t* h0, int64_t* h1, int64_t* h2, int64_t* h3, int64_t* h4, int64_t* h5, int64_t* h6, int64_t* h7, int64_t* h8, int64_t* h9);
void FeSquare(int32_t* h, int32_t*  f);
void FeSquare2(int32_t* h, int32_t*  f);
void FeInvert(int32_t* out, int32_t*  z);
void fePow22523(int32_t* out, int32_t* z);


typedef struct ProjectiveGroupElement_t{
    int32_t X[10], Y[10], Z[10];
} ProjectiveGroupElement;


typedef struct ExtendedGroupElement_t{
    int32_t X[10], Y[10], Z[10], T[10];
} ExtendedGroupElement;

typedef struct CompletedGroupElement_t{
    int32_t X[10], Y[10], Z[10], T[10];
} CompletedGroupElement;

typedef struct PreComputedGroupElement_t{
    int32_t yPlusX[10], yMinusX[10], xy2d[10];
} PreComputedGroupElement;

typedef struct CachedGroupElement_t{
    int32_t yPlusX[10], yMinusX[10], Z[10], T2d[10];
} CachedGroupElement;

void ProjectiveGroupElement_Zero(ProjectiveGroupElement* p);
void ProjectiveGroupElement_Double(ProjectiveGroupElement* p, CompletedGroupElement* r);
void ProjectiveGroupElement_ToBytes(ProjectiveGroupElement* p, byte* s);

void ExtendedGroupElement_Zero(ExtendedGroupElement* p);
void ExtendedGroupElement_Double(ExtendedGroupElement* p,CompletedGroupElement* r);
void ExtendedGroupElement_Add(ExtendedGroupElement* p, ExtendedGroupElement* a, ExtendedGroupElement* b);
void ExtendedGroupElement_Sub(ExtendedGroupElement* p, ExtendedGroupElement* a, ExtendedGroupElement* b);
void ExtendedGroupElement_ToCached(ExtendedGroupElement* p, CachedGroupElement* r);
void ExtendedGroupElement_ToProjective(ExtendedGroupElement* p, ProjectiveGroupElement* r);
void ExtendedGroupElement_ToBytes(ExtendedGroupElement* p, byte* s);
bool ExtendedGroupElement_FromBytes(ExtendedGroupElement* p, byte* s);

void CompletedGroupElement_ToProjective(CompletedGroupElement* p, ProjectiveGroupElement* r);
void CompletedGroupElement_ToExtended(CompletedGroupElement* p, ExtendedGroupElement* r);
void PreComputedGroupElement_Zero(PreComputedGroupElement* p);
void PreComputedGroupElement_CMove(PreComputedGroupElement* t, PreComputedGroupElement* u, int32_t b);

void geAdd(CompletedGroupElement* r, ExtendedGroupElement* p, CachedGroupElement* q);
void geSub(CompletedGroupElement* r, ExtendedGroupElement* p, CachedGroupElement* q);
void geMixedAdd(CompletedGroupElement* r, ExtendedGroupElement* p, PreComputedGroupElement* q);
void geMixedSub(CompletedGroupElement* r, ExtendedGroupElement* p, PreComputedGroupElement* q);
void slide(int8_t* r, byte* a);
void GeDoubleScalarMultVartime(ProjectiveGroupElement* r, byte* a, ExtendedGroupElement* A, byte* b);
int32_t equal(int32_t b, int32_t c);
int32_t negative(int32_t b);
void PreComputedGroupElementCMove(PreComputedGroupElement* t, PreComputedGroupElement* u, int32_t b);
void selectPoint(PreComputedGroupElement* t, int32_t pos, int32_t b);
//a have length 32
void GeScalarMultBase(ExtendedGroupElement* h, byte* a);
void ScMulAdd(byte* s, byte*  a, byte*  b, byte* c);
void ScReduce(byte* out, byte* s);

const int32_t d[10];
const int32_t d2[10];
const int32_t SqrtM1[10];
const int32_t A[10];
PreComputedGroupElement bi[8];
PreComputedGroupElement base[32][8];
#endif //EDWARDS25519_H

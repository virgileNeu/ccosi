#include <stdlib.h>

#include "keys.h"
#include "cosi.h"

int main(void) {

    int self_index        = 0;
    int n_peers           = 2;
    int threshold         = 2;
    PublicKey* publicKeys = calloc(n_peers, sizeof(PublicKey));
    PrivateKey privateKey = calloc(PrivateKeySize, sizeof(byte));

    for(int i=0; i < n_peers; i++) {
        hex2bytes(i, privateKey, PrivateKeySize);
        Public(privateKey, &publicKeys[i]);
    }


    hex2bytes(self_index, privateKey, PrivateKeySize);

    Cosigners* cosigners = NewCosigners(publicKeys, n_peers, NULL, 0);
    Commitment* commitments = calloc(n_peers, sizeof(Commitment));
    SignaturePart* parts = calloc(n_peers, sizeof(SignaturePart));
    for(int i=0; i < n_peers; i++) {
        commitments[i] = NULL;
        parts[i] = NULL;
        Cosigners_SetMaskBit(cosigners, i, Disabled);
    }

    byte aggrK[PublicKeySize];
    Cosigners_AggregatePublicKey(cosigners, aggrK);

    puts("ok");
    return 0;
}

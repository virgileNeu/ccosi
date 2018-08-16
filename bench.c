#include <stdio.h>
#include <stdlib.h>
#include "cosi.h"
#include "ed25519.h"
#include "type.h"
#include "my_random.h"
#include <time.h>

int n = 100;
int k = 20;
byte** privateKeys;
byte** publicKeys;
byte** commitments;
Secret* secrets;
byte** parts;

void init_bench() {
    privateKeys = calloc(k, sizeof(byte*));
    publicKeys = calloc(k, sizeof(byte*));
    commitments = calloc(k, sizeof(byte*));
    secrets = calloc(k, sizeof(Secret));
    parts = calloc(k, sizeof(byte*));
    for(int i = 0; i < k; i++) {
        privateKeys[i] = malloc(PrivateKeySize);
        publicKeys[i] = malloc(PublicKeySize);
        GenerateKey(privateKeys[i], publicKeys[i]);
        commitments[i] = malloc(CommitmentSize);
        parts[i] = malloc(SignaturePartSize);
    }
}

static double time_to_seconds(struct timespec* ts) {
    return (double)ts->tv_sec + (double)ts->tv_nsec / 1000000000.0;
}

void start_bench() {
    byte data[32];
    fillRandom(data, 32);
    Cosigners cosigners;
    Cosigners_Init(&cosigners, publicKeys, k, NULL, 0);
    printf("%d/%d\n", Cosigners_CountEnabled(&cosigners), Cosigners_CountTotal(&cosigners));
    byte aggK[PublicKeySize];
    byte aggR[CommitmentSize];
    printf("setup complete, starting bench\n");
    struct timespec start_sign_time;
    clock_gettime(CLOCK_MONOTONIC, &start_sign_time);
    Cosigners_AggregatePublicKeys(&cosigners, aggK);

    size_t signature_len = Cosigners_CosignatureLen(&cosigners);
    byte* cosignature = malloc(signature_len);

    for(int j=0;j < n; j++) {
        for(int i = 0; i < k; i++) {
            Commit(commitments[i], &secrets[i]);
        }

        Cosigners_AggregateCommit(&cosigners, commitments, k, aggR);

        for(int i = 0; i < k; i++) {
            Cosign(privateKeys[i], &secrets[i], data, 32, aggK, aggR, parts[i]);
        }

        Cosigners_AggregateSignature(&cosigners, aggR, parts, cosignature);
    }
    struct timespec end_sign_time;
    clock_gettime(CLOCK_MONOTONIC, &end_sign_time);
    printf("cosigning: %lf s\n", time_to_seconds(&end_sign_time) - time_to_seconds(&start_sign_time));
    struct timespec start_verif_time;
    clock_gettime(CLOCK_MONOTONIC, &start_verif_time);
	for(int i = 0; i < n; i++) {
        VerifyCosignature(publicKeys, k, k, data, 32, cosignature, signature_len);
    }
    struct timespec end_verif_time;
    clock_gettime(CLOCK_MONOTONIC, &end_verif_time);
    printf("Verifying: %lf s\n", time_to_seconds(&end_verif_time) - time_to_seconds(&start_verif_time));
    free(cosignature);
    Cosigners_Deinit(&cosigners);
}

int main() {
    init_bench();
    start_bench();

    return 0;
}

# ccosi

C translation of the cosi golang package by prof. Bryan Ford : https://godoc.org/github.com/bford/golang-x-crypto/ed25519/cosi.
The main difference is that the only available policy is the threshold policy.

Uses Edwards 25519 curves.

Example of use in the bench.c file. Here is a classical use :

Sender side
```
Cosigners cosigners;
Cosigners_Init(&cosigners, publicKeys, k, NULL, 0);
uint32_t masklen = Cosigners_MaskLen(&cosigners);
byte* emptyMask = calloc(masklen, sizeof(byte));
Cosigners_SetMask(&cosigners, emptyMask, masklen);

// send message to cosign, get participants commitment
Cosigners_SetMaskBit(&cosigners, participant_idx, Enabled);
Commitments[participant_idx] = commitment;

Cosigners_AggregatePublicKeys(&cosigners, aggK);
Cosigners_AggregateCommit(&cosigners, commitments, k, aggR);

// send aggK and aggR and wait for signature parts
bool ok = Cosigners_VerifyPart(&cosigners, message,message_len, aggR, signer_idx, commitments[signer_idx], signer_part);
if(ok) {
    parts[signer_idx] = signer_part;
}
//when have all the parts :
Cosigners_AggregateSignature(&cosigners, aggR, parts, cosignature);
```

Witness side
```
//wait for a request and store message and message_len

Commit(commitment, secret);
// send commitment and store secret

//wait for aggR and aggK
Cosign(privateKey, secret, message, message_len, aggK, aggR, signaturePart);

//send signaturePart

//wait for cosignature
bool ok = VerifyCosignature(publicKeys, n_keys, threshold, message, message_len, cosignature, cosignature_len);
```

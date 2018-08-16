#include "my_random.h"

void fillRandom(byte* array, size_t len) {
    for(size_t i=0; i < len; i++) {
        array[i] = rand();
    }
    /*
    // for openthread
    otPlatRandomGetTrue(array, len);
    */
}

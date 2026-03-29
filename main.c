#include "./md4.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Assumes key is of length 16 bytes
unsigned char* getSecretPrefixMAC_MD4(unsigned char* key, int keylength,
                                      unsigned char* text, int textLength){
    size_t length = keylength+textLength;
    char* hash = malloc(MD4_DIGEST_LENGTH);
    size_t datasize = keylength + textLength;
    char* data = malloc(datasize);
    memcpy(data,key,keylength);
    memcpy(data+keylength,text,textLength);
    MD4(hash, data, datasize);

    // Print the hash as a hexadecimal string
    /*for (int i = 0; i < MD4_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");*/

    free(data);
    return hash;
}

bool authenticate(unsigned char* key, int keylength, 
                  unsigned char* message, int messageLength, 
                  unsigned char* MD4Digest){
    unsigned char* generatedDigest = getSecretPrefixMAC_MD4(key, keylength, message, messageLength);
    return memcmp(generatedDigest,MD4Digest,MD4_DIGEST_LENGTH) == 0;
}

unsigned char* getGluePadding(unsigned char* text, int textLength, int keylength, int* gluePaddingLength) {
    uint64_t totalBytes = (uint64_t)keylength + textLength;
    
    // 1. Calculate how many padding bytes are needed
    // We need: totalBytes + 1 (for 0x80) + K (zeros) + 8 (for length) ≡ 0 (mod 64)
    int k = (56 - (totalBytes + 1) % 64 + 64) % 64;
    *gluePaddingLength = 1 + k + 8;

    unsigned char* padding = malloc(*gluePaddingLength);
    
    // 2. The first byte is always 0x80
    padding[0] = 0x80;

    // 3. Fill with zeros
    for (int i = 1; i <= k; i++) {
        padding[i] = 0x00;
    }

    // 4. Append the length in BITS (totalBytes * 8) as 64-bit Big-Endian
    uint64_t totalBits = totalBytes * 8;
    for (int i = 0; i < 8; i++) {
        // Shift right to get the bytes from most significant to least significant
        padding[1 + k + i] = (totalBits >> (56 - (i * 8))) & 0xFF;
    }

    return padding;
}
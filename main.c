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
    
    int k = (56 - (totalBytes + 1) % 64 + 64) % 64;
    *gluePaddingLength = 1 + k + 8;

    unsigned char* padding = malloc(*gluePaddingLength);
    memset(padding, 0, *gluePaddingLength);
    
    padding[0] = 0x80;

    // Append the length in BITS (totalBytes * 8) as 64-bit LITTLE-ENDIAN
    uint64_t totalBits = totalBytes * 8;
    for (int i = 0; i < 8; i++) {
        // Shift right but store in order: Least Significant Byte first
        padding[1 + k + i] = (totalBits >> (i * 8)) & 0xFF;
    }

    return padding;
}
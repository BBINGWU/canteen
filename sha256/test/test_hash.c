#include <stdio.h>
#include <string.h>
#include "compound_hash.h"

void print_digest(const unsigned char *digest, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", digest[i]);
    printf("\n");
}

int main() {
    const char *message = "abc";
    unsigned char output[COMPOUND_HASH_DIGEST_LENGTH];

    compound_hash((const unsigned char *)message, strlen(message), output);

    printf("Message: \"%s\"\n", message);
    printf("Compound Hash (RIPEMD160(SHA256(x))): ");
    print_digest(output, COMPOUND_HASH_DIGEST_LENGTH);

    return 0;
}
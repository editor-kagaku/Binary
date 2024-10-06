/*
 * # gcc -o prob7-2 -no-pie -fno-stack-protector  prob7-2.c
 */


#include <stdio.h>
#include <string.h>

unsigned int x = 0;

void srand(unsigned int s) {
    x = s;
}

unsigned int rand() {
    unsigned int a = 1103515245;
    unsigned int b = 12345;
    unsigned int c = 2147483647;

    x = (a * x + b) & c;
    return x & 0xFFFF;
}

int main(int argc, char **argv) {
    unsigned char answer[] = "\x55\x35\x52\x8a\xb0\x6c\xf9\xb5\x0c\x8d\x39\xe9";
    unsigned short encoded[256];
    unsigned short buf[256];
    int length = 0;

    if (argc < 2) {
        puts("Input password.");
        return 1;
    }

    memset(encoded, 0, 256);
    strncpy((char *)buf, argv[1], 127);
    length = strlen((char *)buf);

    srand(buf[0]);
    for (int i = 0; i < (length - 1) / 2; i++) {
        encoded[i] = buf[i+1] ^ rand();
    }

    if (!memcmp(encoded, answer, strlen(answer))) {
        puts("Success!");
    } else {
        puts("Authentication failed.");
    }

    return 0;
}



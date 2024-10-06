/*
$ gcc -o prob7-1 -no-pie -fno-stack-protector prob7-1.c
*/

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buf[256];
    int a[] = { 0x79733433, 0x33336150, 0x64723077, 0};

    if (argc < 2) {
        puts("Input password.");
        return 1;
    }

    strncpy(buf, argv[1], 256);

    if (!strcmp(buf, &a)) {
        puts("Success!");
    } else {
        puts("Authentication failed.");
    }

    return 0;
}
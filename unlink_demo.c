#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

long long *p;

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    long long *q = (long long *)malloc(0x90);
    long long *r = (long long *)malloc(0x90);
    p = (long long *)((char *)q - 0x10);

    mprotect((void *)((unsigned long)q & ~0xfff), 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);

    fprintf(stderr, "q data: %p\n", q);
    fprintf(stderr, "overflow:\n");
    read(0, q, 0x100);

    free(r);

    fprintf(stderr, "p now: %p\n", p);

    fprintf(stderr, "stage2:\n");
    read(0, p + 3, 8);

    fprintf(stderr, "p now: %p\n", p);

    fprintf(stderr, "stage3:\n");
    read(0, p, 8);

    fprintf(stderr, "triggering fprintf: %d\n", 1);
    return 0;
}
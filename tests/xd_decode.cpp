// Test harness / CLI for xd.c: decode hex-encoded STObjects to JSON.
//   ./xd_decode [--xahau] HEX [HEX ...]
// Each object's JSON is printed followed by a line containing only "---".
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../xd.h"
#include "../sha-256.h"

static int nib(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char** argv)
{
    b58_sha256_impl = calc_sha_256;
    int i = 1;
    if (i < argc && strcmp(argv[i], "--xahau") == 0)
    {
        xd_network = XD_NETWORK_XAHAU;
        ++i;
    }
    if (i >= argc)
        return fprintf(stderr, "usage: %s [--xahau] HEX [HEX ...]\n", argv[0]), 1;

    for (; i < argc; ++i)
    {
        size_t hl = strlen(argv[i]);
        if (hl % 2)
            return fprintf(stderr, "odd hex length\n"), 1;
        size_t bl = hl / 2;
        uint8_t* buf = (uint8_t*)malloc(bl + 1);
        for (size_t j = 0; j < bl; ++j)
        {
            int hi = nib(argv[i][2 * j]), lo = nib(argv[i][2 * j + 1]);
            if (hi < 0 || lo < 0)
                return fprintf(stderr, "bad hex\n"), 1;
            buf[j] = (uint8_t)(hi << 4 | lo);
        }
        buf[bl] = 0;
        uint8_t* out = 0;
        if (!deserialize(&out, buf, (int)bl + 1, 0, 0, 0))
            printf("DESERIALIZE_FAILED\n");
        else
            printf("%s", out);
        printf("---\n");
        free(out);
        free(buf);
    }
    return 0;
}

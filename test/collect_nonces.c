/* Collect many ECDSA (r,s) from the real stock/rand path (HKSET=0 -> rdrand nonces),
 * for a bias audit of the nonce generator. Prints "r_hex s_hex z_hex" per line. */
#include "asm.h"
#include <stdlib.h>

static void ph(const u8 *b, int n) { for (int i = 0; i < n; i++) printf("%02x", b[i]); }

int main(int argc, char **argv)
{
    int M = argc > 1 ? atoi(argv[1]) : 20000;
    if (asm_init()) return 1;
    HKSET[0] = 0;        /* real rdrand nonces from stock */
    POOLN = 0;           /* force an initial stock refill */
    FILE *ur = fopen("/dev/urandom", "rb");
    u8 z[32], rs[64];
    for (int i = 0; i < M; i++) {
        if (fread(z, 1, 32, ur) != 32) return 2;   /* message hash: irrelevant to nonce */
        sign_(rs, z);                               /* from asm.h: r,s little-endian in rs */
        ph(rs, 32); printf(" "); ph(rs + 32, 32); printf(" "); ph(z, 32); printf("\n");
    }
    return 0;
}

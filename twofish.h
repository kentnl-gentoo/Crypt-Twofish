/*
 * $Id: twofish.h,v 2.02 2001/05/04 08:10:37 ams Exp $
 * Copyright 2001 Abhijit Menon-Sen <ams@wiw.org>
 */

#include <stdlib.h>

#ifdef WIN32
typedef unsigned long uint32_t;
#else
#include <inttypes.h>
#endif

struct twofish {
    int len;                    /* Key length in 64-bit units: 2, 3 or 4 */
    uint32_t K[40];             /* Expanded key                          */
    uint32_t S[4][256];         /* Key-dependent S-boxes                 */
};

struct twofish *twofish_setup(unsigned char *key, int len);
void twofish_crypt(struct twofish *t,
                   unsigned char *input, unsigned char *output,
                   int decrypt);
static uint32_t mds_rem(uint32_t a, uint32_t b);
static uint32_t h(int len, const int x, unsigned char *key, int odd);

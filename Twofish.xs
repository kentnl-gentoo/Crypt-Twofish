/*
 * $Id: Twofish.xs,v 2.00 2001/04/29 23:15:55 ams Exp $
 * Copyright 2001 Abhijit Menon-Sen <ams@wiw.org>
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "twofish.h"

#ifndef sv_undef
#define sv_undef PL_sv_undef
#endif

typedef struct twofish * Crypt__Twofish;

MODULE = Crypt::Twofish     PACKAGE = Crypt::Twofish    PREFIX = twofish_
PROTOTYPES: DISABLE

Crypt::Twofish
twofish_setup(key)
    char *  key    = NO_INIT
    STRLEN  keylen = NO_INIT
    CODE:
    {
        key = SvPV(ST(0), keylen);
        if (keylen != 16 && keylen != 24 && keylen != 32)
            croak("key must be 16, 24, or 32 bytes long");

        RETVAL = twofish_setup((unsigned char *)key, keylen);
    }
    OUTPUT:
        RETVAL

void
twofish_DESTROY(self)
    Crypt::Twofish self
    CODE:
        free(self);

void
twofish_crypt(self, input, output, decrypt)
    Crypt::Twofish self
    char *  input  = NO_INIT
    SV *    output
    int     decrypt
    STRLEN  inlen  = NO_INIT
    STRLEN  outlen = NO_INIT
    CODE:
    {
        input = SvPV(ST(1), inlen);
        if (inlen != 16)
            croak("input must be 16 bytes long");

        if (output == &sv_undef)
            output = sv_newmortal();
        outlen = 16;

        if (SvREADONLY(output) || !SvUPGRADE(output, SVt_PV))
            croak("cannot use output as lvalue");

        twofish_crypt(self,
                      (unsigned char *)input,
                      (unsigned char *)SvGROW(output, outlen),
                      decrypt);

        SvCUR_set(output, outlen);
        *SvEND(output) = '\0';
        SvPOK_only(output);
        SvTAINT(output);
        ST(0) = output;
    }

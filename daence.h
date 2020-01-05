/*-
 * Copyright (c) 2020 Taylor R. Campbell
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef DAENCE_H
#define	DAENCE_H

#define	crypto_dae_salsa20poly1305_KEYBYTES	64u
#define	crypto_dae_salsa20poly1305_TAGBYTES	24u

void crypto_dae_salsa20poly1305(unsigned char */*c*/,
    const unsigned char */*m*/, unsigned long long /*mlen*/,
    const unsigned char */*a*/, unsigned long long /*alen*/,
    const unsigned char[static crypto_dae_salsa20poly1305_KEYBYTES]);

int crypto_dae_salsa20poly1305_open(unsigned char */*m*/,
    const unsigned char */*c*/, unsigned long long /*mlen*/,
    const unsigned char */*a*/, unsigned long long /*alen*/,
    const unsigned char[static crypto_dae_salsa20poly1305_KEYBYTES]);

#endif  /* DAENCE_H */

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

/*
 * Salsa20-DAENCE
 * Salsa20 in Deterministic Authenticated Encryption with no noNCEnse
 *
 *      Given 32-byte k0, 16-byte k1,k2,k3,k4, header a, and
 *      message m:
 *
 *              ha1 := Poly1305_{k1,0}(a), ha2 := Poly1305_{k2,0}(a)
 *              hm1 := Poly1305_{k1,0}(m), hm2 := Poly1305_{k2,0}(m)
 *              h3 := Poly1305_{k3,0}(ha1 || ha2 || hm1 || hm2)
 *              h4 := Poly1305_{k4,0}(ha1 || ha2 || hm1 || hm2)
 *              u := HSalsa20_k0(h3)
 *              t := HSalsa20_u(h4) [truncated to 24 bytes]
 *              c = m + XSalsa20_k0(t)
 *              return (t, c)
 */

#include "salsa20daence.h"

#include <string.h>

#include "crypto_core_hsalsa20.h"
#include "crypto_onetimeauth_poly1305.h"
#include "crypto_stream_xsalsa20.h"
#include "crypto_verify_32.h"

static void *(*volatile explicit_memset)(void *, int, size_t) = memset;

static const unsigned char sigma[16] = "expand 32-byte k";

static void
compressauth(unsigned char t[static 24],
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *a, unsigned long long alen,
    const unsigned char k[static 96])
{
	const unsigned char *k0 = k;	/* k0 := k[0..32] */
	unsigned char k1[32], k2[32], k3[32], k4[32], ham[64];
	unsigned char *ha1 = ham +  0, *ha2 = ham + 16;
	unsigned char *hm1 = ham + 32, *hm2 = ham + 48;
	unsigned char h[32], *h3 = h, *h4 = h + 16;
	unsigned char u[32];

	/* Poly1305: Set evaluation point; zero addend.  */
	memcpy(k1, k + 32, 16); memset(k1 + 16, 0, 16);
	memcpy(k2, k + 48, 16); memset(k2 + 16, 0, 16);
	memcpy(k3, k + 64, 16); memset(k3 + 16, 0, 16);
	memcpy(k4, k + 80, 16); memset(k4 + 16, 0, 16);

	/*
	 * Message compression:
	 *	ha := Poly1305^2_{k1,k2}(a)
	 *	hm := Poly1305^2_{k1,k2}(m)
	 *	h := Poly1305^2_{k3,k4}(ha || hm)
	 */
	crypto_onetimeauth_poly1305(ha1, a, alen, k1);
	crypto_onetimeauth_poly1305(ha2, a, alen, k2);
	crypto_onetimeauth_poly1305(hm1, m, mlen, k1);
	crypto_onetimeauth_poly1305(hm2, m, mlen, k2);
	crypto_onetimeauth_poly1305(h3, ham, 64, k3);
	crypto_onetimeauth_poly1305(h4, ham, 64, k4);

	/* Tag generation: t, _ := HXSalsa20_k0(h3 || h4) */
	crypto_core_hsalsa20(u, h3, k0, sigma);
	crypto_core_hsalsa20(u, h4, u, sigma);
	memcpy(t, u, 24);

	/* paranoia */
	explicit_memset(k1, 0, sizeof k1);
	explicit_memset(k2, 0, sizeof k2);
	explicit_memset(k3, 0, sizeof k3);
	explicit_memset(k4, 0, sizeof k4);
	explicit_memset(ham, 0, sizeof ham);
	explicit_memset(h, 0, sizeof h);
	explicit_memset(u, 0, sizeof u);
}

void
crypto_dae_salsa20daence(unsigned char *c,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *a, unsigned long long alen,
    const unsigned char k[static 96])
{
	const unsigned char *k0 = k;	/* k0 := k[0..32] */

	/* c[0..24] := HXSalsa20_k0(Poly1305^2(a,m)) */
	compressauth(c, m, mlen, a, alen, k);

	/*
	 * Stream cipher:
	 *	c[24..24+mlen] := m[0..mlen]
	 *	    ^ XSalsa20_k0(t @ c[0..24])
	 */
	crypto_stream_xsalsa20_xor(c + 24, m, mlen, c, k0);
}

int
crypto_dae_salsa20daence_open(unsigned char *m,
    const unsigned char *c, unsigned long long mlen,
    const unsigned char *a, unsigned long long alen,
    const unsigned char k[static 96])
{
	const unsigned char *k0 = k;	/* k0 := k[0..32] */
	unsigned char t[32], t_[32];
	int ret;

	/*
	 * Stream cipher:
	 *	m[0..mlen] := c[24..24+mlen]
	 *	    ^ XSalsa20_k0(t' @ c[0..24])
	 */
	crypto_stream_xsalsa20_xor(m, c + 24, mlen, c, k0);

	/* t := HXSalsa20_k0(Poly1305^2(a,m)) */
	compressauth(t, m, mlen, a, alen, k);

	/* Verify tag: c[0..24] ?= t (no crypto_verify_24) */
	memcpy(t_, c, 24);
	memset(t + 24, 0, 8);
	memset(t_ + 24, 0, 8);
	ret = crypto_verify_32(t_, t);
	if (ret)
		explicit_memset(m, 0, mlen); /* paranoia */

	/* Paranoia: clear temporaries.  */
	explicit_memset(t, 0, sizeof t);
	explicit_memset(t_, 0, sizeof t_);

	return ret;
}

int
crypto_dae_salsa20daence_selftest(void)
{
	static const unsigned char k[96] = {
		0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
		0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
		0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
		0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
		0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
		0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
		0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
		0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
		0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
		0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
		0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
		0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
	};
	static const unsigned char a[16] = {
		0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,
		0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,
	};
	static const unsigned char m[] = {
		0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,
		0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,
		0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
		0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f, 0x90,
	};
	static const unsigned char c[24 + sizeof m] = {
		0xa5,0x09,0x6e,0x6c,0xd6,0x56,0x41,0x31,
		0xdc,0xfb,0xd1,0x86,0xcb,0x1e,0x13,0x72,
		0x8e,0x2b,0x67,0x19,0xb0,0xbf,0x71,0x94,
		0x14,0xfb,0x8f,0x32,0x8f,0xca,0x05,0x2a,
		0xcd,0x43,0x27,0xd1,0x37,0x12,0x67,0x96,
		0x19,0x35,0x56,0x63,0x18,0x55,0x38,0x71,
		0xb9,0x0c,0xc9,0x08,0x29,0xa9,0xd9,0x60, 0xf9,
	};
	unsigned char c0[sizeof c];
	unsigned char m0[sizeof m];

	crypto_dae_salsa20daence(c0, m, sizeof m, a, sizeof a, k);
	if (memcmp(c, c0, sizeof c) != 0)
		return -1;
	if (crypto_dae_salsa20daence_open(m0, c, sizeof m, a, sizeof a, k))
		return -1;
	if (memcmp(m, m0, sizeof m) != 0)
		return -1;
	c0[18] ^= 0x4;
	if (crypto_dae_salsa20daence_open(m0, c0, sizeof m, a, sizeof a, k)
	    == 0)
		return -1;

	return 0;
}

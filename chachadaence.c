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
 * ChaCha-DAENCE
 * ChaCha in Deterministic Authenticated Encryption with no noNCEnse
 *
 *      Given 32-byte k0, 16-byte k1, 16-byte k2, header a, and
 *      message m:
 *
 *              h1 := Poly1305_{k1,0}(pad0(a) || pad0(m) || |a|_4)
 *              h2 := Poly1305_{k2,0}(pad0(a) || pad0(m) || |a|_4)
 *              u := HChaCha_k0(h1)
 *              t := HChaCha_u(h2) [truncated to 24 bytes]
 *              c = m + XChaCha_k0(t)
 *              return (t, c)
 */

#include "chachadaence.h"

#include <string.h>

#include <sodium/crypto_core_hchacha20.h>
#include <sodium/crypto_onetimeauth_poly1305.h>
#include <sodium/crypto_stream_xchacha20.h>
#include <sodium/crypto_verify_32.h>

static void *(*volatile explicit_memset)(void *, int, size_t) = memset;

static const unsigned char sigma[16] = "expand 32-byte k";

static void
le32enc(void *buf, uint32_t v)
{
	unsigned char *p = buf;

	*p++ = v & 0xff; v >>= 8;
	*p++ = v & 0xff; v >>= 8;
	*p++ = v & 0xff; v >>= 8;
	*p++ = v & 0xff;
}

static void
poly1305ad(unsigned char h[static 16],
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *a, unsigned long long alen,
    const unsigned char k[static 16])
{
	static const unsigned char z[16] = {0};
	unsigned char alen32le[4];
	crypto_onetimeauth_poly1305_state poly1305;
	unsigned char k_[32];

	/* Poly1305: Set evaluation point; zero addend. */
	memcpy(k_, k, 16);
	memset(k_ + 16, 0, 16);

	/* Set h := Poly1305_k(pad0(a) || pad0(m) || |a|_4). */
	crypto_onetimeauth_poly1305_init(&poly1305, k_);
	crypto_onetimeauth_poly1305_update(&poly1305, a, alen);
	crypto_onetimeauth_poly1305_update(&poly1305, z, (0x10 - alen) & 0xf);
	crypto_onetimeauth_poly1305_update(&poly1305, m, mlen);
	crypto_onetimeauth_poly1305_update(&poly1305, z, (0x10 - mlen) & 0xf);
	le32enc(alen32le, alen);
	crypto_onetimeauth_poly1305_update(&poly1305, alen32le, 4);
	crypto_onetimeauth_poly1305_final(&poly1305, h);

	explicit_memset(&poly1305, 0, sizeof poly1305);
	explicit_memset(k_, 0, sizeof k_);
}

static void
compressauth(unsigned char t[static 24],
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *a, unsigned long long alen,
    const unsigned char k[static 64])
{
	const unsigned char *k0 = k, *k1 = k + 32, *k2 = k + 48;
	unsigned char h[32], *h1 = h, *h2 = h + 16;
	unsigned char u[32];

	/*
	 * Message compression:
	 *	h := Poly1305^2_{k1,k2}(a || m || |a|)
	 */
	poly1305ad(h1, m, mlen, a, alen, k1);
	poly1305ad(h2, m, mlen, a, alen, k2);

	/* Tag generation: t, _ := HXChacha_k0(h1 || h2) */
	crypto_core_hchacha20(u, h1, k0, sigma);
	crypto_core_hchacha20(u, h2, u, sigma);
	memcpy(t, u, 24);

	/* paranoia */
	explicit_memset(h, 0, sizeof h);
	explicit_memset(u, 0, sizeof u);
}

void
crypto_dae_chachadaence(unsigned char *c,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *a, unsigned long long alen,
    const unsigned char k[static 64])
{
	const unsigned char *k0 = k;	/* k0 := k[0..32] */

	/* c[0..24] := HXChacha_k0(Poly1305^2_{k1,k2}(a,m)) */
	compressauth(c, m, mlen, a, alen, k);

	/*
	 * Stream cipher:
	 *	c[24..24+mlen] := m[0..mlen]
	 *	    ^ XChacha_k0(t @ c[0..24])
	 */
	crypto_stream_xchacha20_xor(c + 24, m, mlen, c, k0);
}

int
crypto_dae_chachadaence_open(unsigned char *m,
    const unsigned char *c, unsigned long long mlen,
    const unsigned char *a, unsigned long long alen,
    const unsigned char k[static 64])
{
	const unsigned char *k0 = k;	/* k0 := k[0..32] */
	unsigned char t[32], t_[32];
	int ret;

	/*
	 * Stream cipher:
	 *	m[0..mlen] := c[24..24+mlen]
	 *	    ^ XChacha_k0(t' @ c[0..24])
	 */
	crypto_stream_xchacha20_xor(m, c + 24, mlen, c, k0);

	/* t := HXChacha_k0(Poly1305^2_{k1,k2}(a,m)) */
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
crypto_dae_chachadaence_selftest(void)
{
	static const unsigned char k[64] = {
		0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
		0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
		0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
		0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
		0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
		0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
		0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
		0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
	};
	static const unsigned char a[16] = {
		0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
		0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
	};
	static const unsigned char m[] = {
		0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
		0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
		0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,
		0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f, 0x70,
	};
	static const unsigned char c[24 + sizeof m] = {
		0xa0,0x46,0xb1,0x3d,0xe9,0x14,0x5c,0x02,
		0xd3,0x9c,0xee,0xf2,0x04,0xe7,0x99,0xa1,
		0xc6,0xe1,0x0a,0xa4,0xa9,0x92,0x6a,0x02,
		0xb5,0x2d,0xa0,0xc6,0x97,0x0c,0xf3,0x9a,
		0x41,0x8a,0x48,0xa9,0xc7,0xe1,0xcd,0x2c,
		0xd2,0xc3,0x22,0x1f,0xe7,0xa0,0x96,0xbf,
		0xf3,0xd1,0x89,0xc0,0x78,0xe8,0x55,0xba, 0x8d,
	};
	unsigned char c0[sizeof c];
	unsigned char m0[sizeof m];

	crypto_dae_chachadaence(c0, m, sizeof m, a, sizeof a, k);
	if (memcmp(c, c0, sizeof c) != 0)
		return -1;
	if (crypto_dae_chachadaence_open(m0, c, sizeof m, a, sizeof a, k))
		return -1;
	if (memcmp(m, m0, sizeof m) != 0)
		return -1;
	c0[18] ^= 0x4;
	if (crypto_dae_chachadaence_open(m0, c0, sizeof m, a, sizeof a, k)
	    == 0)
		return -1;

	return 0;
}

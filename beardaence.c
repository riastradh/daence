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
 * ChaCha-Daence for BearSSL
 */

#define	_POSIX_C_SOURCE	200908L

#include <assert.h>
#include <bearssl.h>
#include <stdint.h>
#include <string.h>

static inline uint32_t
le32dec(const void *buf)
{
	const uint8_t *p = buf;
	uint32_t v = 0;

	v |= (uint32_t)p[0] << 0;
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	return v;
}

static inline void
le32enc(void *buf, uint32_t v)
{
	uint8_t *p = buf;

	p[0] = v >> 0;
	p[1] = v >> 8;
	p[2] = v >> 16;
	p[3] = v >> 24;
}

static uint32_t
null_chacha20_run(const void *key, const void *iv, uint32_t cc, void *data,
    size_t len)
{

	(void)iv;		/* ignore */
	if (cc != 0)
		return cc + (len + (64 - 1))/64;
	assert(len == 32);
	memcpy(data, key, 16);
	memset((uint8_t *)data + 16, 0, 16);
	return 1;
}

static void
hchacha20_run(const uint8_t key[static 32], const uint8_t in[static 16],
    uint8_t out[static 32], br_chacha20_run ichacha)
{
	static const unsigned char c[16] = "expand 32-byte k";
	uint8_t buf[64] = {0};

	ichacha(key, in + 4, le32dec(in), buf, sizeof buf);
	le32enc(out + 4*0, le32dec(buf + 4*0) - le32dec(c + 4*0));
	le32enc(out + 4*1, le32dec(buf + 4*1) - le32dec(c + 4*1));
	le32enc(out + 4*2, le32dec(buf + 4*2) - le32dec(c + 4*2));
	le32enc(out + 4*3, le32dec(buf + 4*3) - le32dec(c + 4*3));
	le32enc(out + 4*4, le32dec(buf + 4*12) - le32dec(in + 4*0));
	le32enc(out + 4*5, le32dec(buf + 4*13) - le32dec(in + 4*1));
	le32enc(out + 4*6, le32dec(buf + 4*14) - le32dec(in + 4*2));
	le32enc(out + 4*7, le32dec(buf + 4*15) - le32dec(in + 4*3));
}

static void
xchacha20_run(const uint8_t key[static 32], const uint8_t nonce[static 24],
    uint32_t cc, void *data, size_t len, br_chacha20_run ichacha)
{
	uint8_t subkey[32], subnonce[12];

	hchacha20_run(key, nonce, subkey, ichacha);
	memset(subnonce, 0, 4);
	memcpy(subnonce + 4, nonce + 16, 8);
	ichacha(subkey, subnonce, cc, data, len);
}

static void
compressauth(const uint8_t key[static 64], const void *data, size_t len,
    const void *aad, size_t aad_len, void *tag,
    br_chacha20_run ichacha, br_poly1305_run ipoly1305)
{
	/*
	 * ipoly1305 won't write to data (via null_chacha20_run), so
	 * just discard the const qualifier.
	 */
	void *ptr = (void *)(uintptr_t)data;
	const uint8_t *k0 = key, *k1 = key + 32, *k2 = key + 48;
	uint8_t h[32], *h1 = h, *h2 = h + 16;
	uint8_t u[32];

	ipoly1305(k1, NULL, ptr, len, aad, aad_len, h1, null_chacha20_run, 0);
	ipoly1305(k2, NULL, ptr, len, aad, aad_len, h2, null_chacha20_run, 0);

	hchacha20_run(k0, h1, u, ichacha);
	hchacha20_run(u, h2, u, ichacha);

	memcpy(tag, u, 24);
}

void
br_chachadaence_encrypt(const void *key, void *data, size_t len,
    const void *aad, size_t aad_len, void *tag,
    br_chacha20_run ichacha, br_poly1305_run ipoly1305)
{

	compressauth(key, data, len, aad, aad_len, tag, ichacha, ipoly1305);
	xchacha20_run(key, tag, 0, data, len, ichacha);
}

int
br_chachadaence_decrypt(const void *key, void *data, size_t len,
    const void *aad, size_t aad_len, const void *tag,
    br_chacha20_run ichacha, br_poly1305_run ipoly1305)
{
	const uint8_t *t = tag;
	uint8_t t_[24];
	unsigned i, d = 0;

	xchacha20_run(key, tag, 0, data, len, ichacha);
	compressauth(key, data, len, aad, aad_len, t_, ichacha, ipoly1305);

	/*
	 * XXX No consttime_memequal in BearSSL -- hope the compiler
	 * doesn't try to optimize this...
	 */
	for (i = 0; i < 24; i++)
		d |= t[i] ^ t_[i];
	asm volatile("" ::: "memory");

	if (d) {
		memset(data, 0, len);
		return 0;
	}

	return 1;
}

static int
hchacha20_selftest(br_chacha20_run ichacha)
{
	/* https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03, §2.2.1 */
	static const uint8_t k[32] = {
		0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
		0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
		0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
		0x18,0x19,0x1a,0x1b, 0x1c,0x1d,0x1e,0x1f,
	};
	static const uint8_t in[16] = {
		0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x4a,
		0x00,0x00,0x00,0x00, 0x31,0x41,0x59,0x27,
	};
	static const uint8_t expected[32] = {
		0x82,0x41,0x3b,0x42, 0x27,0xb2,0x7b,0xfe,
		0xd3,0x0e,0x42,0x50, 0x8a,0x87,0x7d,0x73,
		0xa0,0xf9,0xe4,0xd5, 0x8a,0x74,0xa8,0x53,
		0xc1,0x2e,0xc4,0x13, 0x26,0xd3,0xec,0xdc,
	};
	uint8_t out[32];

	hchacha20_run(k, in, out, ichacha);
	if (memcmp(out, expected, 32))
		return -1;

	return 0;
}

int
br_chachadaence_selftest(br_chacha20_run ichacha, br_poly1305_run ipoly1305)
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
	static const unsigned char t[24] = {
		0x99,0x76,0x70,0x9c,0x45,0x3c,0x8f,0x94,
		0xe4,0x92,0xef,0xa7,0x70,0xe3,0xc2,0x21,
		0xe0,0x8e,0xa6,0xa0,0xe5,0x88,0xd5,0x4e,
	};
	static const unsigned char c[sizeof m] = {
		0x22,0x7d,0x2c,0x0c,0xde,0xe4,0x08,0xbc,
		0xe9,0xd0,0x53,0x2a,0x3a,0x36,0x27,0x01,
		0x0f,0x11,0xf2,0xb2,0xe4,0x72,0x67,0xe5,
		0x33,0xe9,0x5a,0xa3,0xb2,0xe7,0x1e,0xfb, 0x68,
	};
	unsigned char tag[sizeof t];
	unsigned char data[sizeof m];

	if (hchacha20_selftest(ichacha))
		return -1;

	memcpy(data, m, sizeof m);
	br_chachadaence_encrypt(k, data, sizeof data, a, sizeof a, tag,
	    ichacha, ipoly1305);
	if (memcmp(tag, t, sizeof t))
		return -1;
	if (memcmp(data, c, sizeof c))
		return -1;
	if (!br_chachadaence_decrypt(k, data, sizeof data, a, sizeof a, t,
		ichacha, ipoly1305))
		return -1;
	if (memcmp(data, m, sizeof m))
		return -1;

	memcpy(data, c, sizeof c);
	data[18] ^= 0x4;
	if (br_chachadaence_decrypt(k, data, sizeof data, a, sizeof a, t,
		ichacha, ipoly1305))
		return -1;

	return 0;
}

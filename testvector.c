#include <assert.h>
#include <string.h>

#include <sodium/crypto_core_hsalsa20.h>
#include <sodium/crypto_core_salsa20.h>
#include <sodium/crypto_onetimeauth_poly1305.h>
#include <sodium/crypto_stream_xsalsa20.h>
#include <sodium/crypto_verify_32.h>
#include <sodium/utils.h>

static const unsigned char sigma[16] = "expand 32-byte k";

static void *
explicit_memset(void *p, int c, size_t n)
{

	assert(c == 0);
	sodium_memzero(p, n);
	return p;
}

static void
show(const char *name, const unsigned char *buf, size_t len)
{
	size_t i;

	printf("%s=", name);
	for (i = 0; i < len; i++) {
		printf("%02hhx", buf[i]);
		if (i + 1 < len && ((i + 1) % 24) == 0)
			printf("\n");
	}
	printf("\n");
}

void
crypto_daencebox_salsa20poly1305_test(unsigned char *c,
    unsigned char v_k0[static restrict 32],
    unsigned char v_k1[static restrict 16],
    unsigned char v_k2[static restrict 16],
    unsigned char v_h1[static restrict 16],
    unsigned char v_h2[static restrict 16],
    unsigned char v_u[static restrict 32],
    const unsigned char *m, unsigned long long mlen,
    const unsigned char n[static 16],
    const unsigned char k[static 32])
{
	unsigned char k012[64], *k0 = k012;
	unsigned char k1[32], k2[32];
	unsigned char h1[16], h2[16];
	unsigned char u[32], t[32];

	/*
	 * Key derivation:
	 *	k012[0..64] := Salsa20_k(n)
	 *	k0 @ k012[0..32]
	 *	k1 := k012[32..48] || 0^16
	 *	k2 := k012[48..64] || 0^16
	 */
	crypto_core_salsa20(k012, n, k, sigma);
	memcpy(k1, k012 + 32, 16);
	memset(k1 + 16, 0, 16);
	memcpy(k2, k012 + 48, 16);
	memset(k2 + 16, 0, 16);

	memcpy(v_k0, k0, 32);
	memcpy(v_k1, k1, 16);
	memcpy(v_k2, k2, 16);

	/*
	 * Message compression:
	 *	h1 := Poly1305_k1(m)
	 *	h2 := Poly1305_k2(m)
	 */
	crypto_onetimeauth_poly1305(h1, m, mlen, k1);
	crypto_onetimeauth_poly1305(h2, m, mlen, k2);

	memcpy(v_h1, h1, 16);
	memcpy(v_h2, h2, 16);

	/*
	 * Tag generation:
	 *	u := HSalsa20_k0(h1)
	 *	t := HSalsa20_u(h2)
	 */
	crypto_core_hsalsa20(u, h1, k0, sigma);
	crypto_core_hsalsa20(t, h2, u, sigma);

	memcpy(v_u, u, 32);

	/* Copy out tag: c[0..24] := t */
	memcpy(c, t, 24);

	/*
	 * Stream cipher:
	 *	c[24..24+mlen] := m[0..mlen]
	 *	    ^ XSalsa20_k0(t @ c[0..24])
	 */
	crypto_stream_xsalsa20_xor(c + 24, m, mlen, c, k0);

	/* Paranoia: clear temporaries.  */
	explicit_memset(k012, 0, sizeof k012);
	explicit_memset(k1, 0, sizeof k1);
	explicit_memset(k2, 0, sizeof k2);
	explicit_memset(h1, 0, sizeof h1);
	explicit_memset(h2, 0, sizeof h2);
	explicit_memset(u, 0, sizeof u);
	explicit_memset(t, 0, sizeof t);
}

int
crypto_daencebox_salsa20poly1305_open(unsigned char *m,
    const unsigned char *c, unsigned long long mlen,
    const unsigned char n[static 16],
    const unsigned char k[static 32])
{
	unsigned char k012[64], *k0 = k012;
	unsigned char khut[64];
	unsigned char *k1 = khut, *k2 = khut + 32;
	unsigned char *h1 = khut, *h2 = khut + 16;
	unsigned char *u = khut + 32;
	unsigned char *t = khut, *t_ = khut + 32;
	int ret;

	/*
	 * Key derivation:
	 *	k012[0..64] := Salsa20_k(n)
	 *	k1 @ khut[0..32] := k012[32..48] || 0^16
	 *	k2 @ khut[32..64] := k012[48..64] || 0^16
	 */
	crypto_core_salsa20(k012, n, k, sigma);
	memcpy(k1, k012 + 32, 16);
	memset(k1 + 16, 0, 16);
	memcpy(k2, k012 + 48, 16);
	memset(k2 + 16, 0, 16);

	/*
	 * Stream cipher:
	 *	m[0..mlen] := c[24..24+mlen]
	 *	    ^ XSalsa20_k0(t' @ c[0..24])
	 */
	crypto_stream_xsalsa20_xor(m, c + 24, mlen, c, k0);

	/*
	 * Message compression:
	 *	h1 @ khut[0..16] := Poly1305_k1(m)
	 *	    {k1 @ khut[0..32]}
	 *	h2 @ khut[16..32] := Poly1305_k2(m)
	 *	    {k2 @ khut[32..64]}
	 */
	crypto_onetimeauth_poly1305(h1, m, mlen, k1);
	crypto_onetimeauth_poly1305(h2, m, mlen, k2);

	/*
	 * Tag generation:
	 *	u @ khut[32..64] := HSalsa20_k0(h1 @ khut[0..16])
	 *	t @ khut[0..24], khut[24..32]
	 *	    := HSalsa20_u(h2 @ khut[16..32])
	 */
	crypto_core_hsalsa20(u, h1, k0, sigma);
	crypto_core_hsalsa20(t, h2, u, sigma);

	/* Verify tag: c[0..24] ?= t (no crypto_verify_24) */
	memset(t + 24, 0, 8);
	memcpy(t_, c, 24);
	memset(t_ + 24, 0, 8);
	ret = crypto_verify_32(t_, t);
	if (ret)
		explicit_memset(m, 0, mlen); /* paranoia */

	/* Paranoia: clear temporaries.  */
	explicit_memset(k012, 0, sizeof k012);
	explicit_memset(khut, 0, sizeof khut);

	return ret;
}

static const unsigned char k[32] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
	0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
	0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
};

static const unsigned char n[16] = {
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
	0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
};

static const unsigned char m[33] = {
	0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
	0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
	0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
	0x50,
};

int
main(void)
{
	unsigned char k0[32],k1[16],k2[16],h1[16],h2[16],u[32];
	unsigned char c[24 + sizeof m], m_[sizeof m];
	unsigned i;
	int ret = 0;

	for (i = 0; i <= sizeof m; i++) {
		/* paranoia */
		memset(k0, 0, sizeof k0);
		memset(k1, 0, sizeof k1);
		memset(k2, 0, sizeof k2);
		memset(h1, 0, sizeof h1);
		memset(h2, 0, sizeof h2);
		memset(u, 0, sizeof u);
		memset(c, 0, sizeof c);
		memset(m_, 0, sizeof m_);

		/* test */
		crypto_daencebox_salsa20poly1305_test(c,
		    k0,k1,k2,h1,h2,u, m, i, n, k);
		if (crypto_daencebox_salsa20poly1305_open(m_, c,
			i, n, k) != 0)
			ret = 1;
		if (memcmp(m, m_, i) != 0)
			ret = 2;

		/* show */
		printf("mlen=%u\n", i);
		show("m", m, i);
		show("k", k, sizeof k);
		show("n", n, sizeof n);
		show("k0", k0, sizeof k0);
		show("k1", k1, sizeof k1);
		show("k2", k2, sizeof k2);
		show("h1", h1, sizeof h1);
		show("h2", h2, sizeof h2);
		show("u", u, sizeof u);
		show("c", c, 24 + i);
		printf("\n");
	}

	fflush(stdout);
	if (ferror(stdout))
		ret = 3;

	return ret;
}

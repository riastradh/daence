#include <assert.h>
#include <string.h>

#include <sodium/crypto_core_hsalsa20.h>
#include <sodium/crypto_core_salsa20.h>
#include <sodium/crypto_onetimeauth_poly1305.h>
#include <sodium/crypto_stream_xsalsa20.h>
#include <sodium/crypto_verify_32.h>
#include <sodium/utils.h>

static const unsigned char sigma[16] = "expand 32-byte k";

/*
 * Lines marked `XXX KAT' expose internal state and are used only
 * for generating test vectors, to assist with making compatible
 * implementations.  For practical deployment, delete all of those
 * lines.
 */

void
crypto_dae_salsa20poly1305_test(unsigned char *c,
    unsigned char v_ham[static restrict 64], /* XXX KAT */
    unsigned char v_h[static restrict 32],   /* XXX KAT */
    unsigned char v_u[static restrict 32],   /* XXX KAT */
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *a, unsigned long long alen,
    const unsigned char k[static 64])
{
	const unsigned char *k0 = k;	/* k0 := k[0..32] */
	unsigned char k1[32], k2[32];
	unsigned char ham[64];
	unsigned char *ha1 = ham +  0, *ha2 = ham + 16;
	unsigned char *hm1 = ham + 32, *hm2 = ham + 48;
	unsigned char h[32], *h1 = h, *h2 = h + 16;
	unsigned char u[32], t[32];

	/*
	 * Poly1305 keys: Set evaluation point; zero addend.
	 *	k1 := k[32..48] || 0^16
	 *	k2 := k[48..64] || 0^16
	 */
	memcpy(k1, k + 32, 16); memset(k1 + 16, 0, 16);
	memcpy(k2, k + 48, 16); memset(k2 + 16, 0, 16);

	/*
	 * Message compression:
	 *	ha := Poly1305^2_{k1,k2}(a)
	 *	hm := Poly1305^2_{k1,k2}(m)
	 *	h := Poly1305^2_k1(ha || hm)
	 */
	crypto_onetimeauth_poly1305(ha1, a, alen, k1);
	crypto_onetimeauth_poly1305(ha2, a, alen, k2);
	crypto_onetimeauth_poly1305(hm1, m, mlen, k1);
	crypto_onetimeauth_poly1305(hm2, m, mlen, k2);
	crypto_onetimeauth_poly1305(h1, ham, 64, k1);
	crypto_onetimeauth_poly1305(h2, ham, 64, k2);

	memcpy(v_ham, ham, sizeof ham);	/* XXX KAT */
	memcpy(v_h, h, sizeof h);	/* XXX KAT */

	/*
	 * Tag generation:
	 *	u := HSalsa20_k0(h1)
	 *	t := HSalsa20_u(h2)
	 */
	crypto_core_hsalsa20(u, h1, k0, sigma);
	crypto_core_hsalsa20(t, h2, u, sigma);

	memcpy(v_u, u, 32);	/* XXX KAT */

	/* Copy out tag: c[0..24] := t */
	memcpy(c, t, 24);

	/*
	 * Stream cipher:
	 *	c[24..24+mlen] := m[0..mlen]
	 *	    ^ XSalsa20_k0(t @ c[0..24])
	 */
	crypto_stream_xsalsa20_xor(c + 24, m, mlen, c, k0);

	/* Paranoia: clear temporaries.  */
	sodium_memzero(k1, sizeof k1);
	sodium_memzero(k2, sizeof k2);
	sodium_memzero(ham, sizeof ham);
	sodium_memzero(h, sizeof h);
	sodium_memzero(u, sizeof u);
	sodium_memzero(t, sizeof t);
}

int
crypto_dae_salsa20poly1305_open(unsigned char *m,
    const unsigned char *c, unsigned long long mlen,
    const unsigned char *a, unsigned long long alen,
    const unsigned char k[static 64])
{
	const unsigned char *k0 = k;	/* k0 := k[0..32] */
	unsigned char k1[32], k2[32];
	unsigned char ham[64];
	unsigned char *ha1 = ham +  0, *ha2 = ham + 16;
	unsigned char *hm1 = ham + 32, *hm2 = ham + 48;
	unsigned char h[32], *h1 = h, *h2 = h + 16;
	unsigned char u[32], t[32], t_[32];
	int ret;

	/*
	 * Stream cipher:
	 *	m[0..mlen] := c[24..24+mlen]
	 *	    ^ XSalsa20_k0(t' @ c[0..24])
	 */
	crypto_stream_xsalsa20_xor(m, c + 24, mlen, c, k0);

	/*
	 * Poly1305 keys: Set evaluation point; zero addend.
	 *	k1 := k[32..48] || 0^16
	 *	k2 := k[48..64] || 0^16
	 */
	memcpy(k1, k + 32, 16); memset(k1 + 16, 0, 16);
	memcpy(k2, k + 48, 16); memset(k2 + 16, 0, 16);

	/*
	 * Message compression:
	 *	ha := Poly1305^2_{k1,k2}(a)
	 *	hm := Poly1305^2_{k1,k2}(m)
	 *	h := Poly1305^2_k1(ha || hm)
	 */
	crypto_onetimeauth_poly1305(ha1, a, alen, k1);
	crypto_onetimeauth_poly1305(ha2, a, alen, k2);
	crypto_onetimeauth_poly1305(hm1, m, mlen, k1);
	crypto_onetimeauth_poly1305(hm2, m, mlen, k2);
	crypto_onetimeauth_poly1305(h1, ham, 64, k1);
	crypto_onetimeauth_poly1305(h2, ham, 64, k2);

	/*
	 * Tag generation:
	 *	u := HSalsa20_k0(h1)
	 *	t := HSalsa20_u(h2)
	 */
	crypto_core_hsalsa20(u, h1, k0, sigma);
	crypto_core_hsalsa20(t, h2, u, sigma);

	/* Verify tag: c[0..24] ?= t (no crypto_verify_24) */
	memset(t + 24, 0, 8);
	memcpy(t_, c, 24);
	memset(t_ + 24, 0, 8);
	ret = crypto_verify_32(t_, t);
	if (ret)
		sodium_memzero(m, mlen); /* paranoia */

	/* Paranoia: clear temporaries.  */
	sodium_memzero(k1, sizeof k1);
	sodium_memzero(k2, sizeof k2);
	sodium_memzero(ham, sizeof ham);
	sodium_memzero(h, sizeof h);
	sodium_memzero(u, sizeof u);
	sodium_memzero(t, sizeof t);
	sodium_memzero(t_, sizeof t_);

	return ret;
}

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

static const unsigned char m[33] = {
	0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
	0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
	0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,
	0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f, 0x60,
};

static void
show(const char *name, const unsigned char *buf, size_t len)
{
	size_t i;

	printf("%s=", name);
	for (i = 0; i < len; i++) {
		printf("%02hhx", buf[i]);
		if (i + 1 < len && ((i + 1) % 24) == 0)
			printf("\n%*s", (int)strlen(name) + 1, "");
	}
	printf("\n");
}

int
main(void)
{
	unsigned char ham[64], h[32], u[32];
	unsigned char c[24 + sizeof m], m_[sizeof m];
	unsigned i;
	int ret = 0;

	for (i = 0; i <= sizeof m; i++) {
		/* paranoia */
		memset(ham, 0, sizeof ham);
		memset(h, 0, sizeof h);
		memset(u, 0, sizeof u);
		memset(c, 0, sizeof c);
		memset(m_, 0, sizeof m_);

		/* test */
		crypto_dae_salsa20poly1305_test(c,
		    ham,h,u, m, i, a, sizeof a, k);
		if (crypto_dae_salsa20poly1305_open(m_, c,
			i, a, sizeof a, k) != 0)
			ret = 1;
		if (memcmp(m, m_, i) != 0)
			ret = 2;

		/* show */
		printf("mlen=%u\n", i);
		printf("alen=%zu\n", sizeof a);
		show("m", m, i);
		show("m_", m_, i);
		show("k", k, sizeof k);
		show("a", a, sizeof a);
		show("h_a", ham, 32);
		show("h_m", ham + 32, 32);
		show("h", h, sizeof h);
		show("u", u, sizeof u);
		show("c", c, 24 + i);
		printf("\n");
	}

	fflush(stdout);
	if (ferror(stdout))
		ret = 3;

	return ret;
}

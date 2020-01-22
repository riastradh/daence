#include <string.h>

#include <sodium/crypto_core_hchacha20.h>
#include <sodium/crypto_onetimeauth_poly1305.h>
#include <sodium/crypto_stream_xchacha20.h>
#include <sodium/crypto_verify_32.h>
#include <sodium/utils.h>

static const unsigned char sigma[16] = "expand 32-byte k";

static void
le64enc(void *buf, uint32_t v)
{
	unsigned char *p = buf;

	*p++ = v & 0xff; v >>= 8;
	*p++ = v & 0xff; v >>= 8;
	*p++ = v & 0xff; v >>= 8;
	*p++ = v & 0xff; v >>= 8;
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
	unsigned char len64le[8];
	crypto_onetimeauth_poly1305_state poly1305;
	unsigned char k_[32];

	/* Poly1305: Set evaluation point; zero addend. */
	memcpy(k_, k, 16);
	memset(k_ + 16, 0, 16);

	/* Set h := Poly1305_k(pad0(a) || pad0(m) || |a|_8 || |m|_8). */
	crypto_onetimeauth_poly1305_init(&poly1305, k_);
	crypto_onetimeauth_poly1305_update(&poly1305, a, alen);
	crypto_onetimeauth_poly1305_update(&poly1305, z, (0x10 - alen) & 0xf);
	crypto_onetimeauth_poly1305_update(&poly1305, m, mlen);
	crypto_onetimeauth_poly1305_update(&poly1305, z, (0x10 - mlen) & 0xf);
	le64enc(len64le, alen);
	crypto_onetimeauth_poly1305_update(&poly1305, len64le, 8);
	le64enc(len64le, mlen);
	crypto_onetimeauth_poly1305_update(&poly1305, len64le, 8);
	crypto_onetimeauth_poly1305_final(&poly1305, h);

	sodium_memzero(&poly1305, sizeof poly1305);
	sodium_memzero(k_, sizeof k_);
}

static void
compressauth(unsigned char t[static 24],
#ifdef DAENCE_GENERATE_KAT
    unsigned char v_h[static restrict 32],
    unsigned char v_u[static restrict 32],
#endif
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *a, unsigned long long alen,
    const unsigned char k[static 96])
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

	/* Tag generation: t, _ := HXChaCha_k0(h1 || h2) */
	crypto_core_hchacha20(u, h1, k0, sigma);
#ifdef DAENCE_GENERATE_KAT
	memcpy(v_h, h, sizeof h);
	memcpy(v_u, u, 32);
#endif
	crypto_core_hchacha20(u, h2, u, sigma);
	memcpy(t, u, 24);

	/* paranoia */
	sodium_memzero(h, sizeof h);
	sodium_memzero(u, sizeof u);
}

void
crypto_dae_chachadaence_test(unsigned char *c,
#ifdef DAENCE_GENERATE_KAT
    unsigned char v_h[static restrict 32],
    unsigned char v_u[static restrict 32],
#endif
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *a, unsigned long long alen,
    const unsigned char k[static 64])
{
	const unsigned char *k0 = k;	/* k0 := k[0..32] */

	/* c[0..24] := HXChaCha_k0(Poly1305^2_{k1,k2}(a,m)) */
	compressauth(c,
#ifdef DAENCE_GENERATE_KAT
	    v_h, v_u,
#endif
	    m, mlen, a, alen, k);

	/*
	 * Stream cipher:
	 *	c[24..24+mlen] := m[0..mlen]
	 *	    ^ XChaCha_k0(t @ c[0..24])
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
#ifdef DAENCE_GENERATE_KAT
	unsigned char v_h[32], v_u[32];
#endif
	unsigned char t[32], t_[32];
	int ret;

	/*
	 * Stream cipher:
	 *	m[0..mlen] := c[24..24+mlen]
	 *	    ^ XChaCha_k0(t' @ c[0..24])
	 */
	crypto_stream_xchacha20_xor(m, c + 24, mlen, c, k0);

	/* t := HXChaCha_k0(Poly1305^2_{k1,k2}(a,m)) */
	compressauth(t,
#ifdef DAENCE_GENERATE_KAT
	    v_h, v_u,
#endif
	    m, mlen, a, alen, k);

	/* Verify tag: c[0..24] ?= t (no crypto_verify_24) */
	memcpy(t_, c, 24);
	memset(t + 24, 0, 8);
	memset(t_ + 24, 0, 8);
	ret = crypto_verify_32(t_, t);
	if (ret)
		sodium_memzero(m, mlen); /* paranoia */

	/* paranoia */
	sodium_memzero(t, sizeof t);
	sodium_memzero(t_, sizeof t_);
#ifdef DAENCE_GENERATE_KAT
	sodium_memzero(v_h, sizeof v_h);
	sodium_memzero(v_u, sizeof v_u);
#endif

	return ret;
}

#ifdef DAENCE_GENERATE_KAT

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
	0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f, 0x70,
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
	unsigned char h[32], u[32];
	unsigned char c[24 + sizeof m], m_[sizeof m];
	unsigned i;
	int ret = 0;

	for (i = 0; i <= sizeof m; i++) {
		/* paranoia */
		memset(h, 0, sizeof h);
		memset(u, 0, sizeof u);
		memset(c, 0, sizeof c);
		memset(m_, 0, sizeof m_);

		/* test */
		crypto_dae_chachadaence_test(c,
		    h,u, m, i, a, sizeof a, k);
		if (crypto_dae_chachadaence_open(m_, c,
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

#endif	/* DAENCE_GENERATE_KAT */

#include "tweetdaence.h"	/* declares prototypes */
#include "tweetnacl.h"
#define FOR(i,n) for (i = 0;i < n;++i)
typedef unsigned char u8;
typedef unsigned long long u64;
static const u8 sigma[] = "expand 32-byte k";

static void prf(u8 *t,const u8 *m,u64 mlen,
    const u8 *a,u64 alen,const u8 *k)
{
  u8 k1[32],k2[32],ham[64],h[32],i;
  FOR(i,16) { k1[i] = k[32 + i]; k1[16 + i] = 0; }
  FOR(i,16) { k2[i] = k[48 + i]; k2[16 + i] = 0; }
  crypto_onetimeauth_poly1305(ham,a,alen,k1);
  crypto_onetimeauth_poly1305(ham + 16,a,alen,k2);
  crypto_onetimeauth_poly1305(ham + 32,m,mlen,k1);
  crypto_onetimeauth_poly1305(ham + 48,m,mlen,k2);
  crypto_onetimeauth_poly1305(h,ham,64,k1);
  crypto_onetimeauth_poly1305(h + 16,ham,64,k2);
  crypto_core_hsalsa20(t,h,k,sigma);
  crypto_core_hsalsa20(t,h + 16,t,sigma);
}
void crypto_dae_salsa20poly1305(u8 *c,const u8 *m,
    u64 mlen,const u8 *a,u64 alen,const u8 *k)
{
  u8 t[32],i;
  prf(t,m,mlen,a,alen,k);
  FOR(i,24) c[i] = t[i];
  crypto_stream_xsalsa20_xor(c + 24,m,mlen,c,k);
}
int crypto_dae_salsa20poly1305_open(u8 *m,const u8 *c,
    u64 mlen,const u8 *a,u64 alen,const u8 *k)
{
  u8 t[32],t_[32];
  u64 i;
  crypto_stream_xsalsa20_xor(m,c + 24,mlen,c,k);
  prf(t,m,mlen,a,alen,k);
  FOR(i,24) t_[i] = c[i];
  FOR(i,8) t[24 + i] = t_[24 + i] = 0;
  if (crypto_verify_32(t,t_)) {
    FOR(i,mlen) m[i] = 0;
    return -1;
  }
  return 0;
}

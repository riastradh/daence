#include "crypto_aead.h"
#include "salsa20daence.h"

int crypto_aead_encrypt(
  unsigned char *c,unsigned long long *clen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k
)
{
  crypto_dae_salsa20daence(c,m,mlen,ad,adlen,k);
  *clen = mlen + 24;
  return 0;
}

int crypto_aead_decrypt(
  unsigned char *m,unsigned long long *mlen,
  unsigned char *nsec,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
)
{
  if (clen < 24) return -1;
  *mlen = clen - 24;
  return crypto_dae_salsa20daence_open(m,c,clen - 24,ad,adlen,k);
}

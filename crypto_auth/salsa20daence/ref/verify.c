#include "crypto_auth.h"
#include "crypto_aead_salsa20daence.h"

int crypto_auth(unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
  unsigned long long clen;
  return crypto_aead_salsa20daence_encrypt(
    h,&clen,(const void *)0,0,in,inlen,(const void *)0,(const void *)0,k);
}

int crypto_auth_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
  unsigned long long mlen;
  return crypto_aead_salsa20daence_decrypt(
    (void *)0,&mlen,(void *)0,h,24,in,inlen,(const void *)0,k);
}

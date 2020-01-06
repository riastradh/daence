#ifndef TWEETDAENCE_H
#define TWEETDAENCE_H
#define crypto_dae_PRIMITIVE "salsa20poly1305"
#define crypto_dae crypto_dae_salsa20poly1305
#define crypto_dae_open crypto_dae_salsa20poly1305_open
#define crypto_dae_KEYBYTES crypto_dae_salsa20poly1305_KEYBYTES
#define crypto_dae_TAGBYTES crypto_dae_salsa20poly1305_TAGBYTES
#define crypto_dae_salsa20poly1305_tweet_KEYBYTES 64
#define crypto_dae_salsa20poly1305_tweet_TAGBYTES 24
void crypto_dae_salsa20poly1305_tweet(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,unsigned long long,const unsigned char *);
int crypto_dae_salsa20poly1305_tweet_open(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,unsigned long long,const unsigned char *);
#define crypto_dae_salsa20poly1305_tweet_VERSION "-"
#define crypto_dae_salsa20poly1305 crypto_dae_salsa20poly1305_tweet
#define crypto_dae_salsa20poly1305_open crypto_dae_salsa20poly1305_tweet_open
#define crypto_dae_salsa20poly1305_KEYBYTES crypto_dae_salsa20poly1305_tweet_KEYBYTES
#define crypto_dae_salsa20poly1305_TAGBYTES crypto_dae_salsa20poly1305_tweet_TAGBYTES
#define crypto_dae_salsa20poly1305_VERSION crypto_dae_salsa20poly1305_tweet_VERSION
#define crypto_dae_salsa20poly1305_IMPLEMENTATION "crypto_dae/salsa20poly1305/tweet"
#endif

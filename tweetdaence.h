#ifndef TWEETDAENCE_H
#define TWEETDAENCE_H
#define crypto_dae_PRIMITIVE "salsa20daence"
#define crypto_dae crypto_dae_salsa20daence
#define crypto_dae_open crypto_dae_salsa20daence_open
#define crypto_dae_KEYBYTES crypto_dae_salsa20daence_KEYBYTES
#define crypto_dae_TAGBYTES crypto_dae_salsa20daence_TAGBYTES
#define crypto_dae_salsa20daence_tweet_KEYBYTES 64
#define crypto_dae_salsa20daence_tweet_TAGBYTES 24
void crypto_dae_salsa20daence_tweet(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,unsigned long long,const unsigned char *);
int crypto_dae_salsa20daence_tweet_open(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,unsigned long long,const unsigned char *);
#define crypto_dae_salsa20daence_tweet_VERSION "-"
#define crypto_dae_salsa20daence crypto_dae_salsa20daence_tweet
#define crypto_dae_salsa20daence_open crypto_dae_salsa20daence_tweet_open
#define crypto_dae_salsa20daence_KEYBYTES crypto_dae_salsa20daence_tweet_KEYBYTES
#define crypto_dae_salsa20daence_TAGBYTES crypto_dae_salsa20daence_tweet_TAGBYTES
#define crypto_dae_salsa20daence_VERSION crypto_dae_salsa20daence_tweet_VERSION
#define crypto_dae_salsa20daence_IMPLEMENTATION "crypto_dae/salsa20daence/tweet"
#endif

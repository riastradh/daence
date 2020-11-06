Daence -- Deterministic Authenticated Encryption with no noNCEnse
=================================================================

Taylor ‘Riastradh’ Campbell <campbell+daence@mumble.net>

**Daence** is a deterministic authenticated cipher built out of
Poly1305 and either Salsa20 or ChaCha.  This repository contains the
source code for https://eprint.iacr.org/2020/067 -- the definition,
security analysis, reference implementation, and test vectors for
Daence -- as well as implementations in C (based on primitives in
either NaCl/TweetNaCl, SUPERCOP, libsodium, or BearSSL), Go,
JavaScript, and Rust, and a toy implementation in Python.

## Usage

If you and your friend share a secret 96-byte key for Salsa20-Daence:

- You can feed a header and a payload of up to 2^38 bytes into
  Daence-Encrypt, which will return an authenticated ciphertext
  concealing the payload; you can then send it to your friend in an
  envelope with the header on it in the clear.

  > c = Daence-Encrypt(key, header, payload)

- Your friend can feed the header and authenticated ciphertext into
  Daence-Decrypt, which either returns the payload, if it was genuine,
  or reports a forgery, if it was not.  (Your friend must immediately
  drop forgeries on the floor and forget about them.)

  > payload = Daence-Decrypt(key, header, c) or raise Forgery!

Unlike AES-GCM, ChaCha/Poly1305, or crypto_secretbox_xsalsa20poly1305,
you do not need to guarantee that every message has a unique number or
random initialization vector -- though if you have one you can put it
in the header to improve security by concealing when payloads are
repeated.

Then, as long as you and your friend encrypt no more than 2^52 messages
(or 2^90/L messages, if you and your friend can agree on a smaller
limit L < 2^38 on the number of bytes in each message):

- An adversary has no hope of distinguishing authenticated ciphertexts
  from uniform random noise -- except for noticing when you repeat the
  same (header, payload) pair under the same key.  (You can prevent
  adversaries from detecting repeated messages by putting a message
  sequence number or just randomization in the header or payload, for
  example.)

- An adversary has no hope of fooling your friend into accepting a
  payload and a header you did not send.  (Daence can also serve to
  authenticate messages without encryption if you simply specify an
  empty payload.)

Salsa20-Daence provides good performance and high security, and admits
a short implementation in terms of three primitives available in NaCl
and libsodium -- crypto_onetimeauth_poly1305, crypto_core_hsalsa20,
and crypto_stream_xsalsa20.  (The ChaCha-Daence variant is defined in
terms of parts that a ChaCha/Poly1305 implementation is likely to have
around, and has a smaller 64-byte key.)

Daence won't beat speed records for ChaCha/Poly1305, NaCl
crypto_secretbox_xsalsa20poly1305, or (hardware-accelerated) AES-GCM --
but who cares about speed when you accidentally repeated a nonce and
thereby leaked all your data to the adversary, including the key to
forgery?


## What's in this repository

```
COPYING                 2-clause BSD licence
Makefile                machine-readable instructions for building everything
README                  you are here
adv.py                  script to compute security bounds for various ciphers
beardaence.c            copypastable ChaCha-Daence using BearSSL
beardaence.h            header file with prototypes for beardaence.c
chachadaence.c          copypastable ChaCha-Daence using libsodium
chachadaence.h          header file with prototypes for chachadaence.c
crypto_aead/            SUPERCOP AEAD API (Salsa20-Daence only)
crypto_auth/            SUPERCOP PRF/authenticator API (Salsa20-Daence only)
daence.bib              bibliography
daence.tex              definition and analysis
go/                     Go module implementing Salsa20- and ChaCha-Daence
js/                     JavaScript (node/browser) implementing Salsa20-Daence
kat_chachadaence.c      reference implementation and test vector generation
kat_chachadaence.exp    expected values of test vectors
kat_salsa20daence.c     reference implementation and test vector generation
kat_salsa20daence.exp   expected values of test vectors
python/                 sample Python code using pyca cryptography
  chachadaence.py       WARNING: not safe for production use; see file
rust/                   Rust crate implementing Salsa20- and ChaCha-Daence
salsa20daence.c         copypastable Salsa20-Daence using NaCl/SUPERCOP
salsa20daence.h         header file with prototypes for salsa20daence.c
t_chachadaence.c        test program to verify chachadaence.c
t_salsa20daence.c       test program to verify crypto_aead/salsa20daence/ref
t_tweetdaence.c         test program to verify tweetdaence.c
tweetdaence.c           tweetnacl-style Salsa20-Daence in 48 lines plus header
tweetdaence.h           header file with prototypes for tweetdaence.c
tweetnacl/              tweetnacl-20140427 from <https://tweetnacl.cr.yp.to/>
```


## Building the specification and testing the implementation

You will need [libsodium](https://libsodium.org/) and a TeX
distribution.  Run

```
make
```

and let me know if anything goes wrong.  If it worked, you should have
a shiny new copy of the definition and analysis in `daence.pdf`, and
evidence that the reference implementation worked on your machine too.


## Measuring performance with [SUPERCOP](https://bench.cr.yp.to/)

Extract the SUPERCOP and symlink the Daence directories into it:

```
cd /path/to/supercop-YYYYMMDD
ln -s /path/to/daence/crypto_aead/salsa20daence crypto_aead/.
ln -s /path/to/daence/crypto_auth/salsa20daence crypto_auth/.
```

Now run SUPERCOP, as <https://bench.cr.yp.to/supercop.html> explains.

Running all of SUPERCOP takes a long time.  If you want to measure just
Salsa20-Daence, you will first need:

```
./do-part init
./do-part used
```

or at least:

```
./do-part init
./do-part crypto_verify 16
./do-part crypto_verify 32
./do-part crypto_core salsa20
./do-part crypto_core hsalsa20
./do-part crypto_stream salsa20
./do-part crypto_stream xsalsa20
./do-part crypto_onetimeauth poly1305
```

Then you can measure crypto_aead/salsa20daence or
crypto_auth/salsa20daence:

```
./do-part crypto_aead salsa20daence
./do-part crypto_auth salsa20daence
```

Raw output will be in: ```./bench/`hostname`/data```

(Plotting data left as an exercise for the conspiratorially-minded
reader.)

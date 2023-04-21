# -*- Mode: Python -*-

# Script to print table of advantages bounds for various message length
# and number limits against:
# - Daence
# - AES-SIV
# - AES-GCM-SIV (repeated nonce)
# - AES-GCM-SIV (random nonce)
# - AES-GCM (sequential 96-bit nonce)
# - ChaCha/Poly1305 (sequential nonce)


from __future__ import division
from __future__ import print_function

from math import ceil
from math import exp
from math import floor
from math import isinf
from math import isnan
from math import log
from math import log1p


def logsumexp(a):
    if len(a) == 0:
        return float('-inf')
    m = max(a)
    if isinf(m) and \
       min(array) != -m and \
       not any(isnan(x) for x in a):
        return m
    return m + log(sum(exp(x - m) for x in a))


def lgsumexp2(a):
    return logsumexp([log(2)*x for x in a])/log(2)


def lg(x):
    return log(x)/log(2)


def lg1p(x):
    return log1p(x)/log(2)


# Improved PRF/PRP switching lemma factor -- Theorem 2.3 of
# <https://cr.yp.to/papers.html#permutations>.
def lg_delta(s, lg_n):
    n = 2.**lg_n
    return -(n/2)*lg1p(-(n - 1)/2.**s)


def prf_prp(adv, s, lg_n):
    # (n^2/2)/2^s
    #return lgsumexp2([adv, 2*lg_n - s - 1])
    return adv + lg_delta(s, lg_n)


def daence(lgL, lgE, lgD):
    # A := (2 D + E^2 + E*(E - 1)/2) / 2^192
    lgA = lgsumexp2([1 + lgD, 2*lgE, 2*lgE - 1]) - 192

    # B := (D + E*(E - 1)/2) * ceil(L/16) / 2^206
    lgB = lgsumexp2([1 + lgD, 2*lgE - 1]) + 2*(lgL - 4) - 206

    return lgsumexp2([lgA, lgB])


# Phillip Rogaway and Thomas Shrimpton, `A Provable-Security Treatment
# of the Key-Wrap Problem', full version of paper in Serge Vaudenay
# (ed.), EUROCRYPT 2006, Springer LNCS 4004, pp. 373--390.
#
# https://web.cs.ucdavis.edu/~rogaway/papers/keywrap.html
#
def aessiv(lgL, lgE, lgD):
    n = 128                     # block size / tag size
    lg_p = lg(1)                # assume one header component
    lg_q = lgsumexp2([lgE, lgD]) # total number of queries
    lg_sigma = lgL + lg_q - 1 - 4 # total message blocks in all queries

    lg_adv = float('-inf')

    # Theorem 2
    lg_adv = lgsumexp2([lg_adv, lg_q - n])

    # Theorem 3
    lg_adv = lgsumexp2([lg_adv, lg_p + lg_q - n])

    if lg_q >= 128:
        return 0

    # PRF/PRP switching
    lg_adv = prf_prp(lg_adv, n, lg_sigma)

    return lg_adv


# Tetsu Iwata and Yannick Seurin, `Reconsidering the Security Bound of
# AES-GCM-SIV', IACR Transactions on Symmetric Cryptology, 2017(4),
# pp. 240--267.
#
# https://doi.org/10.13154/tosc.v2017.i4.240-267
#
def aesgcmsiv_dae(lgL, lgE, lgD):
    n = 128                     # block size
    kl = 256                    # key length
    lgQ = lg(1)                 # distinct nonces in encryption queries
    lgR = lgE                   # maximum times any nonce is repeated

    # Lengths of data are measured in blocks, hence - 4 (= /16 in log
    # space).
    k = lgL - 4                 # maximum length of msg in enc. or dec. query
    lg_l_a = lgL - 4            # maximum length of AD in enc. or dec. query
    lg_sigma = lgL + lgD - 1 - 4 # total message length in decryption queries

    # Theorem 3
    lg_adv = float('-inf')

    # first line
    t0 = lg(36) + 2*lgsumexp2([lgQ, lgD]) - (n + 1)
    t1 = lg(6) + lgsumexp2([lgQ, lgD]) - 3*n/4
    lg_adv = lgsumexp2([lg_adv, min(t0, t1)])

    # second line
    t0 = lgQ + 2*lgR - (n - 2*k)
    t1 = lgsumexp2([lgD, lg_sigma]) + lgsumexp2([lgR + k, lgD, lg_sigma]) - n
    lg_adv = lgsumexp2([lg_adv, t0, t1])

    # third line
    t0 = 2*lgsumexp2([lgQ, lgD]) - (kl + 1)
    t1 = lgQ + 2*lgR + lgsumexp2([k, lg_l_a]) - n
    t2 = lgR + lgD + lgsumexp2([k, lg_l_a]) - (n - 1)
    t3 = lgD - n
    t4 = lgQ + 2*lgR - (n - k - 1)
    lg_adv = lgsumexp2([lg_adv, t0, t1, t2, t3, t4])

    return lg_adv


# Tetsu Iwata, Keisuke Ohashi, and Kazuhiko Minematsu, `Breaking and
# Repairing GCM Security Proofs', full version of paper in Reihaneh
# Safavi-Naini and Ran Canetti (eds.), CRYPTO 2012, Springer LNCS 7417,
# pp. 39-49.
#
# https://eprint.iacr.org/2012/438
#
# (There is a newer paper on GCM improving the analysis for non-96-bit
# nonces, <https://eprint.iacr.org/2015/214.pdf>, but we don't consider
# that here.)
#
def aesgcm(lgL, lgE, lgD):
    n = 128                     # block size
    tau = 128                   # tag size
    lg_q = lgE                  # encryption queries
    lg_q_ = lgD                 # decryption queries / forgery attempts
    lg_l_A = lgL - 4            # maximum plaintext length in blocks
    lg_sigma = lgE + lg_l_A - 1 # total plaintext length (approximated)

    # Appendix C, Eq. (22)
    lg_a = lgsumexp2([lg_sigma, lg_q, lg_q_, lg(1)])
    return prf_prp(lg_q_ + lg_l_A - tau, n, lg_a)


def chacha20poly1305(lgL, lgE, lgD):
    # https://cr.yp.to/highspeed/naclcrypto-20090310.pdf, p. 30
    # https://eprint.iacr.org/2014/613, middle of p. 4
    return lgD + lg(8) + lgL - 4 - 106


# Tetsu Iwata and Yannick Seurin, `Reconsidering the Security Bound of
# AES-GCM-SIV', IACR Transactions on Symmetric Cryptology, 2017(4),
# pp. 240--267.
#
# https://doi.org/10.13154/tosc.v2017.i4.240-267
#
def aesgcmsiv_random(lgL, lgE, lgD):
    k = lgL - 4                 #  maximum message length in blocks

    # Corollary 1
    lg_adv = float('-inf')

    # first line
    t0 = lg(36) + 2*lgE - 129
    t1 = lg(6) + lgE - 96
    lg_adv = lgsumexp2([lg_adv, min(t0, t1)])

    # second line, with Adv^prf_AES(A') taken to be 9 N_E/2^{129 - 2k}
    t0 = lg(9) + lgE - (129 - 2*k)
    t1 = lg(9) + lgE - (126 - k)
    t2 = 4*lgE - lg(24) - 288
    lg_adv = lgsumexp2([lg_adv, t0, t1, t2])

    return lg_adv


def fmt_adv(adv):
    if adv < -32:
        return '$2^{%d}$' % (ceil(adv),)
    elif adv < 0:
        return '$\\bad{2^{%d}}$' % (ceil(adv),)
    else:
        return '$\\bad{1}$'


prev_label = None
for (label, lgL, lgE) in [
        # IP packet
        ('IP packet', 11, 20),
        ('IP packet', 11, 30),
        ('IP packet', 11, 40),
        ('IP packet', 11, 50),
        ('IP packet', 11, 79),
        # megabyte
        ('megabyte', 20, 10),
        ('megabyte', 20, 20),
        ('megabyte', 20, 30),
        ('megabyte', 20, 40),
        ('megabyte', 20, 50),
        ('megabyte', 20, 70),
        # gigabyte
        ('gigabyte', 30, 10),
        ('gigabyte', 30, 20),
        ('gigabyte', 30, 30),
        ('gigabyte', 30, 40),
        ('gigabyte', 30, 60),
        # AES-GCM maximum
        ('AES-GCM max', 36, 10),
        ('AES-GCM max', 36, 25),
        ('AES-GCM max', 36, 54),
        # ChaCha maximum
        ('ChaCha max', 38, 10),
        ('ChaCha max', 38, 25),
        ('ChaCha max', 38, 52),
]:
    if prev_label is not None:
        print(r'\\')
    lgD = lgE + 20              # assume a million forgeries per legit message
    #lgD = lgE                   # assume as many forgeries as legit messages
    if prev_label == label:
        prefix = ''
    else:
        prefix = '\llap{%s: }' % (label,)
    prev_label = label
    print('%s$2^{%d}$ & $2^{%d}$' % (prefix, lgL, lgE))
    print('& %s %% Daence' % (fmt_adv(daence(lgL, lgE, lgD)),))
    print('& %s %% AES-SIV' % (fmt_adv(aessiv(lgL, lgE, lgD)),))
    print('& %s %% AES-GCM-SIV, no nonce' %
        (fmt_adv(aesgcmsiv_dae(lgL, lgE, lgD)),))
    print('& %s %% AES-GCM-SIV, random nonce' %
        (fmt_adv(aesgcmsiv_random(lgL, lgE, lgD)),))
    print('& %s %% AES-GCM, sequential 96-bit nonce' %
        (fmt_adv(aesgcm(lgL, lgE, lgD)),))
    print('& %s %% ChaCha20/Poly1305' %
        (fmt_adv(chacha20poly1305(lgL, lgE, lgD)),))

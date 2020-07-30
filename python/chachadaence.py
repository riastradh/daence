# -*- Mode: Python -*-

### XXX XXX XXX WARNING WARNING WARNING XXX XXX XXX ###
###
### This code is not fit for anything more serious than interactive
### experimentation, because the pyca cryptography library doesn't have a
### way to compute the HChaCha function, and although we can compute it
### in terms of ChaCha, it is only with 32-bit addition on secrets --
### which cannot be done in Python without timing side channels.
###
### XXX XXX XXX WARNING WARNING WARNING XXX XXX XXX

# Copyright (c) 2020 Taylor R. Campbell
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.exceptions import InvalidTag


ZERO64 = bytearray([0] * 64)


def chacha(i, k):
    assert len(i) == 16
    alg = ChaCha20(k, i)
    cipher = Cipher(alg, mode=None, backend=default_backend())
    return cipher.encryptor().update(ZERO64)


SIGMA32 = struct.unpack('<IIII', b'expand 32-byte k')


def hchacha(i, k):
    assert len(i) == 16
    o = chacha(i, k)
    # XXX XXX XXX THIS IS NOT SAFE TO COMPUTE IN PYTHON XXX XXX XXX
    o32 = list(struct.unpack('<IIIIIIIIIIIIIIII', o))
    i32 = struct.unpack('<IIII', i)
    o32[0] = (o32[0] - SIGMA32[0]) & 0xffffffff
    o32[1] = (o32[1] - SIGMA32[1]) & 0xffffffff
    o32[2] = (o32[2] - SIGMA32[2]) & 0xffffffff
    o32[3] = (o32[3] - SIGMA32[3]) & 0xffffffff
    o32[12] = (o32[12] - i32[0]) & 0xffffffff
    o32[13] = (o32[13] - i32[1]) & 0xffffffff
    o32[14] = (o32[14] - i32[2]) & 0xffffffff
    o32[15] = (o32[15] - i32[3]) & 0xffffffff
    return struct.pack('<IIIIIIII', *(o32[0:4] + o32[12:16]))
    # XXX XXX XXX


def chacha_stream_xor(m, n, k):
    assert len(n) == 12
    alg = ChaCha20(k, bytearray([0] * 4) + n)
    cipher = Cipher(alg, mode=None, backend=default_backend())
    return cipher.encryptor().update(m)


def xchacha_stream_xor(m, n, k):
    assert len(n) == 24
    subkey = hchacha(n[0:16], k)
    return chacha_stream_xor(m, bytearray([0] * 4) + n[16:24], subkey)


def _compressauth(m, a, k):
    k0 = k[0:32]
    k1 = k[32:48] + bytearray([0] * 16)
    k2 = k[48:64] + bytearray([0] * 16)

    p1 = Poly1305(k1)
    p2 = Poly1305(k2)
    p1.update(a)
    p2.update(a)
    if len(a) & 0xf:
        pad = bytearray([0] * (16 - (len(a) & 0xf)))
        p1.update(pad)
        p2.update(pad)

    p1.update(m)
    p2.update(m)
    if len(m) & 0xf:
        pad = bytearray([0] * (16 - (len(m) & 0xf)))
        p1.update(pad)
        p2.update(pad)

    len64 = struct.pack('<QQ', len(a), len(m))
    p1.update(len64)
    p2.update(len64)

    h1 = p1.finalize()
    h2 = p2.finalize()

    u0 = hchacha(h1, k0)
    u = hchacha(h2, u0)

    return u[0:24]


def crypto_dae_chachadaence(m, a, k):
    t = _compressauth(m, a, k)
    return t + xchacha_stream_xor(m, t, k[0:32])


def crypto_dae_chachadaence_open(c, a, k):
    m = xchacha_stream_xor(c[24:], c[0:24], k[0:32])
    t = _compressauth(m, a, k)
    if not bytes_eq(bytes(c[0:24]), bytes(t)):
        raise InvalidTag
    return m


def crypto_dae_chachadaence_selftest():
    k = bytearray([
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
	0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
	0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
	0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
	0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
    ])
    a = bytearray([
	0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
	0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
    ])
    m = bytearray([
		0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
		0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
		0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,
		0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f, 0x70,
    ])
    c = bytearray([
	0x99,0x76,0x70,0x9c,0x45,0x3c,0x8f,0x94,
	0xe4,0x92,0xef,0xa7,0x70,0xe3,0xc2,0x21,
	0xe0,0x8e,0xa6,0xa0,0xe5,0x88,0xd5,0x4e,
	0x22,0x7d,0x2c,0x0c,0xde,0xe4,0x08,0xbc,
	0xe9,0xd0,0x53,0x2a,0x3a,0x36,0x27,0x01,
	0x0f,0x11,0xf2,0xb2,0xe4,0x72,0x67,0xe5,
	0x33,0xe9,0x5a,0xa3,0xb2,0xe7,0x1e,0xfb, 0x68,
    ])

    c0 = crypto_dae_chachadaence(m, a, k)
    if c0 != c:
        raise Exception('ChaCha-Daence encrypt self-test failed')

    m0 = crypto_dae_chachadaence_open(c, a, k)
    if m0 != m:
        raise Exception('ChaCha-Daence decrypt self-test failed')

    c0 = bytearray(c0)
    c0[18] ^= 0x10;
    try:
        crypto_dae_chachadaence_open(c0, a, k)
    except InvalidTag:
        pass
    else:
        raise Exception('ChaCha-Daence verify forgery self-test failed')


crypto_dae_chachadaence_selftest()

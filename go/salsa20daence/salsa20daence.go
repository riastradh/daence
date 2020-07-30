/*-
 * Copyright (c) 2020 Taylor R. Campbell
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

package salsa20daence

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20/salsa"
)

type salsa20daence struct {
	k0 [32]byte
	k1 [32]byte
	k2 [32]byte
	k3 [32]byte
	k4 [32]byte
}

func New(key []byte) (cipher.AEAD, error) {
	if len(key) != 96 {
		return nil, errors.New("salsa20daence: key must be 96 bytes")
	}
	d := new(salsa20daence)
	copy(d.k0[0:32], key[0:32])
	copy(d.k1[0:16], key[32:48])
	copy(d.k2[0:16], key[48:64])
	copy(d.k3[0:16], key[64:80])
	copy(d.k4[0:16], key[80:96])
	return d, nil
}

func (d *salsa20daence) NonceSize() int {
	return 0
}

func (d *salsa20daence) Overhead() int {
	return 24
}

func (d *salsa20daence) compressAuth(t, m, a []byte) {
	var ham [64]byte
	var ha1, ha2, hm1, hm2 [16]byte
	var h3 [16]byte
	var h4 [16]byte
	var u0, u [32]byte

	poly1305.Sum(&ha1, a, &d.k1)
	poly1305.Sum(&ha2, a, &d.k2)
	poly1305.Sum(&hm1, m, &d.k1)
	poly1305.Sum(&hm2, m, &d.k2)
	copy(ham[0:16], ha1[:])
	copy(ham[16:32], ha2[:])
	copy(ham[32:48], hm1[:])
	copy(ham[48:64], hm2[:])
	poly1305.Sum(&h3, ham[:], &d.k3)
	poly1305.Sum(&h4, ham[:], &d.k4)

	salsa.HSalsa20(&u0, &h3, &d.k0, &salsa.Sigma)
	salsa.HSalsa20(&u, &h4, &u0, &salsa.Sigma)

	copy(t[:], u[0:24])
}

func (d *salsa20daence) Seal(dst, n, m, a []byte) []byte {
	if len(n) != 0 {
		panic("salsa20daence: nonempty nonce passed to Seal")
	}
	if uint64(len(m)) > 1<<38 {
		panic("salsa20daence: message too long")
	}

	var ret []byte
	if cap(dst) >= len(m)+24 {
		ret = dst[:len(m)+24]
	} else {
		ret = make([]byte, len(m)+24)
		copy(ret, dst)
	}
	out := ret[len(dst):]
	t, c := out[0:24], out[24:]

	var n0, n1 [16]byte
	var subkey [32]byte

	d.compressAuth(t, m, a)
	copy(n0[0:16], t[0:16])
	salsa.HSalsa20(&subkey, &n0, &d.k0, &salsa.Sigma)
	copy(n1[0:8], t[16:24])
	salsa.XORKeyStream(c, m, &n1, &subkey)

	return ret
}

func (d *salsa20daence) Open(dst, n, tc, a []byte) ([]byte, error) {
	if len(n) != 0 {
		panic("salsa20daence: nonempty nonce passed to Seal")
	}
	if uint64(len(tc)) > (1<<38)+24 {
		panic("salsa20daence: message too long")
	}

	t, c := tc[0:24], tc[24:]
	var ret []byte
	if cap(dst) >= len(c) {
		ret = dst[:len(c)]
	} else {
		ret = make([]byte, len(c))
		copy(ret, dst)
	}
	m := ret[len(dst):]

	var n0, n1 [16]byte
	var subkey [32]byte
	var t_ [24]byte

	copy(n0[0:16], t[0:16])
	salsa.HSalsa20(&subkey, &n0, &d.k0, &salsa.Sigma)
	copy(n1[0:8], t[16:24])
	salsa.XORKeyStream(m, c, &n1, &subkey)
	d.compressAuth(t_[:], m, a)
	if subtle.ConstantTimeCompare(t_[:], t) == 0 {
		for i := range m {
			m[i] = 0
		}
		return nil, errors.New("salsa20daence: forgery")
	}

	return ret, nil
}

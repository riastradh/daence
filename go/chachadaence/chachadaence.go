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

package chachadaence // mumble.net/~campbell/daence/go/chachadaence

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
)

type chachadaence struct {
	k0 [32]byte
	k1 [32]byte
	k2 [32]byte
}

func New(key []byte) (cipher.AEAD, error) {
	if len(key) != 64 {
		return nil, errors.New("chachadaence: key must be 64 bytes")
	}
	d := new(chachadaence)
	copy(d.k0[0:32], key[0:32])
	copy(d.k1[0:16], key[32:48])
	copy(d.k2[0:16], key[48:64])
	return d, nil
}

func (d *chachadaence) NonceSize() int {
	return 0
}

func (d *chachadaence) Overhead() int {
	return 24
}

func (d *chachadaence) compressAuth(t, m, a []byte) {
	var pad [16]byte

	p1 := poly1305.New(&d.k1)
	p2 := poly1305.New(&d.k2)

	p1.Write(a)
	p2.Write(a)
	if len(a)%16 != 0 {
		p1.Write(pad[len(a)%16:])
		p2.Write(pad[len(a)%16:])
	}

	p1.Write(m)
	p2.Write(m)
	if len(m)%16 != 0 {
		p1.Write(pad[len(m)%16:])
		p2.Write(pad[len(m)%16:])
	}

	var len64 [16]byte
	binary.LittleEndian.PutUint64(len64[0:8], uint64(len(a)))
	binary.LittleEndian.PutUint64(len64[8:16], uint64(len(m)))
	p1.Write(len64[:])
	p2.Write(len64[:])

	h1 := p1.Sum(nil)
	h2 := p2.Sum(nil)

	u0, _ := chacha20.HChaCha20(d.k0[:], h1)
	u, _ := chacha20.HChaCha20(u0, h2)

	copy(t, u[0:24])
}

func (d *chachadaence) Seal(dst, n, m, a []byte) []byte {
	if len(n) != 0 {
		panic("chachadaence: nonempty nonce passed to Seal")
	}
	if uint64(len(m)) > 1<<38 {
		panic("chachadaence: message too long")
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

	var n1 [12]byte

	d.compressAuth(t, m, a)
	subkey, _ := chacha20.HChaCha20(d.k0[:], t[0:16])
	copy(n1[4:12], t[16:24])
	chacha, _ := chacha20.NewUnauthenticatedCipher(subkey, n1[:])
	chacha.XORKeyStream(c, m)

	return ret
}

func (d *chachadaence) Open(dst, n, tc, a []byte) ([]byte, error) {
	if len(n) != 0 {
		panic("chachadaence: nonempty nonce passed to Seal")
	}
	if uint64(len(tc)) > (1<<38)+24 {
		panic("chachadaence: message too long")
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

	var n1 [12]byte
	var t_ [24]byte

	subkey, _ := chacha20.HChaCha20(d.k0[:], t[0:16])
	copy(n1[4:12], t[16:24])
	chacha, _ := chacha20.NewUnauthenticatedCipher(subkey, n1[:])
	chacha.XORKeyStream(m, c)
	d.compressAuth(t_[:], m, a)
	if subtle.ConstantTimeCompare(t_[:], t) == 0 {
		for i := range m {
			m[i] = 0
		}
		return nil, errors.New("chachadaence: forgery")
	}

	return ret, nil
}

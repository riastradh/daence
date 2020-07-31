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
	"bytes"
	"encoding/hex"
	"testing"
)

func Test(t *testing.T) {
	ks := "000102030405060708090a0b0c0d0e0f"
	ks += "101112131415161718191a1b1c1d1e1f"
	ks += "202122232425262728292a2b2c2d2e2f"
	ks += "303132333435363738393a3b3c3d3e3f"
	ks += "404142434445464748494a4b4c4d4e4f"
	ks += "505152535455565758595a5b5c5d5e5f"
	k, _ := hex.DecodeString(ks)

	as := "606162636465666768696a6b6c6d6e6f"
	a, _ := hex.DecodeString(as)

	ms := "707172737475767778797a7b7c7d7e7f"
	ms += "808182838485868788898a8b8c8d8e8f"
	ms += "90"
	m, _ := hex.DecodeString(ms)

	cs := "a5096e6cd6564131dcfbd186cb1e1372"
	cs += "8e2b6719b0bf719414fb8f328fca052a"
	cs += "cd4327d1371267961935566318553871"
	cs += "b90cc90829a9d960f9"
	c, _ := hex.DecodeString(cs)

	d, err := New(k)
	if err != nil {
		t.Fatal(err)
	}

	c0 := d.Seal(nil, []byte{}, m, a)
	if !bytes.Equal(c0, c) {
		c0s := hex.EncodeToString(c0)
		t.Errorf("seal: got %s, want %s", c0s, cs)
	}

	m0, err := d.Open(nil, []byte{}, c, a)
	if err != nil {
		t.Errorf("open: %s", err)
	}
	if !bytes.Equal(m0, m) {
		m0s := hex.EncodeToString(m0)
		t.Errorf("open: got %s, want %s", m0s, ms)
	}

	c0[18] ^= 0x04
	_, err = d.Open(nil, []byte{}, c0, a)
	if err == nil {
		t.Errorf("open: failed to detect forgery")
	}
}

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

(function(root, f) {
    'use strict'
    if (typeof module !== 'undefined' && module.exports)
        module.exports = f(require('tweetnacl'))
    else
        root.nacl.dae = f(root.nacl)
}(this, function(nacl) {
    'use strict'

    if (!nacl)
        throw new Error('tweetnacl not loaded')

    var sigma = new Uint8Array([ // `expand 32-byte k'
        0x65,0x78,0x70,0x61, 0x6e,0x64,0x20,0x33,
        0x32,0x2d,0x62,0x79, 0x74,0x65,0x20,0x6b,
    ])
    var crypto_core_hsalsa20 = nacl.lowlevel.crypto_core_hsalsa20
    var crypto_onetimeauth_poly1305 = nacl.lowlevel.crypto_onetimeauth
    var crypto_stream_xsalsa20_xor = nacl.lowlevel.crypto_stream_xor
    var crypto_verify_32 = nacl.lowlevel.crypto_verify_32

    function guarantee_array(a) {
        if (!(a instanceof Uint8Array))
            throw new TypeError('expected Uint8Array')
    }

    function guarantee_array_length(a, n) {
        guarantee_array(a)
        if (a.length !== n)
            throw new TypeError('expected Uint8Array of length ' + n)
    }

    function compressauth(t,tpos, m,mpos,mlen, a,apos,alen, k) {
        var k0 = k.slice(0,32)
        var k1 = k.slice(32,48)
        var k2 = k.slice(48,64)
        var k3 = k.slice(64,80)
        var k4 = k.slice(80,96)
        var ham = new Uint8Array(64)
        var h3 = new Uint8Array(16)
        var h4 = new Uint8Array(16)
        var u = new Uint8Array(32)
        var i

        crypto_onetimeauth_poly1305(ham,0, a,apos,alen, k1)
        crypto_onetimeauth_poly1305(ham,16, a,apos,alen, k2)
        crypto_onetimeauth_poly1305(ham,32, m,mpos,mlen, k1)
        crypto_onetimeauth_poly1305(ham,48, m,mpos,mlen, k2)
        crypto_onetimeauth_poly1305(h3,0, ham,0,64, k3)
        crypto_onetimeauth_poly1305(h4,0, ham,0,64, k4)
        crypto_core_hsalsa20(u, h3, k0, sigma)
        crypto_core_hsalsa20(u, h4, u, sigma)

        for (i = 0; i < 24; i++)
            t[tpos + i] = u[i]
    }

    function crypto_dae_salsa20daence(c,cpos, m,mpos,mlen, a,apos,alen, k) {
        compressauth(c,cpos, m,mpos,mlen, a,apos,alen, k)
        var t = c.slice(cpos, cpos + 24)
        crypto_stream_xsalsa20_xor(c,cpos+24, m,mpos,mlen, t, k)
        return 0
    }

    function crypto_dae_salsa20daence_open(m,mpos, c,cpos,clen, a,apos,alen, k)
    {
        if (clen < 24)
            return -1
        var mlen = clen - 24
        var t = new Uint8Array(32)
        var t_ = new Uint8Array(32)
        var i
        for (i = 0; i < 24; i++)
            t[i] = c[cpos + i]
        crypto_stream_xsalsa20_xor(m,mpos, c,cpos+24,mlen, t, k)
        compressauth(t_,0, m,mpos,mlen, a,apos,alen, k)
        if (crypto_verify_32(t,0, t_,0) !== 0) {
            for (i = 0; i < mlen; i++)
                m[mpos + i] = 0
            return -1
        }
        return 0
    }

    var dae = function(m, a, k) {
        guarantee_array(m)
        guarantee_array(a)
        guarantee_array_length(k, 96)
        var c = new Uint8Array(24 + m.length)
        crypto_dae_salsa20daence(c,0, m,0,m.length, a,0,a.length, k)
        return c
    }

    dae.open = function(c, a, k) {
        guarantee_array(c)
        guarantee_array(a)
        guarantee_array_length(k, 96)
        if (c.length < 24)
            return null
        var m = new Uint8Array(c.length - 24)
        if (crypto_dae_salsa20daence_open(m,0, c,0,c.length, a,0,a.length, k)
            !== 0)
            return null
        return m
    }

    dae.keyLength = 96
    dae.overheadLength = 24
    dae.lowlevel = {
        crypto_dae_KEYBYTES: 96,
        crypto_dae_TAGBYTES: 24,
        crypto_dae_salsa20daence: crypto_dae_salsa20daence,
        crypto_dae_salsa20daence_open: crypto_dae_salsa20daence_open,
    }

    dae.selftest = function() {
        var k = new Uint8Array([
	    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
	    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
	    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
	    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
	    0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
	    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	    0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
	    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
	    0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
	    0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
	    0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
        ])
        var a = new Uint8Array([
	    0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,
	    0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,
        ])
        var m = new Uint8Array([
	    0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,
	    0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,
	    0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
	    0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f, 0x90,
        ])
        var c = new Uint8Array([
	    0xa5,0x09,0x6e,0x6c,0xd6,0x56,0x41,0x31,
	    0xdc,0xfb,0xd1,0x86,0xcb,0x1e,0x13,0x72,
	    0x8e,0x2b,0x67,0x19,0xb0,0xbf,0x71,0x94,
	    0x14,0xfb,0x8f,0x32,0x8f,0xca,0x05,0x2a,
	    0xcd,0x43,0x27,0xd1,0x37,0x12,0x67,0x96,
	    0x19,0x35,0x56,0x63,0x18,0x55,0x38,0x71,
	    0xb9,0x0c,0xc9,0x08,0x29,0xa9,0xd9,0x60, 0xf9,
        ])
        var i

        var c0 = dae(m, a, k)
        if (c0.length !== c.length)
            throw new Error('self-test failed -- ciphertext length')
        for (i = 0; i < c.length; i++) {
            if (c0[i] !== c[i])
                throw new Error('self-test failed -- ciphertext byte ' + i)
        }

        var m0 = dae.open(c, a, k)
        if (m0.length !== m.length)
            throw new Error('self-test failed -- plaintext length')
        for (i = 0; i < m.length; i++) {
            if (m0[i] !== m[i])
                throw new Error('self-test failed -- plaintext byte ' + i)
        }

        c0[27] ^= 0x20
        if (dae.open(c0, a, k) !== null)
            throw new Error('self-test failed -- failed to detect forgery')
    }

    return dae
}))

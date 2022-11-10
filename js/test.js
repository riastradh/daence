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

const fs = require('fs')
const salsa20daence = require('./salsa20daence')
const test = require('tape')

const crypto_dae_salsa20daence =
    salsa20daence.lowlevel.crypto_dae_salsa20daence
const crypto_dae_salsa20daence_open =
    salsa20daence.lowlevel.crypto_dae_salsa20daence_open

function hexdec(s) {
    function hex(i) {
        const c = s.charCodeAt(i)
        if (0x30 <= c && c <= 0x39)
            return c - 0x30
        else if (0x41 <= c && c <= 0x46)
            return c - 0x41 + 0xA
        else if (0x61 <= c && c <= 0x66)
            return c - 0x61 + 0xa
        throw new Error('bad hex digit at ' + i)
    }
    if (s.length % 2)
        throw new Error('invalid hex string')
    u8 = new Uint8Array(s.length/2)
    for (let i = 0; i < s.length/2; i++) {
        hi = hex(2*i)
        lo = hex(2*i + 1)
        u8[i] = (hi << 4) | lo
    }
    return u8
}

const kat = JSON.parse(fs.readFileSync('kat_salsa20daence.json'))

test('self-test passes', t => {
    salsa20daence.selftest()
    t.end()
})

for (let i = 0; i < kat.length; i++) {
    test(`KAT${i} agrees`, t => {
        const k = hexdec(kat[i].k)
        const a = hexdec(kat[i].a)
        const m = hexdec(kat[i].m)
        const c = hexdec(kat[i].c)

        const c0 = salsa20daence(m, a, k)
        t.deepEqual(c0, c)
        const m0 = salsa20daence.open(c, a, k)
        t.deepEqual(m0, m)
        c0[19] ^= 0x02
        t.equal(salsa20daence.open(c0, a, k), null)

        const abuf = new Uint8Array(a.length + 2)
        const mbuf = new Uint8Array(m.length + 2)
        const cbuf = new Uint8Array(c.length + 2)
        const m0buf = new Uint8Array(m0.length + 2)
        const c0buf = new Uint8Array(c0.length + 2)

        abuf[0] = abuf[a.length + 1] = 0x4e
        mbuf[0] = mbuf[m.length + 1] = 0x55
        cbuf[0] = cbuf[c.length + 1] = 0x3c
        m0buf[0] = m0buf[m.length + 1] = 0xe7
        c0buf[0] = c0buf[c.length + 1] = 0x1f

        abuf.set(a, 1)
        mbuf.set(m, 1)
        cbuf.set(c, 1)
        t.deepEqual(abuf.slice(1, a.length + 1), a)
        t.deepEqual(mbuf.slice(1, m.length + 1), m)
        t.deepEqual(cbuf.slice(1, c.length + 1), c)

        let rv
        rv = crypto_dae_salsa20daence(c0buf,1, mbuf,1,m.length,
          abuf,1,a.length, k)
        t.equal(0, rv)
        t.deepEqual(c0buf.slice(1, c.length + 1), c)

        rv = crypto_dae_salsa20daence_open(m0buf,1, cbuf,1,c.length,
          abuf,1,a.length, k)
        t.equal(0, rv)
        t.deepEqual(m0buf.slice(1, m.length + 1), m)

        c0buf[14] ^= 0x10
        rv = crypto_dae_salsa20daence_open(m0buf, 1, c0buf,1,c.length,
          abuf,1,a.length, k)
        t.equal(rv, -1)

        t.equal(abuf[0], 0x4e)
        t.equal(abuf[a.length + 1], 0x4e)
        t.equal(mbuf[0], 0x55)
        t.equal(mbuf[m.length + 1], 0x55)
        t.equal(cbuf[0], 0x3c)
        t.equal(cbuf[c.length + 1], 0x3c)
        t.equal(m0buf[0], 0xe7)
        t.equal(m0buf[m.length + 1], 0xe7)
        t.equal(c0buf[0], 0x1f)
        t.equal(c0buf[c.length + 1], 0x1f)
        t.end()
    })
}

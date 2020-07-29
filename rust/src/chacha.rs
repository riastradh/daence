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

use crypto::aead::{AeadEncryptor,AeadDecryptor};
use crypto::chacha20::ChaCha20;
use crypto::mac::Mac;
use crypto::poly1305::Poly1305;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::util::fixed_time_eq;

pub struct ChaChaDaence {
    key: [u8; 32],
    p1: Poly1305,
    p2: Poly1305,
    adlen: usize,
    finished: bool,
}

fn read_u32_le(buf: &[u8]) -> u32 {
    assert!(buf.len() >= 4);
    let x0 = buf[0] as u32;
    let x1 = buf[1] as u32;
    let x2 = buf[2] as u32;
    let x3 = buf[3] as u32;
    return x0 | (x1 << 8) | (x2 << 16) | (x3 << 24);
}

fn write_u32_le(buf: &mut[u8], x: u32) {
    assert!(buf.len() >= 4);
    buf[0] = x as u8;
    buf[1] = (x >> 8) as u8;
    buf[2] = (x >> 16) as u8;
    buf[3] = (x >> 24) as u8;
}

fn write_u64_le(buf: &mut[u8], x: u64) {
    assert!(buf.len() >= 8);
    buf[0] = x as u8;
    buf[1] = (x >> 8) as u8;
    buf[2] = (x >> 16) as u8;
    buf[3] = (x >> 24) as u8;
    buf[4] = (x >> 32) as u8;
    buf[5] = (x >> 40) as u8;
    buf[6] = (x >> 48) as u8;
    buf[7] = (x >> 56) as u8;
}

fn rol32(x: u32, n: u8) -> u32 {
    (x << n) | (x >> (32 - n))
}

macro_rules! quarterround {
    ($a:ident, $b:ident, $c:ident, $d:ident) => {
        $a = $a.wrapping_add($b); $d ^= $a; $d = rol32($d, 16);
        $c = $c.wrapping_add($d); $b ^= $c; $b = rol32($b, 12);
        $a = $a.wrapping_add($b); $d ^= $a; $d = rol32($d,  8);
        $c = $c.wrapping_add($d); $b ^= $c; $b = rol32($b,  7);
    }
}

fn hchacha(k: &[u8], i: &[u8], o: &mut [u8]) {
    let c = b"expand 32-byte k";
    let mut y0 = read_u32_le(&c[0..4]);
    let mut y1 = read_u32_le(&c[4..8]);
    let mut y2 = read_u32_le(&c[8..12]);
    let mut y3 = read_u32_le(&c[12..16]);
    let mut y4 = read_u32_le(&k[0..4]);
    let mut y5 = read_u32_le(&k[4..8]);
    let mut y6 = read_u32_le(&k[8..12]);
    let mut y7 = read_u32_le(&k[12..16]);
    let mut y8 = read_u32_le(&k[16..20]);
    let mut y9 = read_u32_le(&k[20..24]);
    let mut y10 = read_u32_le(&k[24..28]);
    let mut y11 = read_u32_le(&k[28..32]);
    let mut y12 = read_u32_le(&i[0..4]);
    let mut y13 = read_u32_le(&i[4..8]);
    let mut y14 = read_u32_le(&i[8..12]);
    let mut y15 = read_u32_le(&i[12..16]);

    for _ in 0..20/2 {
        quarterround!( y0, y4, y8,y12);
        quarterround!( y1, y5, y9,y13);
        quarterround!( y2, y6,y10,y14);
        quarterround!( y3, y7,y11,y15);
        quarterround!( y0, y5,y10,y15);
        quarterround!( y1, y6,y11,y12);
        quarterround!( y2, y7, y8,y13);
        quarterround!( y3, y4, y9,y14);
    }

    write_u32_le(&mut o[0..4], y0);
    write_u32_le(&mut o[4..8], y1);
    write_u32_le(&mut o[8..12], y2);
    write_u32_le(&mut o[12..16], y3);
    write_u32_le(&mut o[16..20], y12);
    write_u32_le(&mut o[20..24], y13);
    write_u32_le(&mut o[24..28], y14);
    write_u32_le(&mut o[28..32], y15);
}

impl ChaChaDaence {
    pub fn new(key: &[u8], ad: &[u8]) -> ChaChaDaence {
        assert!(key.len() == 64);

        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];

        k1[0..16].copy_from_slice(&key[32..48]);
        k2[0..16].copy_from_slice(&key[48..64]);

        let mut p1 = Poly1305::new(&k1);
        let mut p2 = Poly1305::new(&k2);

        let pad = [0u8; 16];

        p1.input(ad);
        p2.input(ad);
        if (ad.len() % 16) != 0 {
            p1.input(&pad[ad.len() % 16..16]);
            p2.input(&pad[ad.len() % 16..16]);
        }

        let mut daence = ChaChaDaence {
            key: [0u8; 32],
            p1, p2,
            adlen: ad.len(),
            finished: false,
        };
        daence.key.copy_from_slice(&key[0..32]);

        daence
    }

    fn compressauth(&mut self, m: &[u8], t: &mut [u8]) {
        let pad = [0u8; 16];
        let mut len64 = [0u8; 16];
        let mut h1 = [0u8; 16];
        let mut h2 = [0u8; 16];
        let mut u = [0u8; 32];
        let mut t32 = [0u8; 32];

        self.p1.input(m);
        self.p2.input(m);
        if (m.len() % 16) != 0 {
            self.p1.input(&pad[m.len() % 16..16]);
            self.p2.input(&pad[m.len() % 16..16]);
        }

        write_u64_le(&mut len64[0..8], self.adlen as u64);
        write_u64_le(&mut len64[8..16], m.len() as u64);
        self.p1.input(&len64);
        self.p2.input(&len64);

        self.p1.raw_result(&mut h1);
        self.p2.raw_result(&mut h2);

        hchacha(&self.key, &h1, &mut u);
        hchacha(&u, &h2, &mut t32);
        for i in 0..24 {
            t[i] = t32[i];
        }
    }
}

impl AeadEncryptor for ChaChaDaence {
    fn encrypt(&mut self, m: &[u8], c: &mut [u8], t: &mut [u8]) {
        assert!(m.len() == c.len());
        assert!(!self.finished);
        self.finished = true;

        self.compressauth(m, t);
        ChaCha20::new_xchacha20(&self.key, t).process(m, c);
    }
}

impl AeadDecryptor for ChaChaDaence {
    fn decrypt(&mut self, c: &[u8], m: &mut [u8], t: &[u8]) -> bool {
        assert!(m.len() == c.len());
        assert!(!self.finished);
        self.finished = true;

        let mut t_ = [0u8; 24];

        ChaCha20::new_xchacha20(&self.key, t).process(c, m);
        self.compressauth(m, &mut t_);

        if !fixed_time_eq(t, &t_) {
            for i in 0..m.len() {
                m[i] = 0;
            }
            return false;
        }

        true
    }
}

#[cfg(test)]
mod test {
    use crypto::aead::{AeadEncryptor,AeadDecryptor};
    use std::iter::repeat;

    use chacha::ChaChaDaence;

    #[test]
    fn selftest() {
        let k: [u8; 64] = [
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
	    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
	    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
	    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
	    0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
	    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	    0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
        ];
        let a: [u8; 16] = [
	    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
	    0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
        ];
        let m = vec!(
	    0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
	    0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
	    0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,
	    0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f, 0x70,
        );
        let t: [u8; 24] = [
	    0x99,0x76,0x70,0x9c,0x45,0x3c,0x8f,0x94,
	    0xe4,0x92,0xef,0xa7,0x70,0xe3,0xc2,0x21,
	    0xe0,0x8e,0xa6,0xa0,0xe5,0x88,0xd5,0x4e,
        ];
        let c = vec!(
	    0x22,0x7d,0x2c,0x0c,0xde,0xe4,0x08,0xbc,
	    0xe9,0xd0,0x53,0x2a,0x3a,0x36,0x27,0x01,
	    0x0f,0x11,0xf2,0xb2,0xe4,0x72,0x67,0xe5,
	    0x33,0xe9,0x5a,0xa3,0xb2,0xe7,0x1e,0xfb, 0x68,
        );
        let mut m_: Vec<u8> = repeat(0).take(m.len()).collect();
        let mut c_: Vec<u8> = repeat(0).take(c.len()).collect();
        let mut t_ = [0u8; 24];

        ChaChaDaence::new(&k, &a).encrypt(&m, &mut c_, &mut t_);
        assert_eq!(c_, c);
        assert_eq!(t_, t);

        ChaChaDaence::new(&k, &a).decrypt(&c, &mut m_, &t);
        assert_eq!(m_, m);
    }
}

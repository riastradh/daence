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
use crypto::mac::Mac;
use crypto::poly1305::Poly1305;
use crypto::salsa20::Salsa20;
use crypto::salsa20::hsalsa20;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::util::fixed_time_eq;

pub struct Salsa20Daence {
    key: [u8; 32],
    p1: Poly1305,
    p2: Poly1305,
    p3: Poly1305,
    p4: Poly1305,
    finished: bool,
}

impl Salsa20Daence {
    pub fn new(key: &[u8], ad: &[u8]) -> Salsa20Daence {
        assert!(key.len() == 96);

        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        let mut k3 = [0u8; 32];
        let mut k4 = [0u8; 32];

        k1[0..16].copy_from_slice(&key[32..48]);
        k2[0..16].copy_from_slice(&key[48..64]);
        k3[0..16].copy_from_slice(&key[64..80]);
        k4[0..16].copy_from_slice(&key[80..96]);

        let mut p1 = Poly1305::new(&k1);
        let mut p2 = Poly1305::new(&k2);
        let mut p3 = Poly1305::new(&k3);
        let mut p4 = Poly1305::new(&k4);

        let mut ha1 = [0u8; 16];
        let mut ha2 = [0u8; 16];

        p1.input(ad);
        p2.input(ad);
        p1.raw_result(&mut ha1);
        p2.raw_result(&mut ha2);
        p1.reset();
        p2.reset();
        p3.input(&ha1);
        p4.input(&ha1);
        p3.input(&ha2);
        p4.input(&ha2);

        let mut daence = Salsa20Daence {
            key: [0u8; 32],
            p1, p2, p3, p4,
            finished: false,
        };
        daence.key.copy_from_slice(&key[0..32]);

        daence
    }

    fn compressauth(&mut self, m: &[u8], t: &mut [u8]) {
        let mut hm1 = [0u8; 16];
        let mut hm2 = [0u8; 16];
        let mut h3 = [0u8; 16];
        let mut h4 = [0u8; 16];
        let mut u = [0u8; 32];
        let mut t32 = [0u8; 32];

        self.p1.input(m);
        self.p2.input(m);
        self.p1.raw_result(&mut hm1);
        self.p2.raw_result(&mut hm2);
        self.p3.input(&hm1);
        self.p4.input(&hm1);
        self.p3.input(&hm2);
        self.p4.input(&hm2);
        self.p3.raw_result(&mut h3);
        self.p4.raw_result(&mut h4);

        hsalsa20(&self.key, &h3, &mut u);
        hsalsa20(&u, &h4, &mut t32);
        for i in 0..24 {
            t[i] = t32[i];
        }
    }
}

impl AeadEncryptor for Salsa20Daence {
    fn encrypt(&mut self, m: &[u8], c: &mut [u8], t: &mut [u8]) {
        assert!(m.len() as u64 <= 1u64 << 38);
        assert!(m.len() == c.len());
        assert!(!self.finished);
        self.finished = true;

        self.compressauth(m, t);
        Salsa20::new_xsalsa20(&self.key, t).process(m, c);
    }
}

impl AeadDecryptor for Salsa20Daence {
    fn decrypt(&mut self, c: &[u8], m: &mut [u8], t: &[u8]) -> bool {
        assert!(c.len() as u64 <= 1u64 << 38);
        assert!(c.len() == m.len());
        assert!(!self.finished);
        self.finished = true;

        let mut t_ = [0u8; 24];

        Salsa20::new_xsalsa20(&self.key, t).process(c, m);
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

    use salsa20::Salsa20Daence;

    #[test]
    fn selftest() {
        let k: [u8; 96] = [
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
        ];
        let a: [u8; 16] = [
	    0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,
	    0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,
        ];
        let m = vec!(
	    0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,
	    0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,
	    0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
	    0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f, 0x90,
        );
        let t: [u8; 24] = [
	    0xa5,0x09,0x6e,0x6c,0xd6,0x56,0x41,0x31,
	    0xdc,0xfb,0xd1,0x86,0xcb,0x1e,0x13,0x72,
	    0x8e,0x2b,0x67,0x19,0xb0,0xbf,0x71,0x94,
        ];
        let c = vec!(
	    0x14,0xfb,0x8f,0x32,0x8f,0xca,0x05,0x2a,
	    0xcd,0x43,0x27,0xd1,0x37,0x12,0x67,0x96,
	    0x19,0x35,0x56,0x63,0x18,0x55,0x38,0x71,
	    0xb9,0x0c,0xc9,0x08,0x29,0xa9,0xd9,0x60, 0xf9,
        );
        let mut m_: Vec<u8> = repeat(0).take(m.len()).collect();
        let mut c_: Vec<u8> = repeat(0).take(c.len()).collect();
        let mut t_ = [0u8; 24];

        Salsa20Daence::new(&k, &a).encrypt(&m, &mut c_, &mut t_);
        assert_eq!(c_, c);
        assert_eq!(t_, t);

        assert!(Salsa20Daence::new(&k, &a).decrypt(&c, &mut m_, &t));
        assert_eq!(m_, m);

        c_[18] ^= 0x04;
        assert!(!Salsa20Daence::new(&k, &a).decrypt(&c_, &mut m_, &t));

        t_[3] ^= 0x80;
        assert!(!Salsa20Daence::new(&k, &a).decrypt(&c, &mut m_, &t_));
    }
}

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

extern crate crypto_daence;
extern crate crypto;
extern crate structopt;

use crypto_daence::salsa20::Salsa20Daence;
use crypto::aead::{AeadEncryptor,AeadDecryptor};
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::option::Option;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "example", about = "Salsa20-Daence encryption program")]
struct Opt {
    #[structopt(short, long)]
    encrypt: bool,
    #[structopt(short, long)]
    decrypt: bool,
    #[structopt(parse(from_os_str), short, long)]
    keyfile: PathBuf,
    #[structopt(parse(from_os_str), short, long)]
    adfile: Option<PathBuf>,
    #[structopt(parse(from_os_str), short, long)]
    infile: PathBuf,
    #[structopt(parse(from_os_str), short, long)]
    outfile: PathBuf,
}

fn readfile(path: PathBuf) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut file = File::open(path)?;
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

fn main() -> io::Result<()> {
    let opt = Opt::from_args();
    if opt.encrypt == opt.decrypt {
        eprintln!("encrypt or decrypt, but not both");
        std::process::exit(1)
    }
    let key = readfile(opt.keyfile)?;
    let ad = match opt.adfile {
        None => Vec::new(),
        Some(adfile) => readfile(adfile)?,
    };
    let input = readfile(opt.infile)?;
    let mut outfile = File::create(opt.outfile)?;
    let mut cipher = Salsa20Daence::new(&key, &ad);
    let output =
        if opt.encrypt {
            let m = &input;
            let mut output = vec![0; 24 + m.len()];
            let (mut t, mut c) = output[..].split_at_mut(24);
            cipher.encrypt(&m, &mut c, &mut t);
            output
        } else {
            if input.len() < 24 {
                eprintln!("ciphertext too short");
                std::process::exit(2)
            }
            let t = &input[0..24];
            let c = &input[24..];
            let mut output = vec![0; c.len()];
            let mut m = &mut output;
            if !cipher.decrypt(&c, &mut m, &t) {
                eprintln!("forgery");
                std::process::exit(2)
            }
            output
        };
    outfile.write_all(&output)?;
    Ok(())
}

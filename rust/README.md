Daence in Rust
==============

Daence is a deterministic authenticated cipher built out of Poly1305
and either Salsa20 or ChaCha, with good performance and high security
even for extremely large volumes of data.  This is a Rust
implementation of Salsa20-Daence and ChaCha-Daence based on the
[rust-crypto](https://docs.rs/rust-crypto/) crate.

To try it out, run `cargo test`, or run the example program
`examples/main.rs` with

```
cargo run --example main --encrypt \
  --keyfile key --infile foo.txt --outfile foo.enc
cargo run --example main --decrypt \
  --keyfile key --infile foo.enc --outfile foo.dec
```

where `keyfile` contains a 96-byte key (in raw binary).

> **WARNING: `examples/main.rs` is an example program for illustration,
> not a serious file encryption tool.  For example, the 96-byte key
> must be chosen uniformly at random; it cannot simply be a password.**

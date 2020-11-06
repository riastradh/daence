ChaCha-Daence in Python
=======================

ChaCha-Daence is a deterministic authenticated cipher built out of
ChaCha and Poly1305 with good performance and high security even for
extremely large volumes of data.  `chachadaence.py` is a Python
illustration of ChaCha-Daence, **NOT FIT FOR USE IN PRODUCTION**, based
on the pyca [cryptography.io](https://cryptography.io) library.

- **WARNING: Daence is new and this software has only been lightly tested.**

> **WARNING: This is ONLY FOR ILLUSTRATION.  The pyca cryptography.io
> library doesn't provide HChaCha, and although it provides the ChaCha
> core function, which can be used to compute HChaCha, there's no
> straightforward way in Python to safely compute the 32-bit additions
> needed to compute HChaCha from ChaCha.**

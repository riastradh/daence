Go Daence
=========

Daence is a deterministic authenticated cipher built out of Poly1305
and either Salsa20 or ChaCha, with good performance and high security
even for extremely large volumes of data.  This is a Go implementation
of Salsa20-Daence and ChaCha-Daence based on
[`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto), using
the [`AEAD`](https://pkg.go.dev/crypto/cipher?tab=doc#AEAD) interface
from [`crypto/cipher`](https://pkg.go.dev/crypto/cipher).

- **WARNING: Daence is a work in progress.  The definition and API may
  change.  There may be bugs or mistakes in the security analysis.**

To try it out, run `go test ./...`.  For experiments you can import
`mumble.net/~campbell/daence.git/go/salsa20daence` or
`mumble.net/~campbell/daence.git/go/chachadaence`, but **WARNING: these
URLs are not yet permanent.**

```
import "mumble.net/~campbell/daence.git/go/chachadaence"

func main() {
	key := [64]byte{0x01, ...}
	associatedData := []byte("header")
	message := []byte("payload")

	d, _ := chachadaence.New(k)

	// Daence does not take a nonce, so pass an empty slice
	// []byte{} where the AEAD.Seal interface expects a nonce.
	ciphertext := d.Seal(nil, []byte{}, message, associatedData)
	...
	message1, err := d.Open(nil, []byte{}, ciphertext, associatedData)
	if err != nil {
		// reject forgery
	}
	...
}
```

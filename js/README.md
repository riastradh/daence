Salsa20-Daence in JavaScript
============================

Salsa20-Daence is a deterministic authenticated cipher built out of
Salsa20 and Poly1305 with good performance and high security even for
extremely large volumes of data.  This is a JavaScript implementation
of Salsa20-Daence, for either in-browser or node.js use, based on
[TweetNaCl.js](https://github.com/dchest/tweetnacl-js).

To try it out, run `npm install` and then:

- Load `demo.html` in your favourite web browser.
- Invoke `npm test` to run the node tests.
  (Run `cd .. && make js/kat_salsa20daence.json` to generate the
  known-answer test data from the Git repository.)

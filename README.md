kruptein
========
crypto; from `kruptein` to hide or conceal.

[![npm](https://img.shields.io/npm/v/kruptein.svg)](https://npmjs.com/package/kruptein)
![Downloads](https://img.shields.io/npm/dm/kruptein.svg)
[![Known Vulnerabilities](https://snyk.io/test/github/jas-/kruptein/badge.svg)](https://snyk.io/test/github/jas-/kruptein)
[![Node.js CI](https://github.com/jas-/kruptein/actions/workflows/node.js.yml/badge.svg)](https://github.com/jas-/kruptein/actions/workflows/node.js.yml)


Install
-------
To install `npm install kruptein`

Methods
-------
*   `.set(secret, plaintext, [aad], callback)`
*   `.get(secret, ciphertext, [{at: auth_tag, aad: aad}], callback)`

Options
-------
Industry standards are used for the algorithm, hashing algorithm, key & IV sizes. The default key derivation
is pbkdf2, however use of the scrypt derivation function can be enabled.
*   `algorithm`: (Optional) Cipher algorithm from `crypto.getCiphers()`. Default: `aes-256-gcm`.
*   `hashing`: (Optional) Hash algorithm from `crypto.getHashes()`. Default: `sha512`.
*   `encodeas`: (Optional) Output encoding. Currently supports `binary`, `hex`, & `base64`. Default: `base64`.
*   `key_size`: (Optional) Key size bytes (should match block size of algorithm). Default: `32`
*   `iv_size`: (Optional) IV size bytes. Default: `16`.
*   `at_size`: (Optional) Authentication tag size. Applicable to `gcm` & `ocb` cipher modes. Default: `128`.
*   `use_scrypt`: (Optional) Use `.scrypt()` to derive a key. Requires node > v10. Default/Fallback: `.pbkdf2()`.
*   `use_asn1`: (Optional) Disable the default ASN.1 encoding. Default: true

Usage
-----
When selecting an algorithm from `crypto.getCiphers()` the
`iv` and `key_size` values are calculated auto-magically to make implementation
easy.

You can always define your own if the defaults per algorithm and mode
aren't what you would like; see the `options` section above.

Create ciphertext from plaintext
-----------------
To create a new ciphertext object.

```javascript
const kruptein = require("kruptein")(opts);
let secret = "squirrel";

kruptein.set(secret, "Operation mincemeat was an example of deception", (err, ct) => {
  if (err)
    throw err;

  console.log(ct);
});
```

Get plaintext from ciphertext
------------------
To retrieve plaintext from a ciphertext object.

```javascript
const kruptein = require("kruptein")(opts);
let ciphertext, secret = "squirrel";

kruptein.get(secret, ciphertext, (err, pt) => {
  if (err)
    throw err;

  console.log(pt);
});
```

Output
------
The `.set()` method output depends on three factors; the `encodeas`,
`algorithm` and `use_asn1`.

For any algorithm that supports authentication (AEAD), the object
structure includes the `Authentication Tag` and the `Additional
Authentication Data` attribute and value.

When the `use_asn1` option is enabled (default is true), the result is an [ASN.1](https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/)
value using the `encodeas` value. While this is a more complex
encoding option, it helps standardize & minimize the resulting
ciphertext output.


Test harness
------------
The included test harness, invoked with `npm test`, makes every
attempt to trap and handle errors. Some of which come from side
channel or possible malability of the resultant ciphertext.

This can be seen within the `test/index.js` CI test harness under
the HMAC, AT & AAD validation test cases.


Contributing
------------
Contributions are welcome & appreciated!

Refer to the [contributing document](https://github.com/jas-/kruptein/blob/master/CONTRIBUTING.md)
to help facilitate pull requests.

License
-------
This software is licensed under the [MIT License](https://github.com/jas-/kruptein/blob/master/LICENSE).

Copyright Jason Gerfen, 2019 to 2022.

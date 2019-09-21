kruptein
========
crypto; from `kruptein` to hide or conceal

[![npm](https://img.shields.io/npm/v/kruptein.svg)](https://npmjs.com/package/kruptein)
![Downloads](https://img.shields.io/npm/dm/kruptein.svg)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/90c36e954a1e4cef850fcf93213b6635)](https://www.codacy.com/app/jas-/kruptein?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=jas-/kruptein&amp;utm_campaign=Badge_Grade)
[![Known Vulnerabilities](https://snyk.io/test/github/jas-/kruptein/badge.svg)](https://snyk.io/test/github/jas-/kruptein)
[![Build Status](https://travis-ci.org/jas-/kruptein.png?branch=master)](https://travis-ci.org/jas-/kruptein)
[![codecov](https://codecov.io/gh/jas-/kruptein/branch/master/graph/badge.svg)](https://codecov.io/gh/jas-/kruptein)

Install
-------
To install `npm install kruptein`

Methods
-------
*   `.set(secret, plaintext, [aad])`: Create plaintext from ciphertext
*   `.get(secret, ciphertext, [{at: auth_tag, aad: aad}])`: Create ciphertext from plaintext

Options
-------
*   `algorithm`: (Optional) Cipher algorithm from `crypto.getCiphers()`. Default: `aes-256-gcm`.
*   `hashing`: (Optional) Hash algorithm from `crypto.getHashes()`. Default: `sha512`.
*   `encodeas`: (Optional) Output encoding. Currently only supports `binary`.
*   `key_size`: (Optional) Key size bytes (should match block size of algorithm). Default: `32`
*   `iv_size`: (Optional) IV size bytes. Default: `16`.
*   `at_size`: (Optional) Authentication tag size. Applicable to `gcm` & `ocb` cipher modes. Default: `128`.
*   `use_scrypt`: (Optional) Use `.scrypt()` to derive a key. Requires node > v10. Default: `.pbkdf2()`.
*   `debug`: (Optional) Provides additional information about internal operations.

Tests
-----
To test use `npm test` or `node .test/vanilla.js`

Usage
-----
When selecting an algorithm from `crypto.getCiphers()` the
`iv` and `key_size` values are calculated auto-magically to make implementation 
easy.

You can always define your own if the defaults per algorithm and mode
aren't what you would like; see the `options` section above.

Create ciphertext from plaintext; default example
-----------------
To create a new ciphertext object.

```javascript
const kruptein = require('kruptein')(opts);
let ciphertext, secret = "squirrel";

kruptein.set(secret, 'Operation mincemeat was an example of deception', (err, ct) => {
  if (err)
    throw err;
    
  console.log(ct);
});
```

Create ciphertext from plaintext; using AEAD class of ciphers with a custom AAD
------------------------
To create new ciphertext providing custom 'additional authentication data'.

```javascript
const kruptein = require('kruptein')(opts);
let ciphertext, secret = "squirrel";

let aad = func_to_generate_aad();

ciphertext = kruptein.set(secret, 'Operation mincemeat was an example of deception', aad);
```

`.get(ciphertext)`
------------------
To retrieve plaintext; 

```javascript
const kruptein = require('kruptein')(opts);
let ciphertext, plaintext, ciphertext, secret = "squirrel";

plaintext = kruptein.get(secret, ciphertext);
```

`.get(ciphertext, [{at: auth_tag])`
-----------------------------------
To retrieve plaintext using an external authentication tag

```javascript
const kruptein = require('kruptein')(opts);
let ciphertext, plaintext, secret = "squirrel";

let at = func_to_provide_authentication_tag(ciphertext);

plaintext = kruptein.get(secret, ciphertext, at);
```

`.get(ciphertext, [{aad: aad}])`
--------------------------------
To retrieve plaintext using some optional additional authentication data

```javascript
const kruptein = require('kruptein')(opts);
let ciphertext, plaintext, secret = "squirrel";

let aad = func_to_provide_authentication_data();

plaintext = kruptein.get(secret, ciphertext, aad);
```

Output
------
The `.set()` method creates the following object;

Non-Authenticated Ciphers
-------------------------
For those ciphers that __DO NOT__ support [authentication modes](https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-develoment)
the following structure is returned.

```json
{
  'hmac': "<calculated hmac>",
  'ct': "<binary format of resulting ciphertext>",
  'iv': "<buffer format of generated/supplied iv>",
  'salt': "<buffer format of generated/supplied salt>"
}
```

Authenticated Ciphers
---------------------
For those ciphers that __DO__ support [authentication modes](https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-develoment)
the following structure is returned.

__Important__: Note that in the event additional authentication data (aad) is
not provided a digest of the derived key & iv is used.

```json
{
  'hmac': "<calculated hmac>",
  'ct': "<binary format of resulting ciphertext>",
  'iv': "<buffer format of generated/supplied iv>",
  'salt': "<buffer format of generated/supplied salt>",
  'at': "<buffer format of generated authentication tag>",
  'aad': "<buffer format of generated/supplied additional authentication data>"
}
```

Cryptography References
-----------------------
This module conforms to RFC and NIST recommendations regarding algorithm type,
mode, key size, iv size & implementation, digests, key derivation & management
etc.

References:
*   [RFC 4806](https://tools.ietf.org/html/rfc4086): Randomness Requirements for Security
*   [SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf): Block cipher modes of operation
*   [SP 800-38B](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf): Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
*   [SP 800-57P1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf): Recommendations for key management
*   [SP 800-107](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf): Recommendation for Applications Using Approved Hash Algorithms
*   [SP 800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf): Recommendation for Key Derivation Using Pseudorandom Functions
*   [SP 800-131A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf): Transitioning the Use of Cryptographic Algorithms and Key Lengths
*   [SP 800-132](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf): Recommendation for Password-Based Key Derivation
*   [SP 800-175B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf): Guideline for Using Cryptographic Standards in the Federal Government

Contributing
------------
Contributions are welcome & appreciated!

Refer to the [contributing document](https://github.com/jas-/kruptein/blob/master/CONTRIBUTING.md)
to help facilitate pull requests.

License
-------
This software is licensed under the [MIT License](https://github.com/jas-/kruptein/blob/master/LICENSE).

Copyright Jason Gerfen, 2019.

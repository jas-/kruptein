# kruptein

crypto; from `kruptein` to hide or conceal

[![npm](https://img.shields.io/npm/v/kruptein.svg)](https://npmjs.com/package/kruptein)
![Downloads](https://img.shields.io/npm/dm/kruptein.svg)
[![Dependencies](https://img.shields.io/david/jas-/kruptein.svg)](https://david-dm.org/jas-/kruptein)
[![Known Vulnerabilities](https://snyk.io/test/github/jas-/kruptein/badge.svg)](https://snyk.io/test/github/jas-/kruptein)
[![Build Status](https://travis-ci.org/jas-/kruptein.png?branch=master)](https://travis-ci.org/jas-/kruptein)
[![Coverage Status](https://coveralls.io/repos/jas-/kruptein/badge.svg?branch=master&service=github)](https://coveralls.io/github/jas-/kruptein?branch=master)


## install ##
To install `npm install kruptein`


## methods ##
* `get`    Create ciphertext from plaintext
* `set`    Create plaintext from ciphertext


## options ##
* `secret` (Required) Ciphertext passphrase
* `algorithm` (Optional) Cipher algorithm from `crypto.getCiphers()`. Default: `aes-256-gcm`.
* `hashing` (Optional) Hash algorithm from `crypto.getHashes()`. Default: `sha512`.
* `encodeas` (Optional) Output encoding. Currently only supports `binary`.
* `key_size` (Optional) Key size bytes (should match block size of algorithm). Default: `32`
* `iv_size` (Optional) IV size bytes. Default: `16`.
* `at_size` (Optional) Authentication tag size. Applicable to `ccm`, `gcm` & `ocb` cipher modes. Default: `128`.


## tests ##
To test `npm test`


## usage ##
See below for usage.


### get ###
```javascript
const kruptein = require('kruptein');

const options = {
  secret: 'squirrel'
}

let ciphertext = kruptein.set('Operation mincemeat is an example of how deception works');
```

### set ###
```javascript
const kruptein = require('kruptein');

const options = {
  secret: 'squirrel'
}

let plaintext = kruptein.get(plaintext);
```


## contributing ##
Contributions are welcome & appreciated!

Refer to the [contributing document](https://github.com/jas-/kruptein/blob/master/CONTRIBUTING.md)
to help facilitate pull requests.

## license ##
This software is licensed under the [MIT License](https://github.com/jas-/kruptein/blob/master/LICENSE).

Copyright Jason Gerfen, 2019.
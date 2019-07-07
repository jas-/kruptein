# kruptein

crypto; from `kruptein` to hide or conceal

[![npm](https://img.shields.io/npm/v/kruptein.svg)](https://npmjs.com/package/kruptein)
![Downloads](https://img.shields.io/npm/dm/kruptein.svg)
[![Dependencies](https://img.shields.io/david/jas-/kruptein.svg)](https://david-dm.org/jas-/kruptein)
[![Known Vulnerabilities](https://snyk.io/test/github/jas-/kruptein/badge.svg)](https://snyk.io/test/github/jas-/kruptein)
[![Build Status](https://travis-ci.org/jas-/kruptein.png?branch=master)](https://travis-ci.org/jas-/kruptein)
[![codecov](https://codecov.io/gh/jas-/kruptein/branch/master/graph/badge.svg)](https://codecov.io/gh/jas-/kruptein)


## install ##
To install `npm install kruptein`


## methods ##
* `.set(plaintext, [aad])` - Create plaintext from ciphertext
* `.get(ciphertext, [{at: auth_tag, aad: aad}])` - Create ciphertext from plaintext


## options ##
* `secret` (Required) Ciphertext passphrase
* `algorithm` (Optional) Cipher algorithm from `crypto.getCiphers()`. Default: `aes-256-gcm`.
* `hashing` (Optional) Hash algorithm from `crypto.getHashes()`. Default: `sha512`.
* `encodeas` (Optional) Output encoding. Currently only supports `binary`.
* `key_size` (Optional) Key size bytes (should match block size of algorithm). Default: `32`
* `iv_size` (Optional) IV size bytes. Default: `16`.
* `at_size` (Optional) Authentication tag size. Applicable to `gcm` & `ocb` cipher modes. Default: `128`.


## tests ##
To test `npm test`


## usage ##
When selecting an algorithm from `crypto.getCiphers()` the
`iv` and `key_size` values are calculated auto-magically to make implementation 
easy. You can always define your own if the defaults per algorithm and mode
isn't what you would like; see the `options` section above.

### set ###
To create new ciphertext.

```javascript
const kruptein = require('kruptein');

kruptein.init({secret: 'squirrel'});

let ciphertext = kruptein.set('Operation mincemeat was an example of deception');
```

### set using authentication data ###
To create new ciphertext providing custom 'additional authentication data'.

```javascript
const kruptein = require('kruptein');

kruptein.init({secret: 'squirrel'});

let aad = func_to_generate_aad();

let ciphertext = kruptein.set('Operation mincemeat was an example of deception', aad);
```


### get ###
To retrieve plaintext; 

```javascript
const kruptein = require('kruptein');

kruptein.init({secret: 'squirrel'});

let plaintext = kruptein.get(ciphertext);
```

### get using authentication tag ###
To retrieve plaintext using an external authentication tag

```javascript
const kruptein = require('kruptein');

kruptein.init({secret: 'squirrel'});

let at = func_to_provide_authentication_tag(ciphertext);

let plaintext = kruptein.get(ciphertext, at);
```

### get using authentication data ###
To retrieve plaintext using an external authentication tag

```javascript
const kruptein = require('kruptein');

kruptein.init({secret: 'squirrel'});

let aad = func_to_provide_authentication_data();

let plaintext = kruptein.get(ciphertext, aad);
```


## output ##
The object `.set()` creates takes the following format;

### non authenticated ciphers ###
For those ciphers that DO NOT support [authentication modes](https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-develoment) the following structure is returned.

```json
{
    'hmac': "<calculated hmac>",
    'ct': "<binary format of resulting ciphertext>",
    'iv': "<buffer format of generated/supplied iv>"
}
```

### authenticated ciphers ###
For those ciphers that DO support [authentication modes](https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-develoment) the following structure is returned.
Important: Note that in the event additional authentication data (aad) is not provided a digest of the derived key & iv is used.
```json
{
    'hmac': "<calculated hmac>",
    'ct': "<binary format of resulting ciphertext>",
    'iv': "<buffer format of generated/supplied iv>",
    'at': "<buffer format of generated authentication tag>",
    'aad': "<buffer format of generated/supplied additional authentication data>"
}
```

## contributing ##
Contributions are welcome & appreciated!

Refer to the [contributing document](https://github.com/jas-/kruptein/blob/master/CONTRIBUTING.md)
to help facilitate pull requests.

## license ##
This software is licensed under the [MIT License](https://github.com/jas-/kruptein/blob/master/LICENSE).

Copyright Jason Gerfen, 2019.
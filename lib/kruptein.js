/*!
 * kruptein
 * Copyright(c) 2019 Jason Gerfen <jason.gerfen@gmail.com>
 * License: MIT
 */

"use strict";

class Kruptein {

  /**
   * Kruptein class constructor; sets private / public defaults
   * @param {object} options User supplied key / value object
   */
  constructor(options) {
    this.crypto = require("crypto");

    // Ensure we at least have an object
    options = options || {};


    // Set defaults if the user didn't supply any
    //   References: SP 800-38A, 800-38B
    this.algorithm = options.algorithm || "aes-256-gcm";
    this.hashing = options.hashing || "sha512";
    this.encodeas = options.encodeas || "binary";
    this.debug = options.debug || false;


    // Are we using AEAD mode (authenticated ciphers)?
    //   References: SP 800-38A, 800-38B
    this._aead_mode = this.algorithm.match(/ccm|gcm|ocb/) ? true : false;


    // Set some defaults based on the algorithm used
    //   References: SP 800-38A, 800-38B, 800-107, 800-131A
    this._at_size = options._at_size || this._matrix(this.algorithm)._at_size;
    this._iv_size = options._iv_size || this._matrix(this.algorithm)._iv_size;
    this._key_size = options._key_size || this._matrix(this.algorithm)._key_size;


    // Replace pbkdf2 with scrypt for key derivation?
    //   References: SP 800-108 & 800-132
    this._use_scrypt = options.use_scrypt || false;


    // Be loud if asked
    if (this.debug) {
      console.log({
        algorithm: this.algorithm,
        hash: this.hashing,
        encoding: this.encodeas,
        aead_mode: this._aead_mode,
        iv_size: this._iv_size,
        key_size: this._key_size,
        at_size: this._at_size,
        use_scrypt: this._use_scrypt
      });
    }
  }


  /**
   * Public interface for creating ciphertext from plaintext
   * @param {string} secret User supplied key material
   * @param {string} plaintext User supplied plaintext
   * @param {string} aad (optional) User supplied additional authentication data
   * @param {function} cb User supplied callback function
   */
  set(secret, plaintext, aad, cb) {
    // If non-aead cipher then expect 3 vs. 4 args
    cb = cb || aad;

    // Initialize some defaults
    let iv, ct, hmac, obj, key;


    // Bail if using weak cipher algorithm modes
    //   References: SP 800-38A, 800-38B, 800-131A & 800-175B
    if (this._validator())
      return cb("Insecure cipher mode not supported!");


    // Bail if secret is not provided
    if (!secret)
      return cb("Must supply a secret!");


    // Derive a stronger key from secret;
    //   References: SP 800-57P1, 800-108, 800-132 & 800-175B
    this._derive_key(secret, (err, secret) => {
      if (err) {
        (this.debug)
          console.log(err);

        return cb("Unable to derive key!");
      }

      key = secret;
    });


    // Generate a random IV based on the algorithms IV size
    //   References: RFC 4806, SP 800-57P1, 800-132 & 800-175B
    iv = this._iv(this._iv_size);
    

    // If AEAD mode cipher used and an AAD not provided, create one
    //   References: SP 800-38A, 800-38B, 800-131A & 800-175B
    if (this._aead_mode && typeof aad === "function")
      this._digest(iv+key.key, JSON.stringify(plaintext),
                   this.hashing, this.encodeas, (err, res) => {
                     if (err) {
                       if (this.debug)
                         console.log(err);

                      return cb("Unable to generate AAD!");
                     }
 
                     aad = res;
                   });


    // Create ciphertext from plaintext with derived key
    //   References: SP 800-38A, 800-38B, 800-131A, 800-175B, FIPS 197 & 198-1
    this._encrypt(key.key, JSON.stringify(plaintext), this.algorithm,
                  this.encodeas, iv, aad, (err, ciphertext) => {
                    if (err) {
                      if (this.debug)
                        console.log(err);

                      return cb("Unable to create ciphertext!");
                    }

                      ct = ciphertext;
                  });


    // Create an HMAC from the resulting ciphertext
    //   References: FIPS 180-4, FIPS 198-1
    this._digest(key.key, ct.ct, this.hashing,
                 this.encodeas, (err, digest) => {
                    if (err) {
                      if (this.debug)
                        console.log(err);

                      return cb("Unable to create digest!");
                    }
                    
                    hmac = digest;
                 });


    // Create a nice object to pass back
    obj = JSON.parse({
      hmac: hmac,
      ct: ct.ct,
      iv: iv,
      salt: key.salt
    });


    // If AEAD mode include the AAD
    if (aad)
      obj.aad = aad;


    // If AEAD mode include the AT
    if (ct.at)
      obj.at = ct.at;


    return cb(null, JSON.stringify(obj));
  }


  /**
   * Public interface for decrypting plaintext
   * @param {string} secret User supplied key material
   * @param {string} ciphertext User supplied ciphertext
   * @param {object} opts (optional) User supplied AEAD mode data
   * @param {function} cb User supplied callback function
   */
  get(secret, ciphertext, opts, cb) {
    // If non-aead cipher then expect 3 vs. 4 args
    cb = cb || opts;

    // Initialize some defaults
    let ct, hmac, pt, key;


    // Bail if using weak cipher algorithm modes
    //   References: SP 800-38A, 800-38B, 800-131A & 800-175B
    if (this._validator())
      return cb("Insecure cipher mode not supported!");


    // Bail if secret is not provided
    if (!secret)
      return cb("Must supply a secret!");


    // Parse the provided ciphertext object or bail
    try {
      ct = JSON.parse(ciphertext);
    } catch(err) {
      if (this.debug)
        console.log(err);

       return cb("Unable to parse ciphertext object!");
    }


    // Derive a stronger key from secret;
    //   References: SP 800-57P1, 800-108, 800-132 & 800-175B
    this._derive_key(secret, ct.salt, (err, secret) => {
      if (err) {
        if (this.debug)
          console.log(err);

        return cb("Unable to derive key!");
      }

      key = secret;
    });


    // Create an HMAC from the ciphertext HMAC value
    //   References: FIPS 180-4, FIPS 198-1
    this._digest(key.key, ct.ct, this.hashing,
                 this.encodeas, (err, res) => {
                    if (err) {
                      if (this.debug)
                        console.log(err);

                      cb("Unable to generate HMAC!");
                    }

                    hmac = res;
                 });


    // Compare computed from included & bail if not identical
    //   References: Oracle padding attack, side channel attacks & malleable
    if (hmac !== ct.hmac)
      return cb("Encrypted session was tampered with!");


    // If provided get the AAD &/or AT values
    if (opts) {
      ct.aad = (opts.aad) ? opts.aad :
        (ct.aad) ? ct.aad : false;

      ct.at = (opts.at && !ct.at) ?
        opts.at : (ct.at) ?
          ct.at : false;
    }


    // Convert the AT to a buffers
    if (ct.at)
      ct.at = Buffer.from(ct.at, this.encodeas);


    // Create plaintext from ciphertext with derived key
    //   References: SP 800-38A, 800-38B, 800-131A, 800-175B, FIPS 197 & 198-1
    this._decrypt(key.key, ct.ct, this.algorithm, this.encodeas,
                  Buffer.from(ct.iv, this.encodeas),
                  ct.at, ct.aad, (err, res) => {
                    if (err) {
                      if (this.debug)
                        console.log(err);
 
                       return cb("Unable to decrypt ciphertext!");
                    }

                    pt = res;
                  });


    return cb(null, pt);
  }


  /**
   * Private function to encrypt plaintext
   * @param {buffer} key Derived key material
   * @param {string} pt User supplied plaintext
   * @param {string} algo Cipher to encrypt with
   * @param {string} encodeas Encoding output format
   * @param {buffer} iv Unique IV
   * @param {string} aad (optional) AAD for AEAD mode ciphers
   * @param {function} cb User supplied callback function
   */
  _encrypt(key, pt, algo, encodeas, iv, aad, cb) {
    cb = cb || aad;

    let cipher, ct, at;

    cipher = this.crypto.createCipheriv(algo, key, iv, {
      authTagLength: this._at_size
    });

    if (this._aead_mode && typeof aad !== "function") {
      try {
        cipher.setAAD(Buffer.from(aad, encodeas), {
          plaintextLength: Buffer.byteLength(pt)
        });
      } catch(err) {
        if (this.debug)
          console.log(err);

         return cb("Unable to set AAD!");
      }
    }

    ct = cipher.update(Buffer.from(pt, this.encodeas), "utf8", encodeas);
    cipher.setAutoPadding(true);
    ct += cipher.final(encodeas);

    if (this._aead_mode) {
      try {
        at = cipher.getAuthTag();
      } catch(err) {
        if (this.debug)
          console.log(err);

        return cb("Unable to obtain authentication tag");
      }
    }

    return cb(null, (at) ? {"ct": ct, "at": at} : {"ct": ct});
  }


  _decrypt(key, ct, algo, encodeas, iv, at, aad, cb) {
    cb = cb || aad;

    let cipher, pt;


    cipher = this.crypto.createDecipheriv(algo, key, iv, {
      authTagLength: this._at_size
    });

    if (this._aead_mode && at) {
      try {
        cipher.setAuthTag(Buffer.from(at, encodeas));
      } catch(err) {
        if (this.debug)
          console.log(err);

        return cb("Unable to set authentication tag");
      }
    }

    if (this._aead_mode && typeof aad !== "function") {
      try {
        cipher.setAAD(Buffer.from(aad, encodeas), {
          plaintextLength: ct.length
        });
      } catch(err) {
        if (this.debug)
          console.log(err);

        return cb("Unable to set additional authentication data");
      }
    }

    pt = cipher.update(ct, encodeas, "utf8");
    pt += cipher.final("utf8");

    return cb(null, pt);
  }


  _derive_key(secret, salt, cb) {
    cb = cb || salt;
    
    let key, opts = {};

    if (typeof secret === "object") {
      opts = secret.opts;
      secret = secret.secret;
    }

    salt = (typeof salt !== "function") ?
      Buffer.from(salt) : this.crypto.randomBytes(128);

    try {
      if (!this._use_scrypt || typeof this.crypto.scryptSync !== "function") {
        key = this.crypto.pbkdf2Sync(secret, salt, 15000,
                                     this._key_size, this.hashing);
      } else {
        key = this.crypto.scryptSync(secret, salt, this._key_size, opts);
      }
    } catch(err) {
      if (this.debug)
        console.log(err);

      return cb("Unable to derive key!");
    }

    return cb(null, {
      key: key,
      salt: salt
    });
  }
  

  _digest(key, obj, hashing, encodeas, cb) {
    let hmac;
    
    try {
      hmac = this.crypto.createHmac(hashing, key);
      hmac.setEncoding(encodeas);
      hmac.write(obj);
      hmac.end();
    } catch(err) {
      if (this.debug)
        console.log(err);

      return cb("Unable to generate digest!");
    }

    return cb(null, hmac.read().toString(encodeas));
  }


  _iv(_iv_size) {
    return this.crypto.randomBytes(_iv_size);
  }
  

  _matrix(algo) {
    let obj = {
      _at_size: 16,
      _iv_size: 16,
      _key_size: 32
    };

    if (algo.match(/ccm|ocb|gcm/i))
      obj._iv_size = 12;

    if (algo.match(/aes/) && algo.match(/128/))
      obj._key_size = 16;

    if (algo.match(/aes/) && algo.match(/192/))
      obj._key_size = 24;

    if (algo.match(/aes/) && algo.match(/xts/))
      obj._key_size = 32;

    if (algo.match(/aes/) && algo.match(/xts/) && algo.match(/256/))
      obj._key_size = 64;

    return obj;
  }

  
  _validator() {
    return (this.algorithm.match(/ccm|ecb/))
  }
}


module.exports = function(options) {
  return new Kruptein(options);
};

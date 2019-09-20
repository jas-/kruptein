/*!
 * kruptein
 * Copyright(c) 2019 Jason Gerfen <jason.gerfen@gmail.com>
 * License: MIT
 */

"use strict";

class Kruptein {

  constructor(options) {
    this.crypto = require("crypto");

    this.algorithm = options.algorithm || "aes-256-gcm";
    this.hashing = options.hashing || "sha512";
    this.encodeas = options.encodeas || "binary";
    this.debug = options.debug || false;

    this._aead_mode = this.algorithm.match(/ccm|gcm|ocb/) ? true : false;

    this._at_size = options._at_size || this._matrix(this.algorithm)._at_size;
    this._iv_size = options._iv_size || this._matrix(this.algorithm)._iv_size;
    this._key_size = options._key_size || this._matrix(this.algorithm)._key_size;

    this._use_scrypt = options.use_scrypt || false;

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

    if (this.algorithm.match(/ccm/)) {
      let ver = process.version.replace(/v/, "").split(".")[0];

      (ver < 10)
        throw Error("CCM mode not supported! Upgrade your node.js to 10 or greater!");
    }
  }


  set(secret, plaintext, aad, cb) {
    cb = cb || aad;

    let iv, ct, hmac, obj, key;


    if (!secret)
      return cb("Must supply a secret!");


    this._derive_key(secret, (err, secret) => {
      if (err) {
        (this.debug)
          console.log(err);

        return cb("Unable to derive key!");
      }

      key = secret;
    });

    this.secret = key;


    iv = this._iv(this._iv_size);
    

    if (this._aead_mode && typeof aad === "function")
      this._digest(iv+this.secret.key, JSON.stringify(plaintext),
                   this.hashing, this.encodeas, (err, res) => {
                     if (err) {
                      (this.debug)
                        console.log(err);

                      return cb("Unable to generate AAD!");
                     }
 
                     aad = res;
                   });


    this._encrypt(this.secret.key, JSON.stringify(plaintext), this.algorithm,
                  this.encodeas, iv, aad, (err, ciphertext) => {
                    if (err) {
                      (this.debug)
                        console.log(err);

                      return cb("Unable to create ciphertext!");
                    }

                      ct = ciphertext;
                  });

    this._digest(this.secret.key, ct.ct, this.hashing,
                 this.encodeas, (err, digest) => {
                    if (err) {
                      (this.debug)
                        console.log(err);

                      return cb("Unable to create digest!");
                    }
                    
                    hmac = digest;
                 });


    obj = { hmac: hmac, ct: ct.ct, iv: iv, salt: this.secret.salt };


    if (aad)
      obj.aad = aad;


    if (ct.at)
      obj.at = ct.at;


    return cb(null, JSON.stringify(obj));
  }


  get(secret, ciphertext, opts, cb) {
    cb = cb || opts;

    let ct, hmac, pt, key, tmp_ct;


    if (!secret)
      return cb("Must supply a secret!");


    try {
      ct = JSON.parse(ciphertext);
    } catch(err) {
      (this.debug)
        console.log(err);

       return cb("Unable to parse ciphertext object!");
    }


    this._derive_key(secret, ct.salt, (err, secret) => {
      if (err) {
        (this.debug)
          console.log(err);

        return cb("Unable to derive key!");
      }

      key = secret;
    });

    this.secret = key;

    this._digest(this.secret.key, ct.ct, this.hashing,
                 this.encodeas, (err, res) => {
                    if (err) {
                      (this.debug)
                        console.log(err);

                      cb("Unable to generate HMAC!");
                    }

                    hmac = res;
                 });


    if (hmac !== ct.hmac)
      return cb("Encrypted session was tampered with!");


    if (opts) {
      ct.aad = (opts.aad) ? opts.aad :
        (ct.aad) ? ct.aad : false;

      ct.at = (opts.at && !ct.at) ?
        opts.at : (ct.at) ?
          ct.at : false;
    }


    if (ct.at)
      ct.at = Buffer.from(ct.at, this.encodeas);

    this._decrypt(this.secret.key, ct.ct, this.algorithm, this.encodeas,
                  Buffer.from(ct.iv, this.encodeas),
                  ct.at, ct.aad, (err, res) => {
                    if (err) {
                      (this.debug)
                        console.log(err);
 
                       return cb("Unable to decrypt ciphertext!");
                    }

                    pt = res;
                  });


    return cb(null, pt);
  }


  _encrypt(key, pt, algo, encodeas, iv, aad, cb) {
    cb = cb || aad;

    let cipher, ct, at, aad_size;

    if (typeof aad === "object") {
      aad_size = aad.size + 1;
      aad = aad.aad;
    } else {
      aad_size = Buffer.byteLength(pt);
    }

    cipher = this.crypto.createCipheriv(algo, key, iv, {
      authTagLength: this._at_size
    });

    if (this._aead_mode && aad) {
      try {
        cipher.setAAD(Buffer.from(aad, encodeas), {
          plaintextLength: aad_size
        });
      } catch(err) {
        (this.debug)
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
        (this.debug)
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
        (this.debug)
          console.log(err);

        return cb("Unable to set authentication tag");
      }
    }

    if (this._aead_mode && aad) {
      try {
        cipher.setAAD(Buffer.from(aad, encodeas), {
          plaintextLength: ct.length
        });
      } catch(err) {
        (this.debug)
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
      (this.debug)
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
      (this.debug)
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

    if (algo.match(/aes/) && algo.match(/ecb/))
      obj._iv_size = 0;

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
}


module.exports = function(options) {
  return new Kruptein(options);
};
